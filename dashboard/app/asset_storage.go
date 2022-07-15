// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"golang.org/x/net/context"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// TODO: decide if we really want to save job-related assets right now.
//
// The problem is that:
// 1. We cannot first report the job status and then upload the assets -- an email will already
//    be sent by that time.
// 2. If we first upload assets and then construct a JobDoneReq response already with assets,
//    we need to handle extra corner cases:
//    - If JobDoneReq failed, assets must be deleted.
//    - If we uploaded several files, all must be deleted.
//    - What if syz-ci was killed somewhere in between? How do we get rid of those abadoned files?
//
// With the existing asset types it does not seem to be worth it to solve those problems.
// Probably once we have things like code dumps it will start to make some sense.

func saveBuildAsset(c context.Context, ns string, req *dashapi.AddBuildAssetReq) error {
	asset := Asset{
		Type:        asset.Type(req.AssetType),
		DownloadURL: req.DownloadURL,
		CreateDate:  timeNow(c),
	}
	tx := func(c context.Context) error {
		build, err := loadBuild(c, ns, req.BuildID)
		if err != nil {
			return err
		}
		build.Assets = append(build.Assets, asset)
		if _, err := db.Put(c, buildKey(c, ns, req.BuildID), build); err != nil {
			return fmt.Errorf("failed to put build: %w", err)
		}
		log.Infof(c, "updated build: %#v", build)
		return nil
	}
	if err := db.RunInTransaction(c, tx, &db.TransactionOptions{}); err != nil {
		log.Errorf(c, "failed to update build: %v", err)
		return err
	}
	return nil
}

func parallelize(errorStart string, funcs ...func() error) error {
	errors := make(chan error)
	for _, f := range funcs {
		go func(callFunc func() error) {
			errors <- callFunc()
		}(f)
	}
	defer close(errors)
	errorStr := ""
	for i := 0; i < len(funcs); i++ {
		err := <-errors
		if err == nil {
			continue
		}
		errorStr = fmt.Sprintf("%s%v\n", errorStr, err)
	}
	if errorStr != "" {
		return fmt.Errorf("%s\n%s", errorStart, errorStr)
	}
	return nil
}

func queryNeededAssets(c context.Context) (*dashapi.NeededAssetsResp, error) {
	// So far only build assets.
	// TODO: once crash assets are implemented, parallelize the queries.
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Assets.DownloadURL>", "").
		GetAll(c, &builds)
	if err != nil {
		return nil, fmt.Errorf("failed to query builds: %w", err)
	}
	log.Infof(c, "queried %v builds with assets", len(builds))
	resp := &dashapi.NeededAssetsResp{}
	for _, build := range builds {
		for _, asset := range build.Assets {
			resp.DownloadURLs = append(resp.DownloadURLs, asset.DownloadURL)
		}
	}
	return resp, nil
}

type assetDeprecator struct {
	ns           string
	c            context.Context
	bugsQueried  bool
	relevantBugs map[string]bool
}

const keepAssetsForClosedBugs = time.Hour * 24 * 30

func (ad *assetDeprecator) queryBugs() error {
	if ad.bugsQueried {
		return nil
	}
	var openBugKeys []*db.Key
	var closedBugKeys []*db.Key
	err := parallelize("failed to query bugs",
		func() error {
			// Query open bugs.
			var err error
			openBugKeys, err = db.NewQuery("Bug").
				Filter("Namespace=", ad.ns).
				Filter("Status=", BugStatusOpen).
				KeysOnly().
				GetAll(ad.c, nil)
			if err != nil {
				return fmt.Errorf("failed to fetch open builds: %w", err)
			}
			return nil
		},
		func() error {
			// Query recently closed bugs.
			var err error
			closedBugKeys, err = db.NewQuery("Bug").
				Filter("Namespace=", ad.ns).
				Filter("Closed>", timeNow(ad.c).Add(-keepAssetsForClosedBugs)).
				KeysOnly().
				GetAll(ad.c, nil)
			if err != nil {
				return fmt.Errorf("failed to fetch closed builds: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return err
	}
	ad.relevantBugs = map[string]bool{}
	for _, key := range append(append([]*db.Key{}, openBugKeys...), closedBugKeys...) {
		ad.relevantBugs[key.String()] = true
	}
	return nil
}

func (ad *assetDeprecator) buildArchivePolicy(build *Build, asset *Asset) (bool, error) {
	// If the asset is reasonably new, we always keep it.
	const alwaysKeepPeriod = time.Hour * 24 * 14
	if asset.CreateDate.After(timeNow(ad.c).Add(-alwaysKeepPeriod)) {
		return true, nil
	}
	// Query builds to see whether there's a newer same-type asset on the same week.
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ad.ns).
		Filter("Manager=", build.Manager).
		Filter("Assets.Type=", asset.Type).
		Filter("Assets.CreateDate>", asset.CreateDate).
		Limit(1).
		Order("Assets.CreateDate").
		GetAll(ad.c, &builds)
	if err != nil {
		return false, fmt.Errorf("failed to query newer assets: %w", err)
	}
	log.Infof(ad.c, "running archive policy for %s, date %s; queried %d builds",
		asset.DownloadURL, asset.CreateDate, len(builds))
	sameWeek := false
	if len(builds) > 0 {
		origY, origW := asset.CreateDate.ISOWeek()
		for _, nextAsset := range builds[0].Assets {
			if nextAsset.Type != asset.Type {
				continue
			}
			if nextAsset.CreateDate.Before(asset.CreateDate) ||
				nextAsset.CreateDate.Equal(asset.CreateDate) {
				continue
			}
			nextY, nextW := nextAsset.CreateDate.ISOWeek()
			if origY == nextY && origW == nextW {
				log.Infof(ad.c, "found a newer asset: %s, date %s",
					nextAsset.DownloadURL, nextAsset.CreateDate)
				sameWeek = true
				break
			}
		}
	}
	return !sameWeek, nil
}

func (ad *assetDeprecator) buildBugStatusPolicy(build *Build) (bool, error) {
	if err := ad.queryBugs(); err != nil {
		return false, fmt.Errorf("failed to query bugs: %w", err)
	}
	keys, err := db.NewQuery("Crash").
		Filter("BuildID=", build.ID).
		KeysOnly().
		GetAll(ad.c, nil)
	if err != nil {
		return false, fmt.Errorf("failed to query crashes: %w", err)
	}
	for _, key := range keys {
		bugKey := key.Parent()
		if _, ok := ad.relevantBugs[bugKey.String()]; ok {
			// At least one crash is related to an opened/recently closed bug.
			return true, nil
		}
	}
	return false, nil
}

func (ad *assetDeprecator) needThisBuildAsset(build *Build, buildAsset *Asset) (bool, error) {
	if buildAsset.Type == asset.HTMLCoverageReport {
		// We want to keep coverage reports forever, not just
		// while there are any open bugs. But we don't want to
		// keep all coverage reports, just a share of them.
		return ad.buildArchivePolicy(build, buildAsset)
	}
	if build.Type == BuildNormal {
		// A build-related asset, keep it only while there are open bugs with crashes
		// related to this build.
		return ad.buildBugStatusPolicy(build)
	}
	// TODO: fix this once this is no longer the case.
	return false, fmt.Errorf("job-related assets are not supported yet")
}

func (ad *assetDeprecator) updateBuild(buildID string, urlsToDelete []string) error {
	toDelete := map[string]bool{}
	for _, url := range urlsToDelete {
		toDelete[url] = true
	}
	tx := func(c context.Context) error {
		build, err := loadBuild(ad.c, ad.ns, buildID)
		if build == nil || err != nil {
			// Assume the DB has been updated in the meanwhile.
			return nil
		}
		newAssets := []Asset{}
		for _, asset := range build.Assets {
			if _, ok := toDelete[asset.DownloadURL]; !ok {
				newAssets = append(newAssets, asset)
			}
		}
		build.Assets = newAssets
		build.AssetsLastCheck = timeNow(ad.c)
		if _, err := db.Put(ad.c, buildKey(ad.c, ad.ns, buildID), build); err != nil {
			return fmt.Errorf("failed to save build: %w", err)
		}
		return nil
	}
	if err := db.RunInTransaction(ad.c, tx, nil); err != nil {
		return fmt.Errorf("failed to update build: %w", err)
	}
	return nil
}

func (ad *assetDeprecator) batchProcessBuilds(count int) error {
	// We cannot query only the Build with non-empty Assets array and yet sort
	// by AssetsLastCheck. The datastore returns "The first sort property must
	// be the same as the property to which the inequality filter is applied.
	// In your query the first sort property is AssetsLastCheck but the inequality
	// filter is on Assets.DownloadURL.
	// So we have to omit Filter("Assets.DownloadURL>", ""). here.
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ad.ns).
		Order("AssetsLastCheck").
		Limit(count).
		GetAll(ad.c, &builds)
	if err != nil {
		return fmt.Errorf("failed to fetch builds: %w", err)
	}
	for _, build := range builds {
		toDelete := []string{}
		for _, asset := range build.Assets {
			needed, err := ad.needThisBuildAsset(build, &asset)
			if err != nil {
				return fmt.Errorf("failed to test asset: %w", err)
			} else if !needed {
				toDelete = append(toDelete, asset.DownloadURL)
			}
		}
		err := ad.updateBuild(build.ID, toDelete)
		if err != nil {
			return err
		}
	}
	return nil
}

const buildBatchSize = 16

func deprecateNamespaceAssets(c context.Context, ns string) error {
	ad := assetDeprecator{
		ns: ns,
		c:  c,
	}
	err := ad.batchProcessBuilds(buildBatchSize)
	if err != nil {
		return fmt.Errorf("build batch processing failed: %w", err)
	}
	return nil
}

func handleDeprecateAssets(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	for ns := range config.Namespaces {
		err := deprecateNamespaceAssets(c, ns)
		if err != nil {
			log.Errorf(c, "deprecateNamespaceAssets failed for ns=%v: %v", ns, err)
		}
	}
}

func queryLatestManagerAssets(c context.Context, ns string, assetType asset.Type,
	period time.Duration) (map[string]Asset, error) {
	// We don't want to query everything for such a purpose.
	// Assume the assets we're interested in are uploaded often enough.
	const queryLastAssetsFor = time.Hour * 24 * 14
	var builds []*Build
	startTime := timeNow(c).Add(-queryLastAssetsFor)
	_, err := db.NewQuery("Build").
		Filter("Assets.Type=", assetType).
		Filter("Assets.CreateDate>", startTime).
		Order("Assets.CreateDate").
		GetAll(c, &builds)
	if err != nil {
		return nil, err
	}
	ret := map[string]Asset{}
	for _, build := range builds {
		for _, asset := range build.Assets {
			if asset.Type != assetType {
				continue
			}
			ret[build.Manager] = asset
		}
	}
	return ret, nil
}
