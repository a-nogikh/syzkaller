// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/assets"
	"golang.org/x/net/context"
	"google.golang.org/appengine/v2/datastore"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

/*
   TODO: decide if we really want to save job-related assets right now.

   The problem is that:
   1) We cannot first report the job status and then upload the assets -- an email will already
      be sent by that time.
   2) If we first upload assets and then construct a JobDoneReq response already with assets,
      we need to handle extra corner cases:
        - If JobDoneReq failed, assets must be deleted.
        - If we uploaded several files, all must be deleted.
        - What if syz-ci was killed somewhere in between? How do we get rid of those abadoned files?

   With the existing asset types it does not seem to be worth it to solve those problems.
   Probably once we have things like code dumps it will start to make some sense.
*/

/*
TODO:
   - Each asset storage should only receive its own assets to forget.
   - Integrate with the web dashboard
*/

/*
   Currently the code below only supports build-specific assets.
   At some point we'll also implement crash-specific assets. What needs to be done then:

   1) Implement saveCrashAsset method. forgetAssets already works for crash-specific stuff.
   2) Add support to the policies, currently only BugStatusDeprecationPolicy takes care of
      crash-specific assets.
   3) Adjust dashapi, tests and bug reporting.

   TODO: how do we handle crash asset deprecation? Crashes are very easily obsoleted, and so
   the contents of the Asset array will just be gone. Looks like we need to duplicate them
   somewhere. Or use the alternative design, as described below.
*/

/*
   Alternative DB design: don't embed assets, but store them as separate entities.

   type AssetAffilation {
       Entity string
       Key    string
   }

   type Asset struct {
       Type string
       DownloadURL string
       // <...>
       RelatedTo []AssetAffilation ----- the list of entities, to which the asset belongs
   }

Pros:
   1. This would let us restructure and simplify the assets-to-forget detection process.
      a) We could remember the last time we checked if the asset is still needed.
      b) Each `depreated_assets` call the dashboard could check e.g. 30-40 the oldest-non-checked
         ones. And mark those to-be-deprecated with a special flag.
      b) The caller gets all such marked assets.
   2. Very easy to add new asset types

Cons:
   Extra DB queries. At least:
   1. In createBugReport().
   2. Asset deprecation requires much more queries, though they'll be all small.
   3. If we decide to show assets on the bug's page, then we'll need N+M queries:
      - one for each crash build
      - one for each crash
      A possible solution is to only show assets for a few most interesting crashes.
*/

func saveBuildAsset(c context.Context, ns string, req *dashapi.AddBuildAssetReq) error {
	asset := AssetInfo{
		Type:        req.AssetType,
		DownloadURL: req.DownoadURL,
		StorageName: req.AssetStorage,
		InStorageID: req.AssetID,
		CreateDate:  timeNow(c),
	}
	tx := func(c context.Context) error {
		build, err := loadBuild(c, ns, req.BuildID)
		if err != nil {
			return err
		}
		asset.DeprecationPolicy = determineBuildAssetPolicy(build, req.AssetType)
		build.Assets = append(build.Assets, asset)
		if _, err := db.Put(c, buildKey(c, ns, req.BuildID), bug); err != nil {
			return fmt.Errorf("failed to put build: %w", err)
		}
		if !policyRequiresPropagation(asset.DeprecationPolicy) {
			// Nothing else to do.
			return nil
		}
		// We assume that assets that need to propagate will be uploaded most of
		// the time shortly after the build is done, so there won't be many crashes,
		// especially reported ones.
		crashes, crashKeys, err := queryReportedCrashesForBuild(c, req.BuildID)
		if err != nil {
			return fmt.Errorf("failed to query crashes: %w", err)
		}
		for i, crash := range crashes {
			crash.PropagateBuildAssets(build)
			if _, err = db.Put(c, crashKeys[i], crash); err != nil {
				return fmt.Errorf("failed to put crash: %w", err)
			}
		}
		return nil
	}
	if err := db.RunInTransaction(c, tx, &db.TransactionOptions{XG: true}); err != nil {
		log.Errorf(c, "failed to update build: %v", err)
		return err
	}
	return nil
}

func queryCrashesForBuild(c context.Context, buildID string) ([]*Crash, []*db.Key, error) {
	var crashes []*Crash
	keys, err := db.NewQuery("Crash").
		Filter("BuildID=", buildID).
		Filter("Reported>", 0).
		GetAll(c, &crashes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch crashes: %v", err)
	}
	return crashes, keys, nil
}

func parallelize(errorStart string, funcs ...func() error) error {
	var wg sync.WaitGroup
	wg.add(len(funcs))
	errors := make(chan error, len(funcs))
	for _, f := range funcs {
		go func() {
			errors <- f()
			wg.Done()
		}()
	}
	wg.Wait()
	errorStr := ""
	for err := range errors {
		if err == nil {
			continue
		}
		errorStr = fmt.Sprintf("%s%v\n", errorStr, err)
	}
	if errorStr != "" {
		return errorStart + "\n" + errorStr
	}
	return nil
}

func forgetAssets(c context.Context, ns string, req *dashapi.ForgetAssetsReq) error {
	return parallelize("Failed to forget assets",
		func() { forgetBuildAssets(c, ns, req.DownloadURLs) },
		func() { forgetCrashAssets(c, ns, req.DownloadURLs) },
	)
}

func getAssetCleaner(urls []string) func([]AssetInfo) []AssetInfo {
	toDelete := map[string]bool{}
	for _, url := range urls {
		toDelete[url] = true
	}
	return func(assets []AssetInfo) []AssetInfo {
		newAssets := []AssetInfo{}
		for _, asset := range assets {
			if _, ok := toDelete[asset.DownloadURL]; ok {
				continue
			}
			newAssets = append(newAssets, asset)
		}
	}
}

func forgetCrashAssets(c context.Context, ns string, urls []string) error {
	cleaner := getAssetCleaner(urls)
	updateCrashes := func(crashes []*Crash, crashKeys []*db.Key, c context.Context) error {
		for i, crash := range crashes {
			crash.Assets = cleaner(crash.Assets)
			if _, err := db.Put(c, crashKeys[i], crash); err != nil {
				return fmt.Errorf("failed to put crash: %w", err)
			}
		}
		return nil
	}
	// Datastore unfortunately does not provide a `Crash.Assets.DownloadURLs` IN (...) feature.
	// So we have to query for individual URLs.
	for _, url := range urls {
		tx := func(c context.Context) error {
			var builds []*Crash
			keys, err := db.NewQuery("Crash").
				Filter("Assets.DownloadURL=", url).
				GetAll(c, &builds)
			if err != nil {
				return err
			}
			return updateCrashes(builds, keys, c)
		}
		if err := db.RunInTransaction(c, tx, nil); err != nil {
			return err
		}
	}
	return nil
}

func forgetBuildAssets(c context.Context, ns string, urls []string) error {
	cleaner := getAssetCleaner(urls)
	updateBuilds := func(builds []*Build, c context.Context) error {
		for _, build := range builds {
			build.Assets = cleaner(build.Assets)
			if _, err := db.Put(c, buildKey(c, ns, req.BuildID), bug); err != nil {
				return fmt.Errorf("failed to put build: %v", err)
			}
		}
		return nil
	}
	// Datastore unfortunately does not provide a `Build.Assets.DownloadURLs` IN (...) feature.
	// So we have to query for individual URLs.
	for _, url := range urls {
		tx := func(c context.Context) error {
			var builds []*Build
			_, err := db.NewQuery("Build").
				Filter("Assets.DownloadURL=", url).
				GetAll(c, &builds)
			if err != nil {
				return err
			}
			return updateBuilds(builds, c)
		}
		if err := db.RunInTransaction(c, tx, nil); err != nil {
			return err
		}
	}
	return nil
}

func queryDeprecatedAssets(c context.Context, ns string, req *dashapi.DeprecatedAssetsReq) (
	*dashapi.DeprecatedAssetsResp, error) {
	var mu sync.Mutex
	var assets []AssetInfo
	handlers := []func() error{}
	for _, policyFunc := range deprecationPolicies {
		handlers = append(handlers, func() {
			policyAssets, policyErr := policyFunc(c, ns)
			if policyErr != nil {
				return policyErr
			} else {
				mu.Lock()
				assets = append(assets, policyAssets...)
				defer mu.Unlock()
			}
			return nil
		})
	}
	err := parallelize("Failed to poll some policies:", handlers)
	if err != nil {
		return err
	}
	ret := &dashapi.DeprecatedAssetsResp{}
	for _, asset := range assets {
		ret.DownloadURLs = append(ret.DownloadURLs, asset.DownloadURL)
	}
	return ret, nil
}

func queryLatestManagerAssets(c context.Context, ns string, assetType string,
	period time.Duration) (map[string]AssetInfo, error) {
	var builds []*Build
	startTime := timeNow(c).Add(-deprecateBuildAssetTime)
	_, err := db.NewQuery("Build").
		Filter("Assets.Type=", assetType).
		Filter("Assets.CreateDate>", startTime).
		Order("Assets.CreateDate").
		GetAll(c, &builds)
	if err != nil {
		return nil, err
	}
	ret := map[string]AssetInfo{}
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

func policyRequiresPropagation(policy string) bool {
	return policy == BugStatusDeprecationPolicy
}

func (crash *Crash) PropagateBuildAssets(build *Build) {
	existing := map[string]bool{}
	for _, crashAsset := range crash.Assets {
		existing[crashAsset.DownloadURL] = true
	}
	for _, buildAsset := range build.Assets {
		if _, ok := existing[buildAsset.DownloadURL]; ok {
			continue
		}
		if poliyRequiresPropagation(buildAsset.DeprecationPolicy) {
			// We have to duplicate assets with this policy in order to speed up
			// the deprecated assets detection.
			// For details see the handler of BugStatusDeprecationPolicy.
			crash.Assets = append(crash.Assets, buildAsset)
		}
	}
}

type AssetDeprecationPolicy string

const (
	BuildTimeDeprecationPolicy = "time_deprecation"
	BugStatusDeprecationPolicy = "bug_status_deprecation"
	PeriodicDeprecationPolicy  = "periodic_deprecation"
)

type AssetDeprecationPolicyFunc func(c context.Context, ns string) ([]AssetInfo, error)

var deprecationPolicies = map[AssetDeprecationPolicy]AssetDeprecationPolicyFunc{
	BuildTimeDeprecationPolicy: getBuildTimeDeprecatedAssets,
	BugStatusDeprecationPolicy: getBugStatusDeprecatedAssets,
	PeriodicDeprecationPolicy:  getPeriodicallyDeprecatedAssets,
}

// TODO: make this logic be not hard-coded here?
func determineBuildAssetPolicy(build *Build, assetType string) AssetDeprecationPolicy {
	if assetType == assets.HtmlCoverageReport {
		// We want to keep coverage reports forever, not just
		// while there are any open bugs. But we don't want to
		// keep all coverage reports.
		return PeriodicDeprecationPolicy
	}
	if build.Type == BuildNormal {
		// A build-related asset, keep it only while there are
		// some reported bugs with it.
		return BugStatusDeprecationPolicy
	}
	// For job builds it's just too problematic to quickly match them
	// with open/closed bugs. So let's just keep them for a fixed time.
	return BuildTimeDeprecationPolicy
}

const deprecateBuildAssetTime = 24 * time.Hour * 90

// Delete an asset once its Build is X days old.
func getBuildTimeDeprecatedAssets(c context.Context, ns string) ([]AssetInfo, error) {
	builds := []*Build{}
	startTime := timeNow(c).Add(-deprecateBuildAssetTime)
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ns).
		Filter("Assets.DeprecationPolicy=", BuildTimeDeprecationPolicy).
		Filter("Time<", startTime).
		GetAll(c, &builds)
	if err != nil {
		return nil, err
	}
	ret := []AssetInfo{}
	for _, build := range builds {
		for _, asset := range build.Assets {
			if asset.DeprecationPolicy == BuildTimeDeprecationPolicy {
				ret = append(ret, asset)
			}
		}
	}
	return ret, nil
}

type AssetCollection map[string]AssetInfo

func (ac *AssetCollection) MergeIn(assets []AssetInfo, policy AssetDeprecationPolicy) {
	for _, asset := range assets {
		if policy == "" || asset.DeprecationPolicy == policy {
			ac[asset.DownloadURL] = asset
		}
	}
}

func (ac *AssetCollection) Minus(other *AssetCollection) []AssetInfo {
	ret := []AssetInfo{}
	for url, asset := range ac {
		if _, ok := other[url]; !ok {
			ret = append(ret, asset)
		}
	}
	return ret
}

const keepAssetsForClosedBugs = time.Hour * 24 * 30

func getBugStatusDeprecatedAssets(c context.Context, ns string) ([]AssetInfo, error) {
	// If we wanted to just query the outdated crash artifacts, it would be enough to
	// put duplicate build Assets in the Bug entity.
	// But we also must somehow determine Builds which had no recorded
	// reported crashes.
	// So we have to do {all artifacts} - {artifacts we must keep} anyway.

	// One tricky problem here is to what to do with duplicate bugs -- in the DB we just
	// "close" them and specify the canonical bug key. Ideally we should keep assets of
	// the dupped bug as long as the canonical bug is closed, but it seems to be just too
	// complicated, given the restrictions of Datastore.
	// So let's just treat dupped bugs as closed, and keep their assets for keepAssetsForClosedBugs
	// time. In the end, if the bug is a duplicate, there must be the corresponding notion in the
	// mailing list, so nobody should be surprised.

	var buildsWithAssets []*Build
	var buildKeys []*datastore.Key
	var openBugKeys []*datastore.Key
	var closedBugKeys []*Bug
	var crashes []*Crash
	var crashKeys []*datastore.Key

	err := parallelize("failed to query deprecated assets",
		func() error {
			// Query all builds with at least one asset.
			_, err := db.NewQuery("Build").
				Filter("Namespace=", ns).
				Filter("Assets.DeprecationPolicy", BugStatusDeprecationPolicy).
				Order("Time").
				GetAll(c, &buildsWithAssets)
			if err != nil {
				return fmt.Errorf("failed to fetch all builds: %w", err)
			}
			return nil
		},
		func() error {
			// Query open bugs.
			openBugsKeys, err := db.NewQuery("Bug").
				Filter("Namespace=", ns).
				Filter("Status=", BugStatusOpen).
				KeysOnly().
				GetAll(c, nil)
			if err != nil {
				return fmt.Errorf("failed to fetch open builds: %w", err)
			}
			return nil
		},
		func() error {
			// Query recently closed bugs.
			closedBugKeys, err := db.NewQuery("Bug").
				Filter("Namespace=", ns).
				Filter("Closed>", timeNow(c).Add(-keepAssetsForClosedBugs)).
				KeysOnly().
				GetAll(c, nil)
			if err != nil {
				return fmt.Errorf("failed to fetch closed builds: %w", err)
			}
			return nil
		},
		func() error {
			// Just to query reported crashes here would be a mistake -- if a crash
			// is not reported now, nobody says it might not get reported in the future.
			// At the same time, we just don't need unreported artifacts that much. So,
			// TODO: figure out how to save space by giving priority to reported crashes.
			crashKeys, err := db.NewQuery("Crash").
				Filter("Assets.DeprecationPolicy", BugStatusDeprecationPolicy).
				GetAll(c, &crashes)
			if err != nil {
				return fmt.Errorf("failed to fetch open builds: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	keepAssetsForBug := map[string]bool{}
	for _, key := range append(append([]*datastore.Key, closedBugKeys...), closedBugKeys...) {
		keepAssetsForBug = append(keepAssetsForBug, key.String())
	}
	neededBuild := map[string]bool{}
	neverRemove := AssetCollection{}
	probablyRemove := AssetCollection{}
	for id, crash := range crashes {
		bugKey := repCrashKeys[id].Parent
		if _, ok := keepAssetsForBug[bugKey.String()]; ok {
			neverRemove.MergeIn(crash.Assets, BugStatusDeprecationPolicy)
			// We keep the build as long as there's at least one crash which is
			// related to the build and which is related to an open or recently
			// closed bug.
			neededBuild[buildKey(c, ns, crash.BuildID).String()] = true
		} else {
			probablyRemove.MergeIn(crash.Assets, BugStatusDeprecationPolicy)
		}
	}
	// We also need to take care of builds for which there were no crashes.
	for id, build := range buildsWithAssets {
		_, keepBuildAssets := neededBuild[buildKeys[id].String()]
		if id+1 == len(buildsWithAssets) {
			// We always keep the assets of the last build -- it may have no crashes yet,
			// but they may appear in the future.
			keepBuildAssets = true
		}
		if keepBuildAssets {
			neverRemove.MergeIn(build.Assets, BugStatusDeprecationPolicy)
		} else {
			probablyRemove.MergeIn(build.Assets, BugStatusDeprecationPolicy)
		}
	}
	return probablyRemove.Minus(neverRemove), nil
}

func getPeriodicallyDeprecatedAssets(c context.Context, ns string) ([]AssetInfo, error) {
	// We're bucketing such assets to weeks (the starting point - the beginning of the year, not the
	// "now" moment).
	// - Last 2 weeks every asset is kept.
	// - Then, only one asset per week is allowed (the latest one).

	// A small optimization -- we assume that the method is called reasonably often, so we don't
	// query all Builds each time.
	const takeNoMore = 500
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ns).
		Filter("Assets.DeprecationPolicy", PeriodicDeprecationPolicy).
		Order("-Time").
		Limit(takeNoMore).
		GetAll(c, &builds)
	if err != nil {
		return nil, fmt.Errorf("failed to query builds: %w", err)
	}
	type assetBucket struct {
		year int
		week int
		keep AssetInfo
		skip []AssetInfo
	}
	buckets := []assetBucket{}
	for i := len(builds) - 1; i >= 0; i-- {
		builds := builds[i]
		y, w := build.Time.ISOWeek()
		var bucket *assetBucket
		if len(buckets) == 0 || buckets[len(keep)-1].year != y ||
			buckets[len(buckets)-1].week != w {
			buckets = append(buckets, assetBucket{
				week: w,
				year: y,
			})
		}
		bucket = &bukets[len(buckets)-1]
		for _, asset := range build.Assets {
			if asset.DeprecationPolicy != PeriodicDeprecationPolicy {
				continue
			}
			bucket.skip = append(bucket.skip, bucket.keep)
			bucket.keep = builds[i].Assets
		}
	}
	neverRemove := AssetCollection{}
	probablyRemove := AssetCollection{}
	// Ignore two last buckets - they are too recent.
	for i := 0; i < len(builds)-2; i++ {
		bucket := &buckets[i]
		neverRemove.MergeIn([]AssetInfo{bucket.keep}, "")
		probablyRemove.MergeIn(buket.skip, "")
	}
	return probablyRemove.Minus(neverRemove), nil
}
