// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// publicApiBugDescription is used to serve the /bug HTTP requests
// and provide JSON description of the BUG. Backward compatible.
type publicAPIBugDescription struct {
	Version      int         `json:"version"`
	Title        string      `json:"title,omitempty"`
	DisplayTitle string      `json:"display-title"`
	ID           string      `json:"id"`
	Status       string      `json:"status"`
	FixCommits   []vcsCommit `json:"fix-commits,omitempty"`
	CauseCommit  *vcsCommit  `json:"cause-commit,omitempty"`
	DupOfID      string      `json:"dup-of-id,omitempty"`
	Subsystems   []string    `json:"subsystems"`
	// links to the discussions
	Discussions []string                    `json:"discussions,omitempty"`
	Crashes     []publicAPICrashDescription `json:"crashes,omitempty"`
}

type vcsCommit struct {
	Title  string `json:"title"`
	Link   string `json:"link,omitempty"`
	Hash   string `json:"hash,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Branch string `json:"branch,omitempty"`
}

type publicAPICrashDescription struct {
	Title               string `json:"title"`
	SyzReproducer       string `json:"syz-reproducer,omitempty"`
	SyzReproducerData   string `json:"syz-reproducer-data,omitempty"`
	CReproducer         string `json:"c-reproducer,omitempty"`
	CReproducerData     string `json:"c-reproducer-data,omitempty"`
	KernelConfig        string `json:"kernel-config,omitempty"`
	KernelConfigData    string `json:"kernel-config-data,omitempty"`
	KernelSourceGit     string `json:"kernel-source-git,omitempty"`
	KernelSourceCommit  string `json:"kernel-source-commit,omitempty"`
	SyzkallerGit        string `json:"syzkaller-git,omitempty"`
	SyzkallerCommit     string `json:"syzkaller-commit,omitempty"`
	CompilerDescription string `json:"compiler-description,omitempty"`
	Architecture        string `json:"architecture,omitempty"`
	CrashReport         string `json:"crash-report-link,omitempty"`
}

type publicAPIBugGroup struct {
	Version int `json:"version"`
	Bugs    []publicAPIBug
}

type publicAPIBug struct {
	Title       string `json:"title,omitempty"`
	Link        string `json:"link"`
	LastUpdated string `json:"last-updated,omitempty"`
}

func getExtAPIDescrForBugGroups(bugGroups []*uiBugGroup) *publicAPIBugGroup {
	return &publicAPIBugGroup{
		Version: 1,
		Bugs: func() []publicAPIBug {
			var res []publicAPIBug
			for _, group := range bugGroups {
				for _, bug := range group.Bugs {
					res = append(res, publicAPIBug{
						Title: bug.Title,
						Link:  bug.Link,
					})
				}
			}
			return res
		}(),
	}
}

func GetJSONDescrFor(page interface{}) ([]byte, error) {
	var res interface{}
	switch i := page.(type) {
	case *uiTerminalPage:
		res = getExtAPIDescrForBugGroups([]*uiBugGroup{i.Bugs})
	case *uiMainPage:
		res = getExtAPIDescrForBugGroups(i.Groups)
	default:
		return nil, ErrClientNotFound
	}
	return json.MarshalIndent(res, "", "\t")
}

func publicBugDescriptionJSON(c context.Context, bug *Bug) ([]byte, error) {
	res, err := loadPublicBugDescription(c, bug)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(res, "", "\t")
}

func loadPublicBugDescription(c context.Context, bug *Bug) (*publicAPIBugDescription, error) {
	ret := &publicAPIBugDescription{
		Version:      1,
		Title:        bug.Title,
		DisplayTitle: bug.displayTitle(),
		ID:           bug.keyHash(c),
		Status: func() string {
			switch bug.Status {
			case BugStatusOpen:
				return "open"
			case BugStatusFixed:
				return "fixed"
			case BugStatusDup:
				return "dup"
			case BugStatusInvalid:
				return "invalid"
			}
			return "unknown"
		}(),
		FixCommits: func() []vcsCommit {
			if len(bug.Commits) == 0 {
				return nil
			}
			var res []vcsCommit
			// TODO: unify vcsCommit and uiCommit.
			for _, commit := range getBugUICommits(c, bug) {
				res = append(res, vcsCommit{
					Title:  commit.Title,
					Link:   commit.Link,
					Hash:   commit.Hash,
					Repo:   commit.Repo,
					Branch: commit.Branch,
				})
			}
			return res
		}(),
		DupOfID: bug.DupOf,
	}
	discussions, err := discussionsForBug(c, bug.key(c))
	if err != nil {
		return nil, err
	}
	for _, d := range discussions {
		ret.Discussions = append(ret.Discussions, d.link())
	}
	if bug.BisectCause > BisectPending {
		causeBisections, err := queryBugJobs(c, bug, JobBisectCause)
		if err != nil {
			return nil, err
		}
		bisectCause, err := causeBisections.uiBestBisection(c)
		if err != nil {
			return nil, err
		}
		if bisectCause != nil && bisectCause.Commit != nil {
			ret.CauseCommit = &vcsCommit{
				Title:  bisectCause.Commit.Title,
				Link:   bisectCause.Commit.Link,
				Hash:   bisectCause.Commit.Hash,
				Repo:   bisectCause.KernelRepo,
				Branch: bisectCause.KernelBranch,
			}
		}
	}
	for _, item := range bug.LabelValues(SubsystemLabel) {
		ret.Subsystems = append(ret.Subsystems, item.Value)
	}
	// Now load crashes. For now just the reported one.
	bugReporting := lastReportedReporting(bug)
	var crashes []*Crash
	if bugReporting.CrashID != 0 {
		crashKey := db.NewKey(c, "Crash", "", bugReporting.CrashID, bug.key(c))
		crash := new(Crash)
		err := db.Get(c, crashKey, crash)
		if err != nil {
			return nil, err
		}
		crashes = append(crashes, crash)
	} else {
		crashes, _, err = queryCrashesForBug(c, bug.key(c), 1)
		if err != nil {
			return nil, err
		}
	}
	for _, crash := range crashes {
		build, err := loadBuild(c, bug.Namespace, crash.BuildID)
		if err != nil {
			return nil, err
		}
		ui := makeUICrash(c, crash, build)
		crashInfo := publicAPICrashDescription{
			Title:               ui.Title,
			SyzReproducer:       ui.ReproSyzLink,
			CReproducer:         ui.ReproCLink,
			KernelConfig:        ui.KernelConfigLink,
			KernelSourceGit:     ui.KernelCommitLink,
			KernelSourceCommit:  ui.KernelCommit,
			SyzkallerGit:        ui.SyzkallerCommitLink,
			SyzkallerCommit:     ui.SyzkallerCommit,
			CompilerDescription: build.CompilerID,
			Architecture:        kernelArch(build.Arch),
			CrashReport:         ui.ReportLink,
		}
		// TODO: refactor uiCrash not to duplicate much here.
		// TODO: augment repro.
		byteData, _, err := getText(c, textReproSyz, crash.ReproSyz)
		if err != nil {
			return nil, err
		}
		crashInfo.SyzReproducerData = string(byteData)
		if crashInfo.SyzReproducerData != "" {
			crashInfo.SyzReproducerData = fmt.Sprintf("#%s\n%s", crash.ReproOpts, crashInfo.SyzReproducerData)
		}

		byteData, _, err = getText(c, textReproC, crash.ReproC)
		if err != nil {
			return nil, err
		}
		crashInfo.CReproducerData = string(byteData)
		byteData, _, err = getText(c, textKernelConfig, build.KernelConfig)
		if err != nil {
			return nil, err
		}
		crashInfo.KernelConfigData = string(byteData)
		ret.Crashes = append(ret.Crashes, crashInfo)
	}
	return ret, nil
}

func createPublicBugsTarball(c context.Context, ns string, w io.Writer) error {
	gzWriter := gzip.NewWriter(w)
	defer gzWriter.Close()
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	bugs, _, err := loadNamespaceBugs(c, ns)
	if err != nil {
		return err
	}

	type res struct {
		bug  *Bug
		data []byte
	}

	input := make(chan *Bug, 16)
	output := make(chan res, 16)

	wg := sync.WaitGroup{}
	g, _ := errgroup.WithContext(c)

	for i := 0; i < 48; i++ {
		wg.Add(1)
		g.Go(func() error {
			defer wg.Done()

			for bug := range input {
				data, err := publicBugDescriptionJSON(c, bug)
				if err != nil {
					log.Errorf(c, "did not get json for %v: %v",
						bug.key(c), err)
				} else {
					output <- res{bug, data}
				}
			}
			return nil
		})
	}

	wg.Add(1)
	g.Go(func() error {
		defer wg.Done()
		defer close(input)
		for _, bug := range bugs {
			if bug.sanitizeAccess(c, AccessPublic) != AccessPublic {
				continue
			}
			input <- bug
		}
		return nil
	})

	g.Go(func() error {
		wg.Wait()
		close(output)
		return nil
	})

	for ret := range output {
		bug, data := ret.bug, ret.data
		header := &tar.Header{
			Name: bug.keyHash(c) + ".json",
			Size: int64(len(data)),
			Mode: 0644,
		}
		err = tarWriter.WriteHeader(header)
		if err != nil {
			return fmt.Errorf("tar writer error: %w", err)
		}
		_, err = io.Copy(tarWriter, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("io copy error: %w", err)
		}
	}
	return nil
}
