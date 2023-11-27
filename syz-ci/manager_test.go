// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestManagerPollCommits(t *testing.T) {
	// Mock a repository.
	baseDir := t.TempDir()
	repo := vcs.CreateTestRepo(t, baseDir, "")
	var lastCommit *vcs.Commit
	for _, title := range []string{
		"unrelated commit one",
		"commit1 title",
		"unrelated commit two",
		"commit3 title",
		`title with fix

Reported-by: foo+abcd000@bar.com`,
		"unrelated commit three",
	} {
		lastCommit = repo.CommitChange(title)
	}

	vcsRepo, err := vcs.NewRepo(targets.TestOS, targets.TestArch64, baseDir, vcs.OptPrecious)
	if err != nil {
		t.Fatal(err)
	}

	mock := dashapi.NewMock()
	mgr := Manager{
		name:   "test-manager",
		dash:   mock.Dashboard(),
		repo:   vcsRepo,
		mgrcfg: &ManagerConfig{},
	}
	// Mock dashapi calls.
	dashapi.SetHandler(mock, "builder_poll",
		func(req *dashapi.BuilderPollReq) (*dashapi.BuilderPollResp, error) {
			assert.Equal(t, req, &dashapi.BuilderPollReq{
				Manager: "test-manager",
			})
			commits := []string{
				"commit1 title",
				"commit2 title",
				"commit3 title",
				"commit4 title",
			}
			// Let's trigger sampling as well.
			for i := 0; i < 100; i++ {
				commits = append(commits, fmt.Sprintf("test%d", i))
			}
			return &dashapi.BuilderPollResp{
				PendingCommits: commits,
				ReportEmail:    "foo@bar.com",
			}, nil
		},
	)

	matches, fixCommits, err := mgr.pollCommits(lastCommit.Hash)
	if err != nil {
		t.Fatal(err)
	}

	foundCommits := map[string]bool{}
	// Call it several more times to catch all commits.
	for i := 0; i < 50; i++ {
		for _, name := range matches {
			foundCommits[name] = true
		}
		matches, _, err = mgr.pollCommits(lastCommit.Hash)
		if err != nil {
			t.Fatal(err)
		}
	}

	var foundCommitsSlice []string
	for title := range foundCommits {
		foundCommitsSlice = append(foundCommitsSlice, title)
	}
	assert.ElementsMatch(t, foundCommitsSlice, []string{
		"commit1 title", "commit3 title",
	})
	assert.Len(t, fixCommits, 1)
	commit := fixCommits[0]
	assert.Equal(t, commit.Title, "title with fix")
	assert.ElementsMatch(t, commit.BugIDs, []string{"abcd000"})
}
