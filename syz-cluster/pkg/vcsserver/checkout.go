// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcsserver

import (
	"fmt"

	"github.com/google/syzkaller/pkg/vcs"
)

type Checkout struct {
	repo *vcs.Git
}

func newCheckout(path string) (*Checkout, error) {
	return &Checkout{
		repo: &vcs.Git{
			Bare:    true,
			Dir:     path,
			Sandbox: true,
		},
	}
}

func (c *Checkout) poll(name, url, branch string) error {
	commands := [][]string{
		{"remote", "remove", name},
		{"remote", "add", name, url},
		{"fetch", name, branch},
		// TODO: unlike the cron version, let's try w/o tag -f.
	}
	for _, command := range commands {
		err := c.repo.Run(command...)
		if err != nil {
			return fmt.Errorf("running %q failed: %w", command, err)
		}
	}
	return nil
}

func (c *Checkout) spawnWorkdir(path string) (*Workdir, error) {
	// TODO: if it already exists, it must not be re-created.
}

type Workdir struct {
	repo *vcs.Git
}

func (w *Workdir) commitInfo(commit string) (*vcs.Commit, error) {
	if vcs.CheckCommitHash(commitOrBranch) {
		return w.repo.Commit(commitOrBranch)
	}
	return w.repo.Commit(treeName + "/" + commitOrBranch)
}

func (w *Workdir) headCommitInfo(name string) (*vcs.Commit, error) {
	if vcs.CheckCommitHash(commitOrBranch) {
		return w.repo.Commit(commitOrBranch)
	}
	return w.repo.Commit(treeName + "/" + commitOrBranch)
}
