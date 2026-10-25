// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

const (
	torvaldsURL    = "https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux"
	torvaldsBranch = "master"
	// Fetched branches are stored as refs/remotes/<remoteName>/<branch>.
	remoteName = "upstream"
)

// kernelRepo manages two directories:
//   - linux: the git repository that keeps all fetched commits.
//   - build-repo: a worktree of linux, in which all kernels are built.
//
// Kernels are built in-tree and build-repo is never cleaned of the build artifacts,
// so switching between the base and the patched kernel only recompiles the modified files.
// Any manual changes in build-repo are discarded.
type kernelRepo struct {
	repo     vcs.Git
	buildDir string
	// The state build-repo was brought to by the last checkout call.
	current string
}

func newKernelRepo(workdir string) (*kernelRepo, error) {
	r := &kernelRepo{
		repo:     vcs.Git{Dir: filepath.Join(workdir, "linux")},
		buildDir: filepath.Join(workdir, "build-repo"),
	}
	if !osutil.IsExist(filepath.Join(r.repo.Dir, ".git")) {
		if err := osutil.MkdirAll(r.repo.Dir); err != nil {
			return nil, err
		}
		if _, err := r.repo.Run("init"); err != nil {
			return nil, fmt.Errorf("git init failed: %w", err)
		}
	}
	return r, nil
}

// resolve returns the full hash of the commit (or tag, or branch), fetching it from the remote
// if it's not present locally. Branches are always re-fetched to get their latest state.
func (r *kernelRepo) resolve(remote, branch, commit string) (string, error) {
	if hash, err := r.revParse(commit); err == nil {
		return hash, nil
	}
	log.Logf(0, "fetching %v from %v (it may take a while)", commit, remote)
	if fullHashRe.MatchString(commit) {
		commit = strings.ToLower(commit)
		// Keep a ref to the commit, otherwise it may be garbage collected.
		ref := fmt.Sprintf("%v:refs/%v/commits/%v", commit, remoteName, commit)
		if _, err := r.repo.Run("fetch", remote, ref); err != nil {
			return "", fmt.Errorf("failed to fetch %v: %w", commit, err)
		}
		return r.revParse(commit)
	}
	// The commit may be an abbreviated hash, a tag or a branch name.
	// Abbreviated hashes and tags are expected to be reachable from the branch.
	if _, err := r.repo.Run("fetch", "--tags", remote, r.refspec(branch)); err != nil {
		return "", fmt.Errorf("failed to fetch %v: %w", branch, err)
	}
	if hash, err := r.lookup(commit); err == nil {
		return hash, nil
	}
	if _, err := r.repo.Run("fetch", remote, r.refspec(commit)); err == nil {
		if hash, err := r.lookup(commit); err == nil {
			return hash, nil
		}
	}
	return "", fmt.Errorf("commit %v not found in %v", commit, remote)
}

// refspec stores the fetched branch as refs/remotes/<remoteName>/<branch>,
// otherwise the fetched commits would not be referenced by anything and could be garbage collected.
func (r *kernelRepo) refspec(branch string) string {
	return fmt.Sprintf("+refs/heads/%v:refs/remotes/%v/%v", branch, remoteName, branch)
}

func (r *kernelRepo) lookup(commit string) (string, error) {
	if hash, err := r.revParse(commit); err == nil {
		return hash, nil
	}
	return r.revParse(fmt.Sprintf("refs/remotes/%v/%v", remoteName, commit))
}

var fullHashRe = regexp.MustCompile("^(?i)[a-f0-9]{40}$")

func (r *kernelRepo) revParse(commit string) (string, error) {
	out, err := r.repo.Run("rev-parse", "--verify", "--quiet", commit+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// checkout brings build-repo to the commit (which must be a full hash) with the patch applied.
// Unlike vcs.Git.Reset(), it does not remove ignored files, so the previous build artifacts are kept.
func (r *kernelRepo) checkout(commit string, patch []byte) error {
	state := commit + "+" + hash.String(patch)
	if r.current == state {
		return nil
	}
	r.current = ""
	buildRepo := vcs.Git{Dir: r.buildDir}
	if !osutil.IsExist(filepath.Join(r.buildDir, ".git")) {
		// The worktree dir may have been removed manually, forget about it.
		if _, err := r.repo.Run("worktree", "prune"); err != nil {
			return fmt.Errorf("git worktree prune failed: %w", err)
		}
		if _, err := r.repo.Run("worktree", "add", "--detach", r.buildDir, commit); err != nil {
			return fmt.Errorf("git worktree add failed (try removing %v): %w", r.buildDir, err)
		}
	}
	if _, err := buildRepo.Run("reset", "--hard", commit); err != nil {
		return fmt.Errorf("git reset failed: %w", err)
	}
	// Remove the untracked files (e.g. the ones added by the previous patch), but keep the ignored ones.
	if _, err := buildRepo.Run("clean", "-fd"); err != nil {
		return fmt.Errorf("git clean failed: %w", err)
	}
	if len(patch) != 0 {
		if err := buildRepo.Apply(patch); err != nil {
			return fmt.Errorf("failed to apply the patch: %w", err)
		}
	}
	r.current = state
	return nil
}
