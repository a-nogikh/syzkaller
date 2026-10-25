// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKernelRepoCheckout(t *testing.T) {
	workdir := t.TempDir()
	repo, err := newKernelRepo(workdir)
	require.NoError(t, err)
	// Reopening must not fail.
	_, err = newKernelRepo(workdir)
	require.NoError(t, err)

	writeFile(t, filepath.Join(repo.repo.Dir, ".gitignore"), "*.o\n")
	writeFile(t, filepath.Join(repo.repo.Dir, "main.c"), "a\n")
	gitCommit(t, repo, "first")
	first, err := repo.revParse("HEAD")
	require.NoError(t, err)
	writeFile(t, filepath.Join(repo.repo.Dir, "main.c"), "b\n")
	gitCommit(t, repo, "second")
	second, err := repo.revParse("HEAD")
	require.NoError(t, err)

	// Local commits are resolved without fetching.
	resolved, err := repo.resolve("/non-existing-remote", "master", first[:12])
	require.NoError(t, err)
	assert.Equal(t, first, resolved)

	patch := `diff --git a/new.c b/new.c
new file mode 100644
index 0000000..b1e6722
--- /dev/null
+++ b/new.c
@@ -0,0 +1 @@
+new
`
	require.NoError(t, repo.checkout(first, []byte(patch)))
	assert.Equal(t, "a\n", readFile(t, filepath.Join(repo.buildDir, "main.c")))
	assert.Equal(t, "new\n", readFile(t, filepath.Join(repo.buildDir, "new.c")))
	// Imitate a build artifact.
	writeFile(t, filepath.Join(repo.buildDir, "main.o"), "object")
	writeFile(t, filepath.Join(repo.buildDir, "main.c"), "modified\n")

	require.NoError(t, repo.checkout(second, nil))
	assert.Equal(t, "b\n", readFile(t, filepath.Join(repo.buildDir, "main.c")))
	// The file added by the previous patch must be removed.
	assert.False(t, osutil.IsExist(filepath.Join(repo.buildDir, "new.c")))
	// But the build artifacts must be preserved.
	assert.Equal(t, "object", readFile(t, filepath.Join(repo.buildDir, "main.o")))

	// The worktree is recreated if it was removed.
	require.NoError(t, os.RemoveAll(repo.buildDir))
	require.NoError(t, repo.checkout(first, nil))
	assert.Equal(t, "a\n", readFile(t, filepath.Join(repo.buildDir, "main.c")))
}

func TestKernelRepoResolve(t *testing.T) {
	remote := vcs.Git{Dir: t.TempDir()}
	runGit(t, remote, "init", "--initial-branch=master")
	commitFile := func(data string) string {
		writeFile(t, filepath.Join(remote.Dir, "file"), data)
		runGit(t, remote, "add", "-A")
		runGit(t, remote, "-c", "user.name=test", "-c", "user.email=test@test.com",
			"commit", "--no-gpg-sign", "-m", data)
		return strings.TrimSpace(string(runGit(t, remote, "rev-parse", "HEAD")))
	}
	first := commitFile("first")
	runGit(t, remote, "tag", "v1")
	second := commitFile("second")
	runGit(t, remote, "checkout", "-b", "dev")
	dev := commitFile("dev")
	runGit(t, remote, "checkout", "master")

	tests := []struct {
		name   string
		commit string
		want   string
	}{
		{"full hash", second, second},
		{"upper-case hash", strings.ToUpper(first), first},
		{"abbreviated hash", first[:12], first},
		{"tag", "v1", first},
		{"branch", "master", second},
		{"other branch", "dev", dev},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo, err := newKernelRepo(t.TempDir())
			require.NoError(t, err)
			hash, err := repo.resolve(remote.Dir, "master", test.commit)
			require.NoError(t, err)
			assert.Equal(t, test.want, hash)
		})
	}

	repo, err := newKernelRepo(t.TempDir())
	require.NoError(t, err)
	_, err = repo.resolve(remote.Dir, "master", "unknown")
	assert.ErrorContains(t, err, "not found")

	// Branches are re-fetched to get the latest commit.
	hash, err := repo.resolve(remote.Dir, "master", "master")
	require.NoError(t, err)
	assert.Equal(t, second, hash)
	third := commitFile("third")
	hash, err = repo.resolve(remote.Dir, "master", "master")
	require.NoError(t, err)
	assert.Equal(t, third, hash)
}

func runGit(t *testing.T, git vcs.Git, args ...string) []byte {
	out, err := git.Run(args...)
	require.NoError(t, err)
	return out
}

func gitCommit(t *testing.T, repo *kernelRepo, msg string) {
	runGit(t, repo.repo, "add", "-A")
	runGit(t, repo.repo, "-c", "user.name=test", "-c", "user.email=test@test.com",
		"commit", "--no-gpg-sign", "-m", msg)
}

func writeFile(t *testing.T, file, data string) {
	require.NoError(t, osutil.WriteFile(file, []byte(data)))
}

func readFile(t *testing.T, file string) string {
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	return string(data)
}
