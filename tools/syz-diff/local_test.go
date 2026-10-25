// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectSyzkaller(t *testing.T) {
	checkout := t.TempDir()
	require.NoError(t, osutil.MkdirAll(filepath.Join(checkout, kernelConfigDir)))
	other := t.TempDir()

	dir, err := selectSyzkaller([]string{other, checkout})
	require.NoError(t, err)
	assert.Equal(t, checkout, dir)

	_, err = selectSyzkaller([]string{other})
	assert.ErrorContains(t, err, "failed to find the syzkaller checkout")
}

func TestSummary(t *testing.T) {
	sessionDir := t.TempDir()
	store := &manager.DiffFuzzerStore{BasePath: filepath.Join(sessionDir, "artifacts")}
	store.PatchedCrashed(&report.Report{
		Title:  "KASAN: use-after-free in foo",
		Report: []byte("report"),
		Output: []byte("output"),
	})
	store.BaseCrashed("WARNING in bar", []byte("base report"))

	run := &localRun{sessionDir: sessionDir}
	require.NoError(t, run.summary(store))

	bugs, err := osutil.ReadJSON[[]manager.DiffBug](filepath.Join(store.BasePath, "bugs.json"))
	require.NoError(t, err)
	require.Len(t, bugs, 2)
	assert.Equal(t, "KASAN: use-after-free in foo", bugs[0].Title)
	assert.Equal(t, "WARNING in bar", bugs[1].Title)

	summary, err := os.ReadFile(filepath.Join(sessionDir, "summary.txt"))
	require.NoError(t, err)
	for _, bug := range bugs {
		dir := bugDir(bug)
		require.NotEmpty(t, dir)
		assert.True(t, osutil.IsExist(filepath.Join(store.BasePath, dir)))
		assert.Contains(t, string(summary), bug.Title+": "+dir)
	}
	assert.Contains(t, string(summary), "unreproduced patched-only crashes:\n  KASAN: use-after-free in foo (1 crashes)")
}
