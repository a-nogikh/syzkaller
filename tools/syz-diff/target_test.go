// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/fuzzconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const netPatch = `diff --git a/net/core/sock.c b/net/core/sock.c
index 1111111..2222222 100644
--- a/net/core/sock.c
+++ b/net/core/sock.c
@@ -1,3 +1,3 @@
 a
-b
+c
 d
`

func TestLoadSeries(t *testing.T) {
	dir := t.TempDir()
	patchFile := filepath.Join(dir, "fix.diff")
	require.NoError(t, os.WriteFile(patchFile, []byte(netPatch), 0644))
	series, err := loadSeries(patchFile)
	require.NoError(t, err)
	assert.Equal(t, "fix.diff", series.Title)
	require.Len(t, series.Patches, 1)
	assert.Equal(t, []byte(netPatch), series.Patches[0].Body)
	assert.Equal(t, []string{"net/core/sock.c"}, series.ModifiedFiles())

	badFile := filepath.Join(dir, "bad.diff")
	require.NoError(t, os.WriteFile(badFile, []byte("not a patch\n"), 0644))
	_, err = loadSeries(badFile)
	assert.ErrorContains(t, err, "does not look like a git diff")

	_, err = loadSeries(filepath.Join(dir, "missing.diff"))
	assert.Error(t, err)
}

func TestSelectTarget(t *testing.T) {
	target, err := selectTarget(&api.Series{
		Patches: []api.SeriesPatch{{Body: []byte(netPatch)}},
	})
	require.NoError(t, err)
	assert.Equal(t, string(api.TrackKASAN), target.Track)
	assert.NotEmpty(t, target.KernelConfig)
	assert.Equal(t, []string{api.FocusNet}, target.FuzzConfig.Focus)
	assert.NotEmpty(t, target.FuzzConfig.CorpusURLs)

	// Patches that don't match any specific target are fuzzed without focus.
	target, err = selectTarget(&api.Series{
		Patches: []api.SeriesPatch{{Body: []byte(`diff --git a/lib/foo.c b/lib/foo.c
--- a/lib/foo.c
+++ b/lib/foo.c
@@ -1 +1 @@
-a
+b
`)}},
	})
	require.NoError(t, err)
	assert.Empty(t, target.FuzzConfig.Focus)
	assert.NotEmpty(t, target.FuzzConfig.CorpusURLs)
}

func TestSetPaths(t *testing.T) {
	cfg, err := fuzzconfig.GeneratePatched(&api.FuzzConfig{})
	require.NoError(t, err)
	paths := kernelPaths{
		KernelObj:      "/build/obj",
		Image:          "/cache/image",
		Kernel:         "/build/kernel",
		Syzkaller:      "/syzkaller",
		Workdir:        "/session/patched",
		KernelSrc:      "/src",
		KernelBuildSrc: "/build-src",
	}
	require.NoError(t, setPaths(cfg, paths))
	assert.Equal(t, paths.KernelObj, cfg.KernelObj)
	assert.Equal(t, paths.Image, cfg.Image)
	assert.Equal(t, paths.Syzkaller, cfg.Syzkaller)
	assert.Equal(t, paths.Workdir, cfg.Workdir)
	assert.Equal(t, paths.KernelSrc, cfg.KernelSrc)
	assert.Equal(t, paths.KernelBuildSrc, cfg.KernelBuildSrc)

	var vmCfg map[string]any
	require.NoError(t, json.Unmarshal(cfg.VM, &vmCfg))
	assert.Equal(t, paths.Kernel, vmCfg["kernel"])
	// The rest of the VM config must be preserved.
	assert.EqualValues(t, 9, vmCfg["count"])
	assert.Equal(t, "root=/dev/sda1", vmCfg["cmdline"])
}
