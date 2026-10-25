// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/triage"
)

// loadSeries wraps a git diff into a single-patch series.
func loadSeries(patchFile string) (*api.Series, error) {
	data, err := os.ReadFile(patchFile)
	if err != nil {
		return nil, err
	}
	if len(vcs.ParseGitDiff(data)) == 0 {
		return nil, fmt.Errorf("%v does not look like a git diff", patchFile)
	}
	title := filepath.Base(patchFile)
	return &api.Series{
		Title: title,
		Patches: []api.SeriesPatch{
			{Seq: 1, Title: title, Body: data},
		},
	}, nil
}

// selectTarget picks the fuzzing configuration for the series the same way syz-cluster does.
func selectTarget(series *api.Series) (*triage.MergedFuzzConfig, error) {
	configs := triage.SelectFuzzConfigs(series, api.DefaultFuzzTargets())
	for _, target := range triage.MergeKernelFuzzConfigs(configs) {
		if target.Track == string(api.TrackKASAN) {
			return target, nil
		}
	}
	return nil, fmt.Errorf("no %v fuzz target matches the patch", api.TrackKASAN)
}

type kernelPaths struct {
	KernelObj      string
	Image          string
	Kernel         string
	Syzkaller      string
	Workdir        string
	KernelSrc      string
	KernelBuildSrc string
}

// setPaths replaces the syz-cluster container paths in the manager config with the local ones.
func setPaths(cfg *mgrconfig.Config, paths kernelPaths) error {
	cfg.KernelObj = paths.KernelObj
	cfg.Image = paths.Image
	cfg.Syzkaller = paths.Syzkaller
	cfg.Workdir = paths.Workdir
	cfg.KernelSrc = paths.KernelSrc
	cfg.KernelBuildSrc = paths.KernelBuildSrc
	vmPatch, err := json.Marshal(map[string]string{"kernel": paths.Kernel})
	if err != nil {
		return err
	}
	vmCfg, err := config.MergeJSONs(cfg.VM, vmPatch)
	if err != nil {
		return fmt.Errorf("failed to set the VM kernel: %w", err)
	}
	cfg.VM = vmCfg
	return nil
}
