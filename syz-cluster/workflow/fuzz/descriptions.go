// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/fuzzconfig"
	"github.com/google/syzkaller/syz-cluster/pkg/triage"
)

// generateDescriptions lets AI update the syscall descriptions for the patch series.
// Failures are not fatal: we then just fuzz with the original descriptions.
func generateDescriptions(ctx context.Context, config *api.FuzzConfig, client *api.Client,
	artifactsDir string) *ai.PatchDescriptionsResult {
	if *flagRepository == "" {
		return nil
	}
	res, err := runDescriptionsWorkflow(ctx, config, client, artifactsDir)
	if err != nil {
		app.Errorf("failed to generate AI descriptions: %v", err)
		return nil
	}
	return res
}

func runDescriptionsWorkflow(ctx context.Context, config *api.FuzzConfig, client *api.Client,
	artifactsDir string) (*ai.PatchDescriptionsResult, error) {
	appConfig, err := app.Config()
	if err != nil {
		return nil, fmt.Errorf("failed to load app config: %w", err)
	}
	if appConfig.AI == nil || appConfig.AI.Empty() {
		return nil, nil
	}
	// Don't waste time and tokens if we are not going to fuzz anyway.
	baseSymbols, patchedSymbols, _ := readSymbolHashes()
	if shouldSkipFuzzing(baseSymbols, patchedSymbols) {
		return nil, nil
	}
	series, err := client.GetSessionSeries(ctx, *flagSession)
	if err != nil {
		return nil, fmt.Errorf("failed to query the series: %w", err)
	}
	if series.IsStableRC() {
		log.Logf(0, "skipping AI descriptions for stable RC series")
		return nil, nil
	}
	// We only need the paths, so the config doesn't need to be completed.
	patched, err := fuzzconfig.GeneratePatched(config)
	if err != nil {
		return nil, err
	}
	targetOS, _, targetArch, _, _, err := mgrconfig.SplitTarget(patched.RawTarget)
	if err != nil {
		return nil, err
	}
	buildDir := filepath.Dir(patched.KernelObj)
	kernelConfig, err := os.ReadFile(filepath.Join(buildDir, "kernel.config"))
	if err != nil {
		return nil, err
	}
	uapiHeaders := filepath.Join(buildDir, "uapi")
	if !osutil.IsExist(uapiHeaders) {
		uapiHeaders = ""
	}
	tracer := &debugtracer.GenericTracer{TraceWriter: log.VerboseWriter(0)}
	if err := setupTriageWorkspace(config, series, tracer); err != nil {
		return nil, err
	}
	aiClient, err := triage.NewAIClient(ctx, appConfig, tracer)
	if err != nil {
		return nil, err
	}
	defer aiClient.Close()
	res, trajectory, err := aiClient.PatchDescriptions(ctx, &ai.PatchDescriptionsArgs{
		TargetOS:         targetOS,
		TargetArch:       targetArch,
		KernelSrc:        *flagRepository,
		KernelConfig:     string(kernelConfig),
		Patches:          triage.SeriesPatches(series),
		Syzkaller:        patched.Syzkaller,
		UAPIHeaders:      uapiHeaders,
		EnabledSyscalls:  patched.EnabledSyscalls,
		DisabledSyscalls: patched.DisabledSyscalls,
	})
	if len(trajectory) != 0 {
		if err := osutil.WriteFile(filepath.Join(artifactsDir, "ai_descriptions.html"), trajectory); err != nil {
			log.Logf(0, "failed to save the AI descriptions trajectory: %v", err)
		}
	}
	if err != nil {
		return nil, err
	}
	if res.Diff != "" {
		if err := osutil.WriteFile(filepath.Join(artifactsDir, "ai_descriptions.diff"), []byte(res.Diff)); err != nil {
			log.Logf(0, "failed to save the AI descriptions diff: %v", err)
		}
	}
	return res, nil
}

// applyDescriptions switches the configs to the AI-updated descriptions and boosts the relevant syscalls.
// On failure, it returns the original configs.
func applyDescriptions(base, patched *mgrconfig.Config, res *ai.PatchDescriptionsResult) (
	*mgrconfig.Config, *mgrconfig.Config) {
	if res == nil {
		return base, patched
	}
	newBase, newPatched, err := withDescriptions(base, patched, res, filepath.Join(*flagWorkdir, "descriptions"))
	if err != nil {
		app.Errorf("failed to apply AI descriptions: %v", err)
		return base, patched
	}
	log.Logf(0, "fuzzing with AI descriptions: new syscalls %q, boosted syscalls %q",
		res.NewSyscalls, res.RelevantSyscalls)
	return newBase, newPatched
}

func withDescriptions(base, patched *mgrconfig.Config, res *ai.PatchDescriptionsResult, workdir string) (
	*mgrconfig.Config, *mgrconfig.Config, error) {
	target := patched.Target
	if len(res.Files) != 0 {
		var err error
		target, err = compileDescriptions(filepath.Join(patched.Syzkaller, "sys", patched.TargetOS),
			workdir, res.Files, patched.Target)
		if err != nil {
			return nil, nil, err
		}
	}
	// Focused configs enable only some syscalls, make sure that the AI-selected ones are enabled.
	// The base kernel also needs the new target since it runs the patched kernel programs.
	enable := slices.Concat(res.NewSyscalls, res.RelevantSyscalls)
	newBase, err := withEnabledSyscalls(base, target, enable)
	if err != nil {
		return nil, nil, err
	}
	newPatched, err := withEnabledSyscalls(patched, target, enable)
	if err != nil {
		return nil, nil, err
	}
	// Some of the relevant syscalls may still be disabled by the config (e.g. by disable_syscalls).
	enabled := map[string]bool{}
	for _, id := range newPatched.Syscalls {
		enabled[target.Syscalls[id].Name] = true
	}
	var boosted []string
	for _, name := range res.RelevantSyscalls {
		if enabled[name] {
			boosted = append(boosted, name)
		} else {
			log.Logf(0, "not boosting %v: it's disabled in the config", name)
		}
	}
	newPatched.Experimental.BoostedSyscalls = boosted
	newPatched.BoostedCalls, err = mgrconfig.ParseBoostedSyscalls(target, newPatched.Syscalls, boosted)
	if err != nil {
		return nil, nil, err
	}
	return newBase, newPatched, nil
}

func withEnabledSyscalls(cfg *mgrconfig.Config, target *prog.Target, syscalls []string) (*mgrconfig.Config, error) {
	ret := *cfg
	if len(ret.EnabledSyscalls) != 0 {
		ret.EnabledSyscalls = slices.Concat(ret.EnabledSyscalls, syscalls)
	}
	return ret.WithTarget(target)
}

// compileDescriptions compiles the descriptions from sysDir with the updated files applied on top.
func compileDescriptions(sysDir, dir string, files map[string]string, base *prog.Target) (*prog.Target, error) {
	if err := osutil.CopyDirRecursively(sysDir, dir); err != nil {
		return nil, err
	}
	for name, data := range files {
		if err := osutil.WriteFile(filepath.Join(dir, name), []byte(data)); err != nil {
			return nil, err
		}
	}
	res, err := compiler.CompileTarget(dir, base)
	if err != nil {
		return nil, err
	}
	if len(res.MissingConsts) != 0 {
		return nil, fmt.Errorf("missing consts, e.g. %v", res.MissingConsts[0].Name)
	}
	return res.Target, nil
}
