// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	golog "log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	pkgbuild "github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/manager/diff"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/build"
	"github.com/google/syzkaller/syz-cluster/pkg/fuzz"
	"github.com/google/syzkaller/syz-cluster/pkg/fuzzconfig"
	"github.com/google/syzkaller/vm"
)

const (
	kernelArch = "amd64"
	compiler   = "clang" // See syz-cluster/pkg/build.
	httpAddr   = "localhost:50544"
)

type localParams struct {
	Workdir    string
	BaseCommit string
	PatchFile  string
	Duration   time.Duration
	CacheSize  uint64
	Debug      bool
}

// localRun builds the base and the patched kernels (or takes them from the cache)
// and runs a syz-cluster-like differential fuzzing session.
type localRun struct {
	localParams
	ctx        context.Context
	syzkaller  string
	sessionDir string
	cache      *artifactCache
	repo       *kernelRepo
}

func runLocal(params localParams) error {
	syzkaller, err := findSyzkaller()
	if err != nil {
		return err
	}
	workdir := osutil.Abs(params.Workdir)
	params.Workdir = workdir
	sessionDir := filepath.Join(workdir, "sessions", time.Now().Format("2006-01-02_15-04-05"))
	if err := osutil.MkdirAll(sessionDir); err != nil {
		return err
	}
	// Duplicate all log output into the session dir.
	// The file is intentionally kept open until the process exits, so that the final error is also logged.
	logFile, err := os.Create(filepath.Join(sessionDir, "log.txt"))
	if err != nil {
		return err
	}
	golog.SetOutput(io.MultiWriter(os.Stderr, logFile))
	log.Logf(0, "session dir: %v", sessionDir)
	cache, err := newArtifactCache(filepath.Join(workdir, "cache"), params.CacheSize)
	if err != nil {
		return fmt.Errorf("failed to initialize the cache: %w", err)
	}
	defer cache.release()
	repo, err := newKernelRepo(workdir)
	if err != nil {
		return err
	}
	// Let Ctrl+C stop fuzzing gracefully and still print the summary.
	osutil.HandleInterrupts(vm.Shutdown)
	run := &localRun{
		localParams: params,
		ctx:         vm.ShutdownCtx(),
		syzkaller:   syzkaller,
		sessionDir:  sessionDir,
		cache:       cache,
		repo:        repo,
	}
	err = run.run()
	if err != nil && run.ctx.Err() != nil && errors.Is(err, context.Canceled) {
		log.Logf(0, "interrupted")
		return nil
	}
	return err
}

// kernelConfigDir is the location of the kernel configs within the syzkaller checkout.
var kernelConfigDir = filepath.Join("dashboard", "config", "linux")

// findSyzkaller returns the syzkaller checkout with the built binaries and the kernel configs.
// syz-diff is normally run as <checkout>/bin/syz-diff, otherwise the current dir is checked.
func findSyzkaller() (string, error) {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			candidates = append(candidates, filepath.Dir(filepath.Dir(exe)))
		}
	}
	candidates = append(candidates, osutil.Abs("."))
	return selectSyzkaller(candidates)
}

func selectSyzkaller(candidates []string) (string, error) {
	for _, dir := range candidates {
		if osutil.IsExist(filepath.Join(dir, kernelConfigDir)) {
			return dir, nil
		}
	}
	return "", fmt.Errorf("failed to find the syzkaller checkout (tried %v),"+
		" build syz-diff with `make diff` and run it as bin/syz-diff", strings.Join(candidates, ", "))
}

func (r *localRun) run() error {
	series, err := loadSeries(r.PatchFile)
	if err != nil {
		return err
	}
	patch := series.Patches[0].Body
	target, err := selectTarget(series)
	if err != nil {
		return err
	}
	fuzzCfg := *target.FuzzConfig
	log.Logf(0, "kernel config: %v, focus: %q, corpus: %q",
		target.KernelConfig, fuzzCfg.Focus, fuzzCfg.CorpusURLs)
	if err := osutil.WriteJSON(filepath.Join(r.sessionDir, "fuzz_config.json"), fuzzCfg); err != nil {
		return err
	}

	commit, err := r.repo.resolve(torvaldsURL, torvaldsBranch, r.BaseCommit)
	if err != nil {
		return err
	}
	log.Logf(0, "base commit: %v", commit)
	image, err := r.cache.image(r.ctx)
	if err != nil {
		return err
	}
	baseBuild, err := r.buildKernel("base", commit, nil, target.KernelConfig, image)
	if err != nil {
		return err
	}
	patchedBuild, err := r.buildKernel("patched", commit, patch, target.KernelConfig, image)
	if err != nil {
		return err
	}
	// The builds may have been taken from the cache, so make sure that the sources match the patched kernel.
	// They are used for the coverage reports and for symbolization.
	if err := r.repo.checkout(commit, patch); err != nil {
		return err
	}

	var corpusFiles []string
	for _, url := range fuzzCfg.CorpusURLs {
		file, err := r.cache.corpus(r.ctx, url)
		if err != nil {
			return err
		}
		corpusFiles = append(corpusFiles, file)
	}
	fuzzCfg.CorpusURLs = nil

	base, err := r.managerConfig(fuzzconfig.GenerateBase, &fuzzCfg, "base", baseBuild, image)
	if err != nil {
		return err
	}
	patched, err := r.managerConfig(fuzzconfig.GeneratePatched, &fuzzCfg, "patched", patchedBuild, image)
	if err != nil {
		return err
	}
	patched.HTTP = httpAddr
	for name, cfg := range map[string]*mgrconfig.Config{"base": base, "patched": patched} {
		if err := config.SaveFile(filepath.Join(r.sessionDir, name+".cfg"), cfg); err != nil {
			return err
		}
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	return r.fuzz(base, patched, baseBuild, patchedBuild, &fuzzCfg, series, corpusFiles)
}

// buildKernel returns the dir with the kernel build artifacts (see syz-cluster/pkg/build.Run).
func (r *localRun) buildKernel(name, commit string, patch []byte, configName, image string) (string, error) {
	// Kernel builds cannot be interrupted, so at least don't start new ones.
	if err := r.ctx.Err(); err != nil {
		return "", err
	}
	configDir := filepath.Join(r.syzkaller, kernelConfigDir)
	kernelConfig, err := os.ReadFile(filepath.Join(configDir, configName))
	if err != nil {
		return "", fmt.Errorf("failed to read the kernel config: %w", err)
	}
	compilerID, err := pkgbuild.CompilerIdentity(compiler)
	if err != nil {
		return "", fmt.Errorf("failed to query the compiler version: %w", err)
	}
	logFile := filepath.Join(r.sessionDir, fmt.Sprintf("build-%v.log", name))
	desc := buildCacheDesc(commit, patch, configName, kernelConfig, compilerID)
	return r.cache.get("build", desc, func(dir string) error {
		log.Logf(0, "building the %v kernel (log: %v)", name, logFile)
		start := time.Now()
		if err := r.repo.checkout(commit, patch); err != nil {
			return err
		}
		logOutput, err := os.Create(logFile)
		if err != nil {
			return err
		}
		defer logOutput.Close()
		var ccache string
		if _, err := exec.LookPath("ccache"); err == nil {
			ccache = "ccache"
		}
		res, err := build.Run(&build.Params{
			Req: &api.BuildRequest{
				Arch:       kernelArch,
				ConfigName: configName,
			},
			KernelDir:    r.repo.buildDir,
			OutputDir:    dir,
			ConfigDir:    configDir,
			UserspaceDir: image,
			Ccache:       ccache,
			Tracer:       &debugtracer.GenericTracer{WithTime: true, TraceWriter: logOutput},
		})
		if err != nil {
			return fmt.Errorf("failed to build the %v kernel: %w", name, err)
		}
		if !res.Success {
			return fmt.Errorf("failed to build the %v kernel (see %v):\n%s", name, logFile, res.Report)
		}
		log.Logf(0, "built the %v kernel in %v", name, time.Since(start).Round(time.Second))
		// We don't need a copy of the image in each build dir.
		return os.Remove(filepath.Join(dir, "image"))
	})
}

func (r *localRun) managerConfig(generate func(*api.FuzzConfig) (*mgrconfig.Config, error),
	fuzzCfg *api.FuzzConfig, name, buildDir, image string) (*mgrconfig.Config, error) {
	cfg, err := generate(fuzzCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the %v config: %w", name, err)
	}
	err = setPaths(cfg, kernelPaths{
		KernelObj:      filepath.Join(buildDir, "obj"),
		Image:          image,
		Kernel:         filepath.Join(buildDir, "kernel"),
		Syzkaller:      r.syzkaller,
		Workdir:        filepath.Join(r.sessionDir, name),
		KernelSrc:      r.repo.buildDir,
		KernelBuildSrc: r.repo.buildDir,
	})
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (r *localRun) fuzz(base, patched *mgrconfig.Config, baseBuild, patchedBuild string,
	fuzzCfg *api.FuzzConfig, series *api.Series, corpusFiles []string) error {
	baseSymbols, err := build.ReadSymbolHashes(baseBuild)
	if err != nil {
		log.Errorf("failed to read the base symbol hashes: %v", err)
	}
	patchedSymbols, err := build.ReadSymbolHashes(patchedBuild)
	if err != nil {
		log.Errorf("failed to read the patched symbol hashes: %v", err)
	}
	crashesDir := filepath.Join(r.Workdir, "base-crashes")
	if err := osutil.MkdirAll(crashesDir); err != nil {
		return err
	}
	knownCrashes, err := loadBaseCrashes(filepath.Join(crashesDir, filepath.Base(baseBuild)+".json"))
	if err != nil {
		return err
	}
	artifactsDir := filepath.Join(r.sessionDir, "artifacts")
	if err := osutil.MkdirAll(artifactsDir); err != nil {
		return err
	}
	store := &manager.DiffFuzzerStore{BasePath: artifactsDir}

	log.Logf(0, "fuzzing for %v, web UI: http://%v", r.Duration, httpAddr)
	ctx, cancel := context.WithTimeout(r.ctx, r.Duration)
	defer cancel()
	err = fuzz.Run(ctx, &fuzz.Params{
		Base:           base,
		Patched:        patched,
		BaseSymbols:    baseSymbols,
		PatchedSymbols: patchedSymbols,
		Config:         fuzzCfg,
		Series:         series,
		Timeout:        r.Duration,
		CorpusFiles:    corpusFiles,
		Debug:          r.Debug,
		Store:          store,
		OnBaseCrash: func(ctx context.Context, title string) {
			if err := knownCrashes.Add(title); err != nil {
				log.Errorf("failed to save the base crash: %v", err)
			}
		},
		OnBug: func(ctx context.Context, bug *diff.Bug) {
			log.Logf(0, "patched-only bug: %q (repro: %v)", bug.Report.Title, bug.Repro != nil)
		},
		ShouldIgnoreCrash: func(ctx context.Context, title string) (bool, error) {
			return knownCrashes.Has(title), nil
		},
	})
	if errors.Is(err, fuzz.ErrSkipFuzzing) {
		log.Logf(0, "the base and the patched kernel binaries are identical, nothing to fuzz")
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		err = nil
	}
	// Even if fuzzing failed, there may already be some findings.
	if summaryErr := r.summary(store); summaryErr != nil {
		if err == nil {
			return summaryErr
		}
		log.Errorf("failed to save the summary: %v", summaryErr)
	}
	return err
}

func (r *localRun) summary(store *manager.DiffFuzzerStore) error {
	bugs := store.List()
	slices.SortFunc(bugs, func(a, b manager.DiffBug) int {
		return strings.Compare(a.Title, b.Title)
	})
	if err := osutil.WriteJSON(filepath.Join(store.BasePath, "bugs.json"), bugs); err != nil {
		return err
	}
	summary := new(bytes.Buffer)
	summary.Write(store.PlainTextDump())
	if candidates := fuzz.FilterFindingCandidates(bugs); len(candidates) > 0 {
		fmt.Fprintf(summary, "\nunreproduced patched-only crashes:\n")
		for _, bug := range candidates {
			fmt.Fprintf(summary, "  %v (%v crashes)\n", bug.Title, bug.Patched.Crashes)
		}
	}
	if len(bugs) > 0 {
		fmt.Fprintf(summary, "\nartifacts (in %v):\n", store.BasePath)
		for _, bug := range bugs {
			if dir := bugDir(bug); dir != "" {
				fmt.Fprintf(summary, "  %v: %v\n", bug.Title, dir)
			}
		}
	}
	file := filepath.Join(r.sessionDir, "summary.txt")
	if err := osutil.WriteFile(file, summary.Bytes()); err != nil {
		return err
	}
	log.Logf(0, "summary (%v):\n%s", file, summary.Bytes())
	return nil
}

// bugDir returns the bug's artifacts dir relative to DiffFuzzerStore.BasePath.
func bugDir(bug manager.DiffBug) string {
	for _, file := range []string{bug.Patched.Report, bug.Patched.CrashLog, bug.Patched.Repro,
		bug.Patched.ReproLog, bug.Base.Report} {
		if file != "" {
			return filepath.Dir(file)
		}
	}
	return ""
}
