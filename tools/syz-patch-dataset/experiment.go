// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

func experimentLoop(state *state, experimentFile *object[Experiment]) {
	exp := experimentFile.get()

	ensureResult := func(release KernelRelease, id string, series *Series) *ExperimentResult {
		results := exp.getResults(release, id)
		if len(results) > 0 {
			return results[0]
		}
		log.Printf("running experiment: release %s, series %v", release.Tag, id)
		result := runExperiment(state, release, id, series)
		log.Printf("build time %v, run time %v, errors: apply %q, build %q, run %q",
			result.BuildTime, result.RunTime,
			result.ApplyError, result.BuildError, result.RunError)

		exp.Results = append(exp.Results, result)

		err := experimentFile.save(exp)
		if err != nil {
			log.Fatal(err)
		}
		return result
	}

	for id, series := range exp.Dataset {
		release, rc := releasesForPatch(state.releases.get(), series.Patches[0])
		if rc != nil {
			res := ensureResult(*rc, "", nil)
			if res.Success() {
				res := ensureResult(*rc, id, &series)
				if res.Success() {
					continue
				}
			}
		}
		if release != nil {
			res := ensureResult(*release, "", nil)
			if res.Success() {
				ensureResult(*release, id, &series)
			}
		}
	}
}

func runExperiment(state *state, release KernelRelease, id string, series *Series) *ExperimentResult {
	ret := &ExperimentResult{Release: release, SeriesID: id}

	kernel := state.kernel
	_, err := kernel.SwitchCommit(release.Commit)
	if err != nil {
		log.Fatalf("failed to switch commit: %v", err)
	}

	vcs.LinuxFixBackportsPublic(kernel)

	if series != nil {
		for _, patch := range series.Patches {
			blob, err := state.patchStorage.read(patch.ID)
			if err != nil {
				log.Fatalf("failed to read blob for patch %q: %v", patch.ID, err)
			}
			err = vcs.Patch(*flagKernel, blob)
			if err != nil {
				ret.ApplyError = fmt.Sprintf("failed to apply patch %q: %v", patch.ID, err)
				return ret
			}
		}
	}

	err = osutil.CopyFile(*flagKernelConfig, filepath.Join(*flagKernel, ".config"))
	if err != nil {
		log.Fatalf("failed to copy the kernel config: %v", err)
	}

	buildStart := time.Now()

	_, err = osutil.RunCmd(time.Minute*30, *flagKernel, "make", "CC=clang", "LD=ld.lld", "olddefconfig")
	ret.BuildTime = time.Since(buildStart)
	if err != nil {
		ret.BuildError = fmt.Sprint(err)
		return ret
	}

	_, err = osutil.RunCmd(time.Minute*30, *flagKernel, "make", "CC=clang", "LD=ld.lld", "-j64")
	ret.BuildTime = time.Since(buildStart)
	if err != nil {
		ret.BuildError = fmt.Sprint(err)
		return ret
	}

	runCorpus(ret, id == "")

	log.Printf("done: %d bugs found", len(ret.Bugs))

	return ret
}

func runCorpus(ret *ExperimentResult, release bool) {
	if !osutil.IsExist(*flagSyzkaller) || !osutil.IsDir(*flagSyzkaller) {
		log.Fatalf("invalid syzkaller directory: %v", *flagSyzkaller)
	}
	crashes := filepath.Join(*flagSyzkaller, "workdir", "crashes")
	os.RemoveAll(crashes)

	start := time.Now()

	_, err := osutil.RunCmd(time.Minute*10, *flagSyzkaller, "./bin/syz-manager",
		"-config", "experiment_fast.cfg", "-mode", "smoke-test")
	if err != nil {
		ret.RunError = fmt.Sprint("boot error: %v", err)
	}

	timeout := time.Minute * 15
	if release {
		timeout = time.Minute * 60
	}
	log.Printf("running the manager for %v", timeout)
	_, err = osutil.RunCmd(timeout, *flagSyzkaller, "./bin/syz-manager",
		"-config", "experiment.cfg", "-mode", "corpus-run")
	ret.RunTime = time.Since(start)
	if err != nil && !strings.Contains(fmt.Sprint(err), "timedout after") {
		ret.RunError = fmt.Sprint(err)
		return
	}
	crashMap, err := extractCrashes(crashes)
	if err != nil {
		log.Fatal(err)
	}
	ret.Bugs = map[string]string{}
	for title, report := range crashMap {
		if len(ret.Bugs[title]) > 0 {
			continue
		}
		ret.Bugs[title] = report
	}
}

func extractCrashes(crashdir string) (map[string]string, error) {
	dirs, err := osutil.ListDir(crashdir)
	if err != nil {
		return nil, err
	}
	ret := map[string]string{}
	for _, dir := range dirs {
		bugFolder := filepath.Join(crashdir, dir)
		title, err := os.ReadFile(filepath.Join(bugFolder, "description"))
		if err != nil {
			continue
		}
		report, _ := os.ReadFile(filepath.Join(bugFolder, "report0"))
		ret[strings.TrimSpace(string(title))] = string(report)
	}
	return ret, nil
}

func testCorpusSaturation() {
	syzkaller := *flagSyzkaller
	crashes := filepath.Join(syzkaller, "workdir", "crashes")

	stop := make(chan bool)
	go func() {
		start := time.Now()
		for {
			select {
			case <-time.After(time.Minute):
			case <-stop:
				return
			}
			crashes, err := extractCrashes(crashes)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("%d minutes: %d bugs", int(time.Since(start).Minutes()), len(crashes))
		}

	}()

	_, err := osutil.RunCmd(time.Minute*60, *flagSyzkaller, "./bin/syz-manager",
		"-config", "experiment.cfg", "-mode", "corpus-run")
	log.Printf("finished: %v", err)
	close(stop)
}

func (e Experiment) getResults(release KernelRelease, seriesID string) []*ExperimentResult {
	var ret []*ExperimentResult
	for _, item := range e.Results {
		if item.Release != release {
			continue
		}
		if item.SeriesID != seriesID {
			continue
		}
		ret = append(ret, item)
	}
	return ret
}
