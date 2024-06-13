// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"log"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagSyzkaller    = flag.String("syzkaller", "/tmp/syzkaller", "A configured syzkaller checkout")
	flagKernel       = flag.String("kernel", "", "Linux kernel checkout")
	flagKernelConfig = flag.String("kernel_config", "", "Linux kernel config")
	flagWorkdir      = flag.String("workdir", "./workdir", "path to the workdir")
	flagHTTP         = flag.String("http", "", "An HTTP port to listen on")
)

func main() {
	defer tool.Init()()

	start := time.Now()
	state := loadState()
	log.Printf("state loaded in %v", time.Since(start))

	expObj, err := newObject[Experiment](filepath.Join(*flagWorkdir, "experiment_2.bin"))
	if err != nil {
		log.Fatal(err)
	}
	if *flagHTTP != "" {
		serveHTTP(state, expObj.get())
	} else {
		firstExperiment(state)
	}
}

func firstExperiment(state *state) {
	expObj, err := newObject[Experiment](filepath.Join(*flagWorkdir, "experiment_2.bin"))
	if err != nil {
		log.Fatal(err)
	}

	obj := expObj.get()
	if obj.Description == "" {
		obj.Description = "The smoky experiment"
		obj.Dataset = filterFixedSeries(state)
		err := expObj.save(obj)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("initialized the experiment: dataset has %d entries", len(obj.Dataset))
	}

	experimentLoop(state, expObj)
}

type state struct {
	kernel         vcs.Repo
	patchStorage   *blobStorage
	series         *object[map[string]Series]
	commitToSeries *object[map[string]string]
	releases       *object[[]KernelRelease]
}

func loadState() *state {
	var s state

	var err error
	s.patchStorage, err = newBlobStorage(filepath.Join(*flagWorkdir, "patches"))
	if err != nil {
		log.Fatal(err)
	}

	s.series, err = newObject[map[string]Series](filepath.Join(*flagWorkdir, "series.bin"))
	if err != nil {
		log.Fatal(err)
	}

	s.releases, err = newObject[[]KernelRelease](filepath.Join(*flagWorkdir, "releases.bin"))
	if err != nil {
		log.Fatal(err)
	}

	s.kernel, err = vcs.NewRepo(targets.Linux, "", *flagKernel)
	if err != nil {
		log.Fatal(err)
	}

	return &s
}
