// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-diff runs differential fuzzing of a base and a patched kernel.
//
// If -workdir is set, syz-diff builds both kernels from -base-commit and -patch
// (caching the builds in the workdir) and fuzzes them similarly to syz-cluster:
//
//	bin/syz-diff -workdir ~/syz-workdir -base-commit <commit> -patch fix.diff -time 1h
//
// The results (logs, configs, findings and a summary) are saved to <workdir>/sessions/<timestamp>/.
// The binaries and the kernel configs are taken from the syzkaller checkout syz-diff was built in.
// Without -workdir, it fuzzes two pre-built kernels described by the -base and -new syz-manager configs.
package main

import (
	"flag"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/manager/diff"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

var (
	flagBaseConfig = flag.String("base", "", "base config")
	flagNewConfig  = flag.String("new", "", "new config (treated as the main one)")
	flagDebug      = flag.Bool("debug", false, "dump all VM output to console")
	flagPatch      = flag.String("patch", "", "a git patch")
	flagWorkdir    = flag.String("workdir", "", "persistent working dir; if set, the kernels are built from"+
		" -base-commit and -patch")
	flagBaseCommit = flag.String("base-commit", "", "base kernel commit, tag or branch (with -workdir)")
	flagTime       = flag.Duration("time", time.Hour, "how long to fuzz (with -workdir)")
	flagCacheSize  = flag.String("cache-size", "100GB", "max size of the kernel build/download cache in -workdir"+
		" (e.g. 500MB, 100GB, 1TB)")
)

func main() {
	if !prog.GitRevisionKnown() {
		log.Fatalf("bad syz-diff build: build with make, run bin/syz-diff")
	}
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)

	if *flagWorkdir != "" {
		if *flagBaseCommit == "" || *flagPatch == "" {
			log.Fatalf("-base-commit and -patch must be set together with -workdir")
		}
		if *flagBaseConfig != "" || *flagNewConfig != "" {
			log.Fatalf("-base and -new cannot be used together with -workdir")
		}
		if *flagTime <= 0 {
			log.Fatalf("-time must be positive")
		}
		cacheSize, err := aflow.ParseCacheSize(*flagCacheSize)
		if err != nil {
			log.Fatalf("invalid -cache-size: %v", err)
		}
		err = runLocal(localParams{
			Workdir:    *flagWorkdir,
			BaseCommit: *flagBaseCommit,
			PatchFile:  *flagPatch,
			Duration:   *flagTime,
			CacheSize:  cacheSize,
			Debug:      *flagDebug,
		})
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	baseCfg, err := mgrconfig.LoadFile(*flagBaseConfig)
	if err != nil {
		log.Fatalf("base config: %v", err)
	}

	newCfg, err := mgrconfig.LoadFile(*flagNewConfig)
	if err != nil {
		log.Fatalf("new config: %v", err)
	}

	if *flagPatch != "" {
		data, err := os.ReadFile(*flagPatch)
		if err != nil {
			log.Fatal(err)
		}
		diff.PatchFocusAreas(newCfg, [][]byte{data}, nil, nil)
	}

	ctx := vm.ShutdownCtx()
	err = diff.Run(ctx, baseCfg, newCfg, diff.Config{
		Store: &manager.DiffFuzzerStore{BasePath: newCfg.Workdir},
		Debug: *flagDebug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
