// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
)

var fileNameRe = regexp.MustCompile(`(?m)(?:\-\-\-|\+\+\+)\s(?:a|b)\/([^\s]+)`)

func extractModifiedFiles(cfg *mgrconfig.Config, data []byte) {
	const maxAffectedByHeader = 50

	names := map[string]bool{}
	for _, match := range fileNameRe.FindAllStringSubmatch(string(data), -1) {
		file := match[1]
		names[file] = true

		if strings.HasSuffix(file, ".h") && cfg.KernelSrc != "" {
			// Ideally, we should combine this with the recompilation process - then we know
			// exactly which files were affected by the patch.
			out, err := osutil.RunCmd(time.Minute, cfg.KernelSrc, "/usr/bin/grep",
				"-rl", "--include", `*.c`, `<`+strings.TrimPrefix(file, "include/")+`>`)
			if err != nil {
				log.Logf(0, "failed to grep for the header usages: %v", err)
				continue
			}
			lines := strings.Split(string(out), "\n")
			if len(lines) >= maxAffectedByHeader {
				// It's too widespread. It won't help us focus on anything.
				log.Logf(0, "the header %q is included in too many files (%d)", file, len(lines))
				continue
			}
			for _, name := range lines {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				names[name] = true
			}
		}
	}

	var namesList []string
	for name := range names {
		namesList = append(namesList, name)
		cfg.FuzzFilter.Files = append(cfg.FuzzFilter.Files, name)
	}

	sort.Strings(namesList)
	log.Logf(0, "adding the following affected files to fuzz_filter: %q", namesList)
}
