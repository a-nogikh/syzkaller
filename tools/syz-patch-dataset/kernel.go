// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"log"
	"strings"

	"github.com/google/syzkaller/pkg/vcs"
)

func fetchKernelReleases(state *state) {
	bisecter := state.kernel.(vcs.Bisecter)

	tags, err := bisecter.PreviousReleaseTags("HEAD", "clang", true)
	if err != nil {
		log.Fatal(err)
	}

	var releases []KernelRelease

	for _, tag := range tags {
		commit, err := state.kernel.GetCommit(tag)
		if err != nil {
			log.Fatal(err)
		}
		releases = append(releases, KernelRelease{
			Tag:    tag,
			Commit: commit.Hash,
			Date:   commit.Date,
		})
	}

	log.Printf("%+v", releases)
	err = state.releases.save(releases)
	if err != nil {
		log.Fatal(err)
	}
}

// Returns the closest release & RC.
func releasesForPatch(releases []KernelRelease, patch Patch) (*KernelRelease, *KernelRelease) {
	var rc, release *KernelRelease
	for i := range releases {
		info := &releases[i]
		if info.Date.After(patch.Date) {
			continue
		}

		if strings.Contains(info.Tag, "rc") {
			if rc == nil || info.Date.After(rc.Date) {
				rc = info
			}
		} else {
			if release == nil || info.Date.After(release.Date) {
				release = info
			}
		}
	}
	if rc != nil && release != nil && release.Date.After(rc.Date) {
		rc = nil
	}
	return release, rc
}
