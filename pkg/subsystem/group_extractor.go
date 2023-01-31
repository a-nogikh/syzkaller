// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"github.com/google/syzkaller/pkg/subsystem/entity"
)

// GroupExtractor deduces the subsystems from the list of crashes.
type GroupExtractor struct {
	raw RawExtractorInterface
}

type Crash struct {
	GuiltyPath string
	SyzRepro   []byte
}

type RawExtractorInterface interface {
	FromPath(path string) []*entity.Subsystem
	FromProg(progBytes []byte) []*entity.Subsystem
}

func MakeGroupExtractor(raw RawExtractorInterface) *GroupExtractor {
	return &GroupExtractor{raw}
}

func (ge *GroupExtractor) Extract(crashes []*Crash) []*entity.Subsystem {
	// First put all subsystems to the same list.
	subsystems := []*entity.Subsystem{}
	for _, crash := range crashes {
		if crash.GuiltyPath != "" {
			subsystems = append(subsystems, ge.raw.FromPath(crash.GuiltyPath)...)
		}
		if len(crash.SyzRepro) > 0 {
			subsystems = append(subsystems, ge.raw.FromProg(crash.SyzRepro)...)
		}
	}

	// If there are both parents and children, remove parents.
	ignore := make(map[*entity.Subsystem]struct{})
	for _, entry := range subsystems {
		for p := range entry.ReachableParents() {
			ignore[p] = struct{}{}
		}
	}

	// And calculate counts.
	counts := make(map[*entity.Subsystem]int)
	maxCount := 0
	for _, entry := range subsystems {
		if _, ok := ignore[entry]; ok {
			continue
		}
		counts[entry]++
		if counts[entry] > maxCount {
			maxCount = counts[entry]
		}
	}

	// Pick the most prevalent ones.
	ret := []*entity.Subsystem{}
	for entry, count := range counts {
		if count < maxCount {
			continue
		}
		ret = append(ret, entry)
	}
	return ret
}
