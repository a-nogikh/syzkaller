// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"cmp"
	"slices"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
)

const (
	// pcSampleRate is the share of fuzzing executions for which we collect full coverage
	// in order to profile the distribution of the fuzzer attention over kernel PCs.
	pcSampleRate           = 0.05
	defaultMinExecs        = 1000
	defaultMinDuration     = 5 * time.Minute
	defaultMinAreaHits     = 100
	defaultAttentionCutoff = 0.85
)

type pcSampler struct {
	mu          sync.Mutex
	pcHits      map[uint64]int
	totalHits   int
	execCount   int
	windowStart time.Time
}

func newPCSampler(now time.Time) *pcSampler {
	return &pcSampler{
		pcHits:      make(map[uint64]int),
		windowStart: now,
	}
}

func (s *pcSampler) collect(info *flatrpc.ProgInfo) {
	if info == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execCount++
	for _, call := range info.Calls {
		if call == nil {
			continue
		}
		for _, pc := range call.Cover {
			s.pcHits[pc]++
			s.totalHits++
		}
	}
	if info.Extra != nil {
		for _, pc := range info.Extra.Cover {
			s.pcHits[pc]++
			s.totalHits++
		}
	}
}

// trySnapshotAndReset atomically checks whether the accumulation window is complete and,
// if so, returns the collected hits and starts a new window. Checking and resetting must
// happen under the same lock, otherwise a concurrent caller could observe an empty window
// and wrongly conclude that there is nothing to focus on.
func (s *pcSampler) trySnapshotAndReset(now time.Time, minExecs int, minDuration time.Duration) (
	hits map[uint64]int, totalHits, execCount int, elapsed time.Duration, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	elapsed = now.Sub(s.windowStart)
	if s.execCount < minExecs || elapsed < minDuration {
		return nil, s.totalHits, s.execCount, elapsed, false
	}
	hits = s.pcHits
	totalHits = s.totalHits
	execCount = s.execCount
	s.pcHits = make(map[uint64]int)
	s.totalHits = 0
	s.execCount = 0
	s.windowStart = now
	return hits, totalHits, execCount, elapsed, true
}

type pcCount struct {
	pc    uint64
	count int
}

func calculateCompensatoryAreas(baseAreas []corpus.FocusArea, pcHits map[uint64]int,
	minAreaHits int, attentionCutoff float64, logf func(string, ...any)) []corpus.FocusArea {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if len(pcHits) == 0 {
		logf("compensatory areas: no PC hits collected during window")
		return nil
	}
	isDefaultMode := len(baseAreas) == 0
	if isDefaultMode {
		// No focus areas were configured; treat the whole kernel as a single default area.
		baseAreas = []corpus.FocusArea{{
			Name:   "default",
			Weight: 1.0,
		}}
	}

	var compAreas []corpus.FocusArea
	for _, base := range baseAreas {
		var areaHits []pcCount
		var areaTotal int
		for pc, count := range pcHits {
			if len(base.CoverPCs) > 0 {
				if _, ok := base.CoverPCs[pc]; !ok {
					continue
				}
			}
			areaHits = append(areaHits, pcCount{pc: pc, count: count})
			areaTotal += count
		}
		if areaTotal < minAreaHits {
			logf("compensatory area for %q: omitted (only %d sampled hits, need %d)", base.Name, areaTotal, minAreaHits)
			continue
		}
		if len(areaHits) < 2 {
			logf("compensatory area for %q: omitted (only %d distinct PC hit)", base.Name, len(areaHits))
			continue
		}

		slices.SortFunc(areaHits, func(a, b pcCount) int {
			if a.count != b.count {
				return cmp.Compare(b.count, a.count)
			}
			return cmp.Compare(a.pc, b.pc)
		})

		cutoff := int(float64(areaTotal) * attentionCutoff)
		hotPCs := make(map[uint64]struct{})
		var accum int
		for _, item := range areaHits {
			hotPCs[item.pc] = struct{}{}
			accum += item.count
			if accum >= cutoff {
				break
			}
		}

		name := base.Name
		if name == "" || name == "default" {
			name = "compensatory"
		} else {
			name += " [compensatory]"
		}

		actualAttention := 0.0
		if areaTotal > 0 {
			actualAttention = float64(accum) / float64(areaTotal) * 100
		}

		if len(base.CoverPCs) > 0 {
			// Configured focus area: reduce the positive filter directly to the colder PC subset.
			colderPCs := make(map[uint64]struct{})
			for pc := range base.CoverPCs {
				if _, ok := hotPCs[pc]; !ok {
					colderPCs[pc] = struct{}{}
				}
			}
			if len(colderPCs) == 0 {
				logf("compensatory area for %q: omitted (all %d PCs in base area are hot)", base.Name, len(base.CoverPCs))
				continue
			}
			logf("compensatory area for %q: created %q with weight %.1f "+
				"(reduced from %d to %d cold PCs, dropped %d hot PCs covering %.1f%% of hits)",
				base.Name, name, base.Weight, len(base.CoverPCs), len(colderPCs), len(hotPCs), actualAttention)
			compAreas = append(compAreas, corpus.FocusArea{
				Name:     name,
				CoverPCs: colderPCs,
				Weight:   base.Weight,
				Dynamic:  true,
			})
		} else {
			// Global / default area: negative filter (all kernel code except hot PCs).
			if len(hotPCs) >= len(areaHits) {
				logf("compensatory area: omitted (all %d sampled PCs are hot)", len(areaHits))
				continue
			}
			logf("compensatory area: created %q with weight %.1f (ignored %d hot PCs covering %.1f%% of hits)",
				name, base.Weight, len(hotPCs), actualAttention)
			compAreas = append(compAreas, corpus.FocusArea{
				Name:      name,
				IgnorePCs: hotPCs,
				Weight:    base.Weight,
				Dynamic:   true,
			})
		}
	}
	if isDefaultMode && len(compAreas) > 0 {
		// In default mode, add a baseline dynamic area (nil filters = accepts all corpus programs)
		// with equal weight (1.0) so the baseline corpus and compensatory area compete 50/50.
		compAreas = append([]corpus.FocusArea{{
			Name:    "baseline",
			Weight:  1.0,
			Dynamic: true,
		}}, compAreas...)
	}
	return compAreas
}
