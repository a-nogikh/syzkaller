// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"cmp"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
)

// focusTier holds the triage and mutation job queues for a group of inputs.
// In the patch testing mode, there's a separate tier for each focus area with CoverPCs,
// so that inputs that reach the patched code are triaged and mutated with priority.
// Otherwise, all inputs share the single catch-all tier.
type focusTier struct {
	weight   float64
	coverPCs map[uint64]struct{}
	// Beginnings of the signal.PCRange ranges that contain coverPCs.
	signalRanges map[uint64]struct{}
	// If not set, inputs are only saved to the corpus, but not minimized and mutated.
	inFocus     bool
	hints       *tierJobQueue
	triageQueue *queue.DynamicOrderer
	smashQueue  *queue.PlainQueue
	hintsQueue  *queue.PlainQueue
}

const (
	// Limit concurrently running hints jobs per tier so PlainQueue round-robin doesn't
	// stall thousands of jobs and keep thousands of CompMaps in memory at once,
	// starting pending hints jobs as capacity opens up.
	maxRunningHintsJobs = 25
	// Limit pending new-input hints jobs per tier so memory stays bounded under sustained load.
	maxPendingHintsJobs = 256
	// In the patch testing mode, candidate triage may encounter thousands of corpus seeds
	// in broad focus areas, and each hints job may run thousands of mutants; cap how many
	// candidate hints jobs can be active+pending per tier.
	maxCandidateHintsJobs = 30
)

func newFocusTier(fuzzer *Fuzzer, weight float64) *focusTier {
	return &focusTier{
		weight:      weight,
		inFocus:     true,
		hints:       newTierJobQueue(fuzzer.statJobsHints, maxRunningHintsJobs, maxPendingHintsJobs, maxCandidateHintsJobs),
		triageQueue: queue.DynamicOrder(),
		smashQueue:  queue.Plain(),
		hintsQueue:  queue.Plain(),
	}
}

// tierJobQueue bounds the number of concurrently running jobs of one type in a tier,
// keeping excess jobs pending and starting them as running jobs finish. New inputs
// take priority over re-smashed corpus candidates.
type tierJobQueue struct {
	mu            sync.Mutex
	stat          *stat.Val
	running       int
	maxRunning    int
	maxPending    int
	maxCandidates int
	pendingNew    []job
	pendingCands  []job
}

func newTierJobQueue(stat *stat.Val, maxRunning, maxPending, maxCandidates int) *tierJobQueue {
	return &tierJobQueue{
		stat:          stat,
		maxRunning:    maxRunning,
		maxPending:    maxPending,
		maxCandidates: maxCandidates,
	}
}

func (q *tierJobQueue) submit(fuzzer *Fuzzer, j job, flags ProgFlags) {
	if fuzzer.ctx.Err() != nil {
		return
	}
	candidate := flags&ProgSmashed != 0
	q.mu.Lock()
	if candidate {
		if q.maxCandidates >= 0 && q.running+len(q.pendingCands) >= q.maxCandidates {
			q.mu.Unlock()
			return
		}
		if q.running >= q.maxRunning {
			q.pendingCands = append(q.pendingCands, j)
			q.mu.Unlock()
			return
		}
	} else if q.running >= q.maxRunning {
		if q.maxPending <= 0 || len(q.pendingNew) < q.maxPending {
			q.pendingNew = append(q.pendingNew, j)
		}
		q.mu.Unlock()
		return
	}
	q.running++
	q.mu.Unlock()
	q.start(fuzzer, j)
}

func (q *tierJobQueue) start(fuzzer *Fuzzer, j job) {
	fuzzer.startJobWithDone(q.stat, j, func() {
		q.done(fuzzer)
	})
}

func (q *tierJobQueue) done(fuzzer *Fuzzer) {
	q.mu.Lock()
	if fuzzer.ctx.Err() != nil {
		q.pendingNew = nil
		q.pendingCands = nil
		q.running--
		q.mu.Unlock()
		return
	}
	var next job
	switch {
	case len(q.pendingNew) > 0:
		next = q.pendingNew[0]
		q.pendingNew[0] = nil
		q.pendingNew = q.pendingNew[1:]
	case len(q.pendingCands) > 0:
		next = q.pendingCands[0]
		q.pendingCands[0] = nil
		q.pendingCands = q.pendingCands[1:]
	default:
		q.running--
		q.mu.Unlock()
		return
	}
	q.mu.Unlock()
	q.start(fuzzer, next)
}

// newFocusTiers creates a tier per focus area with CoverPCs in the patch testing mode
// (plus the catch-all tier), or just the catch-all tier otherwise.
func newFocusTiers(fuzzer *Fuzzer) []*focusTier {
	cfg := fuzzer.Config
	catchAll := newFocusTier(fuzzer, 1.0)
	if !cfg.PatchTest {
		return []*focusTier{catchAll}
	}
	areas := cfg.Corpus.FocusAreas()
	slices.SortStableFunc(areas, func(a, b corpus.FocusArea) int {
		return cmp.Compare(b.Weight, a.Weight)
	})
	var tiers []*focusTier
	for _, area := range areas {
		if area.Weight <= 0 {
			continue
		}
		if len(area.CoverPCs) == 0 {
			// The area of the whole corpus (there's at most one such area).
			catchAll.weight = area.Weight
			continue
		}
		tier := newFocusTier(fuzzer, area.Weight)
		tier.coverPCs = area.CoverPCs
		tier.signalRanges = make(map[uint64]struct{})
		for pc := range area.CoverPCs {
			begin, _ := signal.PCRange(pc)
			tier.signalRanges[begin] = struct{}{}
		}
		tiers = append(tiers, tier)
	}
	// We don't want to spend time on inputs that don't reach the focus areas
	// (unless there are no focus areas at all).
	catchAll.inFocus = len(tiers) == 0
	return append(tiers, catchAll)
}

// shouldSmash returns whether an input with the triage flags needs to be smashed.
func (tier *focusTier) shouldSmash(flags ProgFlags) bool {
	if !tier.inFocus {
		return false
	}
	// Programs that reach a focus area are smashed even if they were smashed before
	// (e.g. corpus candidates in the patch testing mode) since the focus area is new.
	return flags&ProgSmashed == 0 || len(tier.coverPCs) != 0
}

// mayCover returns whether the signal may include PCs from the tier's focus area.
// Signal elements only approximately identify PCs (see signal.PCRange), so this may
// return true for signal from unrelated code close to the focus area.
func (tier *focusTier) mayCover(sig signal.Signal) bool {
	for e := range sig {
		begin, _ := signal.PCRange(uint64(e))
		if _, ok := tier.signalRanges[begin]; ok {
			return true
		}
	}
	return false
}

func (tier *focusTier) covers(cov cover.Cover) bool {
	for pc := range cov {
		if _, ok := tier.coverPCs[pc]; ok {
			return true
		}
	}
	return false
}

func (fuzzer *Fuzzer) catchAllTier() *focusTier {
	return fuzzer.tiers[len(fuzzer.tiers)-1]
}

// triageQueueForCalls returns the triage queue of the highest priority tier
// whose focus area may be reached by the new signal.
func (fuzzer *Fuzzer) triageQueueForCalls(triage map[int]*triageCall) *queue.DynamicOrderer {
	for _, tier := range fuzzer.tiers[:len(fuzzer.tiers)-1] {
		for _, call := range triage {
			if tier.mayCover(call.newSignal) {
				return tier.triageQueue
			}
		}
	}
	return fuzzer.catchAllTier().triageQueue
}

// tierForCall returns the highest priority tier whose focus area is covered by the call.
func (fuzzer *Fuzzer) tierForCall(info *triageCall) *focusTier {
	for _, tier := range fuzzer.tiers[:len(fuzzer.tiers)-1] {
		if tier.covers(info.cover) {
			return tier
		}
	}
	return fuzzer.catchAllTier()
}
