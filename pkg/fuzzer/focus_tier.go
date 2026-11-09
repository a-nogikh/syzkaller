// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/stat"
)

// focusTier holds the triage and mutation job queues for a group of inputs.
// Currently, all inputs share the single catch-all tier.
type focusTier struct {
	weight      float64
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
)

func newFocusTier(fuzzer *Fuzzer, weight float64) *focusTier {
	return &focusTier{
		weight:      weight,
		hints:       newTierJobQueue(fuzzer.statJobsHints, maxRunningHintsJobs, maxPendingHintsJobs),
		triageQueue: queue.DynamicOrder(),
		smashQueue:  queue.Plain(),
		hintsQueue:  queue.Plain(),
	}
}

// tierJobQueue bounds the number of concurrently running jobs of one type in a tier,
// keeping excess jobs pending and starting them as running jobs finish.
type tierJobQueue struct {
	mu         sync.Mutex
	stat       *stat.Val
	running    int
	maxRunning int
	maxPending int
	pending    []job
}

func newTierJobQueue(stat *stat.Val, maxRunning, maxPending int) *tierJobQueue {
	return &tierJobQueue{
		stat:       stat,
		maxRunning: maxRunning,
		maxPending: maxPending,
	}
}

func (q *tierJobQueue) submit(fuzzer *Fuzzer, j job) {
	if fuzzer.ctx.Err() != nil {
		return
	}
	q.mu.Lock()
	if q.running >= q.maxRunning {
		if q.maxPending <= 0 || len(q.pending) < q.maxPending {
			q.pending = append(q.pending, j)
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
	if fuzzer.ctx.Err() != nil || len(q.pending) == 0 {
		if fuzzer.ctx.Err() != nil {
			q.pending = nil
		}
		q.running--
		q.mu.Unlock()
		return
	}
	next := q.pending[0]
	q.pending[0] = nil
	q.pending = q.pending[1:]
	q.mu.Unlock()
	q.start(fuzzer, next)
}

func (fuzzer *Fuzzer) catchAllTier() *focusTier {
	return fuzzer.tiers[len(fuzzer.tiers)-1]
}
