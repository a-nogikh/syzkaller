// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

// Retryer gives a second chance to the inputs from crashed VMs.
type Retryer struct {
	fuzzer             FuzzerOps
	delayed            *priorityQueue[*Request]
	statRiskyRetries   *stats.Val
	statRiskyDiscarded *stats.Val
	statRiskyFallback  *stats.Val
	statRiskyRun       *stats.Val

	mu  sync.Mutex
	rnd *rand.Rand
	crashEstimator
}

func NewRetryer(base FuzzerOps) *Retryer {
	ret := &Retryer{
		fuzzer:  base,
		delayed: makePriorityQueue[*Request](),
		statRiskyRetries: stats.Create("risky prog reruns", "Reexecuted risky progs",
			stats.StackedGraph("prog reruns")),
		statRiskyDiscarded: stats.Create("risky progs discarded", "Inputs deemeed too risky for execution",
			stats.Rate{}, stats.StackedGraph("risky progs")),
		statRiskyFallback: stats.Create("risky progs fallback", "Unable to get a non-risky prog",
			stats.Rate{}, stats.StackedGraph("risky progs")),
		statRiskyRun: stats.Create("risky progs run", "New risky progs",
			stats.Rate{}, stats.StackedGraph("risky progs")),
		rnd: rand.New(rand.NewSource(0)),
	}
	stats.Create("risky prog queue", "Queued risky inputs",
		func() int {
			return ret.delayed.Len()
		}, stats.StackedGraph("prog reruns"))

	go func() {
		for range time.NewTicker(time.Minute).C {
			ret.printCallEstimates()
		}
	}()

	return ret
}

func (retryer *Retryer) nextRand() float64 {
	retryer.mu.Lock()
	defer retryer.mu.Unlock()
	return retryer.rnd.Float64()
}

func (retryer *Retryer) NextInput(opts RequestOpts) *Request {
	if opts.MayRisk {
		item := retryer.delayed.tryPop()
		if item != nil {
			item.value.retried = true
			retryer.statRiskyRetries.Add(1)
			return item.value
		}
	}
	for attempts := 0; ; attempts++ {
		input := retryer.fuzzer.NextInput(opts)
		crashProb := retryer.CrashProbability(input.Prog)
		crashBudget := 0.001
		if opts.MayRisk {
			crashBudget = 0.01
		}
		if crashProb < crashBudget {
			return input
		}
		if retryer.nextRand() < crashBudget/crashProb {
			retryer.statRiskyRun.Add(1)
			return input
		}
		if attempts == 2 {
			// We don't want to query new inputs infinitely.
			// If it's the third attempt in a row, then so be it.
			retryer.statRiskyFallback.Add(1)
			return input
		}
		retryer.statRiskyDiscarded.Add(1)
		retryer.fuzzer.Done(input, &Result{Crashed: true})
	}
}

// No sense to let the queue grow infinitely.
// If we're going above the limit, something is seriously wrong with the DUT.
const retryerQueueLimit = 10000

func (retryer *Retryer) Done(req *Request, res *Result) {
	if res.Crashed {
		retryer.Avoid(req.Prog)
		retryer.toBacklog(req)
	} else {
		retryer.OK(req.Prog)
		retryer.fuzzer.Done(req, res)
	}
}

func (retryer *Retryer) toBacklog(req *Request) {
	if req.noRetry || req.retried || retryer.delayed.Len() > retryerQueueLimit {
		retryer.fuzzer.Done(req, &Result{Crashed: true})
		return
	}
	retryer.delayed.push(&priorityQueueItem[*Request]{
		value: req,
	})
}

type crashEstimator struct {
	mu        sync.RWMutex
	callProbs map[*prog.Syscall]*stats.AverageValue[float64]
}

func (ce *crashEstimator) OK(p *prog.Prog) {
	// We are okay to miss some good executions.
	ce.save(p, 0, false)
}

func (ce *crashEstimator) Avoid(p *prog.Prog) {
	// But all bad executions must be recorded.
	ce.save(p, 1.0, false)
}

func (ce *crashEstimator) CrashProbability(p *prog.Prog) float64 {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	prob := 0.0
	for _, call := range p.Calls {
		estimate := ce.callProbs[call.Meta]
		if estimate == nil || estimate.Count() < 3 {
			continue
		}
		value := estimate.Value()
		if value > prob {
			prob = value
		}
	}
	return prob
}

func (ce *crashEstimator) save(p *prog.Prog, prob float64, tentative bool) {
	if !ce.mu.TryLock() {
		if tentative {
			return
		}
		ce.mu.Lock()
	}
	defer ce.mu.Unlock()

	if ce.callProbs == nil {
		ce.callProbs = map[*prog.Syscall]*stats.AverageValue[float64]{}
	}
	for _, call := range p.Calls {
		estimate := ce.callProbs[call.Meta]
		if estimate == nil {
			estimate = &stats.AverageValue[float64]{}
			ce.callProbs[call.Meta] = estimate
		}
		estimate.Save(prob)
	}
}

// Needed for debugging.
func (ce *crashEstimator) printCallEstimates() {
	type item struct {
		name string
		val  float64
	}
	var items []item
	ce.mu.RLock()
	for key, v := range ce.callProbs {
		items = append(items, item{key.Name, v.Value()})
	}
	ce.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].val > items[j].val })
	if len(items) > 25 {
		items = items[:25]
	}
	for _, info := range items {
		log.Logf(0, "call %s: prob %.3f", info.name, info.val)
	}
}
