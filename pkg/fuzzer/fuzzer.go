// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Config *Config
	Corpus *Corpus

	ctx    context.Context
	mu     sync.Mutex
	stats  map[string]uint64
	rnd    *rand.Rand
	target *prog.Target

	choiceTable *choiceTableProxy

	nextExec     *priorityQueue[*Request]
	runningExecs map[*Request]time.Time
	jobIDs       map[job]int64
	nextJobID    int64

	queuedCandidates atomic.Uint64
	// If the source of candidates runs out of them, we risk
	// generating too many needCandidate requests (one for
	// each Config.MinCandidates). We prevent this with candidatesRequested.
	candidatesRequested atomic.Bool
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	f := &Fuzzer{
		Config: cfg,
		Corpus: newCorpus(),

		ctx:          ctx,
		stats:        map[string]uint64{},
		rnd:          rnd,
		target:       target,
		choiceTable:  &choiceTableProxy{},
		nextExec:     makePriorityQueue[*Request](),
		runningExecs: map[*Request]time.Time{},
		jobIDs:       map[job]int64{},
	}
	go f.leakDetector()
	f.updateChoiceTable()
	return f
}

type Config struct {
	Logf           func(level int, msg string, args ...interface{})
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	LeakChecking   bool
	FetchRawCover  bool
	// If the number of queued candidates is less than MinCandidates,
	// NeedCandidates is triggered.
	MinCandidates  uint
	NeedCandidates chan struct{}
	NewInputs      chan rpctype.Input
}

type Request struct {
	Prog         *prog.Prog
	NeedCover    bool
	NeedRawCover bool
	NeedSignal   bool
	NeedHints    bool
	// Fields that are only relevant within pkg/fuzzer.
	flags   ProgTypes
	stat    string
	result  *Result
	resultC chan *Result
}

type Result struct {
	Info *ipc.ProgInfo
	Stop bool
}

func (fuzzer *Fuzzer) Done(req *Request, res *Result) {
	// Triage individual calls.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	if req.NeedSignal && res.Info != nil {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, &info, call, req.flags)
		}
		fuzzer.triageProgCall(req.Prog, &res.Info.Extra, -1, req.flags)
	}
	// Unblock threads that wait for the result.
	req.result = res
	if req.resultC != nil {
		req.resultC <- res
	}
	// Update stats.
	fuzzer.mu.Lock()
	fuzzer.stats[req.stat]++
	delete(fuzzer.runningExecs, req)
	fuzzer.mu.Unlock()
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *ipc.CallInfo, call int,
	flags ProgTypes) {
	prio := signalPrio(p, info, call)
	if !fuzzer.Corpus.AddRawMaxSignal(info.Signal, prio) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s\n", call, p)
	fuzzer.startJob(&triageJob{
		p:     p.Clone(),
		call:  call,
		info:  *info,
		flags: flags,
	})
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

type Candidate struct {
	Prog      *prog.Prog
	Hash      hash.Sig
	Smashed   bool
	Minimized bool
}

func (fuzzer *Fuzzer) NextInput() *Request {
	req := fuzzer.nextInput()
	fuzzer.mu.Lock()
	fuzzer.runningExecs[req] = time.Now()
	fuzzer.mu.Unlock()
	if req.stat == statCandidate {
		if fuzzer.queuedCandidates.Load() <= 0 {
			panic("queuedCandidates is out of sync")
		}
		fuzzer.queuedCandidates.Add(^uint64(0))
	}
	if fuzzer.Config.NeedCandidates != nil &&
		fuzzer.NeedCandidates() &&
		!fuzzer.candidatesRequested.CompareAndSwap(false, true) {
		select {
		case fuzzer.Config.NeedCandidates <- struct{}{}:
		default:
		}
	}
	return req
}

func (fuzzer *Fuzzer) nextInput() *Request {
	nextExec := fuzzer.nextExec.tryPop()
	if nextExec != nil {
		return nextExec.value
	}
	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	rnd := fuzzer.rand()
	if rnd.Float64() < mutateRate {
		req := mutateProgRequest(fuzzer, rnd)
		if req != nil {
			return req
		}
	}
	return genProgRequest(fuzzer, rnd)
}

func (fuzzer *Fuzzer) startJob(newJob job) {
	fuzzer.Logf(1, "started %T", newJob)
	go func() {
		fuzzer.mu.Lock()
		fuzzer.jobIDs[newJob] = fuzzer.nextJobID
		fuzzer.nextJobID++
		fuzzer.mu.Unlock()
		newJob.run(fuzzer)
		fuzzer.mu.Lock()
		delete(fuzzer.jobIDs, newJob)
		fuzzer.mu.Unlock()
	}()
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

func (fuzzer *Fuzzer) NeedCandidates() bool {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return fuzzer.queuedCandidates.Load() < uint64(fuzzer.Config.MinCandidates)
}

func (fuzzer *Fuzzer) AddCandidate(candidate Candidate) {
	fuzzer.queuedCandidates.Add(1)
	fuzzer.pushExec(candidateRequest(candidate), priority{candidatePrio})
	fuzzer.candidatesRequested.Store(false)
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	seed := fuzzer.rnd.Int63()
	fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(seed))
}

func (fuzzer *Fuzzer) execPrio(job job) priority {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return append(
		append(priority{}, job.priority()...),
		-fuzzer.jobIDs[job],
	)
}

func (fuzzer *Fuzzer) pushExec(req *Request, prio priority) {
	if req.stat == "" {
		panic("Request.Stat field must be set")
	}
	if req.NeedHints && (req.NeedCover || req.NeedSignal) {
		panic("Request.NeedHints is mutually exclusive with other fields")
	}
	fuzzer.nextExec.push(&priorityQueueItem[*Request]{
		value: req, prio: prio,
	})
}

func (fuzzer *Fuzzer) exec(job job, req *Request) *Result {
	req.resultC = make(chan *Result, 1)
	fuzzer.pushExec(req, fuzzer.execPrio(job))
	select {
	case <-fuzzer.ctx.Done():
		return &Result{Stop: true}
	case res := <-req.resultC:
		close(req.resultC)
		return res
	}
}

func (fuzzer *Fuzzer) leakDetector() {
	const timeout = 10 * time.Minute
	ticket := time.NewTicker(timeout)
	defer ticket.Stop()
	for {
		select {
		case <-ticket.C:
			fuzzer.mu.Lock()
			for req, startedTime := range fuzzer.runningExecs {
				if time.Since(startedTime) > timeout {
					panic(fmt.Sprintf("execution timed out: %v", req))
				}
			}
			fuzzer.mu.Unlock()
		case <-fuzzer.ctx.Done():
			return
		}
	}
}

func (fuzzer *Fuzzer) ChoiceTable() prog.ChoiceTable {
	return fuzzer.choiceTable
}

func (fuzzer *Fuzzer) updateChoiceTable() {
	fuzzer.choiceTable.tryUpdate(fuzzer.target,
		fuzzer.Corpus,
		fuzzer.Config.EnabledCalls)
}
