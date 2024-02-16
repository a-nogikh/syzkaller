// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Config    *Config
	Corpus    *Corpus
	NewInputs chan rpctype.Input

	ctx    context.Context
	mu     sync.Mutex
	stats  map[string]uint64
	rnd    *rand.Rand
	target *prog.Target

	ct      *prog.ChoiceTable
	ctMu    sync.Mutex // TODO: use RWLock.
	ctProgs int

	nextExec *priorityQueue[*Request]
	nextJob  *priorityQueue[job]
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	f := &Fuzzer{
		Config:    cfg,
		Corpus:    newCorpus(),
		NewInputs: make(chan rpctype.Input),

		ctx:    ctx,
		stats:  map[string]uint64{},
		rnd:    rnd,
		target: target,

		nextExec: makePriorityQueue[*Request](),
		nextJob:  makePriorityQueue[job](),
	}
	go func() {
		<-ctx.Done()
		close(f.NewInputs)
	}()
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
	Candidates     chan Candidate
}

type Request struct {
	Prog         *prog.Prog
	NeedCover    bool
	NeedRawCover bool
	NeedSignal   bool
	NeedHints    bool // TODO: can both it and something above be true?
	// Fields that are only relevant within pkg/fuzzer.
	flags        ProgTypes
	stat         string
	result       *Result
	resultCond   *sync.Cond
	timeout      chan struct{}
	timeoutTimer *time.Timer
}

func (req *Request) sent() {
	// Let's catch lost requests.
	req.resultCond.L.Lock()
	defer req.resultCond.L.Unlock()
	req.timeoutTimer = time.AfterFunc(15*time.Minute, func() {
		select {
		case req.timeout <- struct{}{}:
		default:
		}
	})
}

func (req *Request) wait() <-chan *Result {
	ch := make(chan *Result)
	go func() {
		req.resultCond.L.Lock()
		for req.result == nil {
			req.resultCond.Wait()
		}
		req.resultCond.L.Unlock()
		ch <- req.result
	}()
	return ch
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
	req.resultCond.L.Lock()
	req.result = res
	req.resultCond.Broadcast()
	req.resultCond.L.Unlock()
	// Update stats.
	fuzzer.mu.Lock()
	fuzzer.stats[req.stat]++
	fuzzer.mu.Unlock()
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *ipc.CallInfo, call int,
	flags ProgTypes) {
	prio := signalPrio(p, info, call)
	if !fuzzer.Corpus.AddRawMaxSignal(info.Signal, prio) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s\n",
		call, string(p.Serialize()))
	fuzzer.queueJob(&triageJob{
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
	nextExec := fuzzer.nextExec.pop(zeroPrio)
	minPrio := zeroPrio
	if nextExec != nil {
		minPrio = nextExec.prio
	}
	betterJob := fuzzer.genBetterJob(minPrio)
	if betterJob != nil {
		fuzzer.Logf(1, "started %T", betterJob)
		go betterJob.run(fuzzer)
	}
	if nextExec != nil {
		return nextExec.value
	}
	// We may end up in a deadlock if the new job is waiting
	// for something else. But at least so far no job does
	// something like that.
	req := fuzzer.nextExec.popWait().value
	req.sent()
	return req
}

func (fuzzer *Fuzzer) genBetterJob(minPrio priority) job {
	// Candidate job is somewhat special -- there's an external
	// source of them and yet we don't want to keep the queue too big.
	// At least until pkg/fuzzer resides on syz-fuzzer.
	if item := fuzzer.nextJob.pop(
		minPrio.maxWith(candidateJobPrio)); item != nil {
		return item.value
	}
	if minPrio < candidateJobPrio {
		select {
		case candidate := <-fuzzer.Config.Candidates:
			return newCandidateJob(candidate)
		default:
		}
	}
	if item := fuzzer.nextJob.pop(minPrio); item != nil {
		return item.value
	}
	if minPrio != zeroPrio {
		// Don't create jobs to fill out the pipeline.
		return nil
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
		if p := fuzzer.Corpus.chooseProgram(rnd); p != nil {
			return &smashJob{
				p:     p,
				short: true,
			}
		}
	}
	return &genJob{}
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// TODO: make the step be dependent on the corpus size.
	const regenerateEveryProgs = 100

	progsCount := len(fuzzer.Corpus.Programs())
	if fuzzer.ct != nil &&
		progsCount < fuzzer.ctProgs+regenerateEveryProgs {
		return fuzzer.ct
	}
	fuzzer.ct = fuzzer.target.BuildChoiceTable(fuzzer.Corpus.Programs(),
		fuzzer.Config.EnabledCalls)
	fuzzer.ctProgs = progsCount
	return fuzzer.ct
}

// Helper methods for jobs.

func (fuzzer *Fuzzer) queueJob(newJob job) {
	fuzzer.Logf(1, "queued %T", newJob)
	fuzzer.nextJob.push(&priorityQueueItem[job]{
		value: newJob, prio: newJob.priority(),
	})
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	seed := fuzzer.rnd.Int63()
	fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(seed))
}

// Later we might split this into exec() and wait() to let jobs
// post async exec requests.
func (fuzzer *Fuzzer) execWait(job job, req *Request) *Result {
	if req.stat == "" {
		panic("Request.Stat field must be set")
	}
	req.resultCond = sync.NewCond(&sync.Mutex{})
	req.timeout = make(chan struct{})
	fuzzer.nextExec.push(&priorityQueueItem[*Request]{
		value: req, prio: job.priority(),
	})

	// Don't keep too many running timers.
	defer func() {
		req.resultCond.L.Lock()
		defer req.resultCond.L.Unlock()
		if req.timeoutTimer != nil {
			req.timeoutTimer.Stop()
		}
	}()

	select {
	case <-fuzzer.ctx.Done():
		return &Result{Stop: true}
	case res := <-req.wait():
		return res
	case <-req.timeout:
		panic(fmt.Sprintf(
			"timed out waiting for an execution result:\n%s",
			string(req.Prog.Serialize()),
		))
	}
}
