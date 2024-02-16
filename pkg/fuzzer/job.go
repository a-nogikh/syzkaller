// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"fmt"
	"math/rand"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// TODO: do we need per-job Logf?
// TODO: split into separate files?

const (
	smashJobPrio priority = iota + 1
	genJobPrio
	triageJobPrio
	candidateJobPrio
	candidateTriageJobPrio
)

type job interface {
	priority() priority
	run(fuzzer *Fuzzer)
}

type ProgTypes int

const (
	ProgCandidate ProgTypes = 1 << iota
	ProgMinimized
	ProgSmashed
	ProgNormal ProgTypes = 0
)

type genJob struct{}

func (job *genJob) priority() priority {
	return genJobPrio
}

func (job *genJob) run(fuzzer *Fuzzer) {
	p := fuzzer.target.Generate(fuzzer.rand(),
		prog.RecommendedCalls,
		fuzzer.ChoiceTable())
	fuzzer.execWait(job, &Request{
		Prog:       p,
		NeedSignal: true,
		stat:       statGenerate,
	})
}

type candidateJob struct {
	p     *prog.Prog
	flags ProgTypes
}

func newCandidateJob(input Candidate) *candidateJob {
	flags := ProgCandidate
	if input.Minimized {
		flags |= ProgMinimized
	}
	if input.Smashed {
		flags |= ProgSmashed
	}
	return &candidateJob{
		p:     input.Prog,
		flags: flags,
	}
}

func (job *candidateJob) priority() priority {
	return candidateJobPrio
}

func (job *candidateJob) run(fuzzer *Fuzzer) {
	fuzzer.execWait(job, &Request{
		Prog:       job.p,
		NeedSignal: true,
		stat:       statCandidate,
		flags:      job.flags,
	})
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p     *prog.Prog
	call  int
	info  ipc.CallInfo
	flags ProgTypes
}

func (job *triageJob) priority() priority {
	if job.flags&ProgCandidate > 0 {
		return candidateTriageJobPrio
	}
	return triageJobPrio
}

func (job *triageJob) run(fuzzer *Fuzzer) {
	prio := signalPrio(job.p, &job.info, job.call)
	inputSignal := signal.FromRaw(job.info.Signal, prio)
	newSignal := fuzzer.Corpus.signalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if job.call != -1 {
		callName = job.p.Calls[job.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", job.call, callName)
	}
	fuzzer.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	// Compute input coverage and non-flaky signal for minimization.
	stableSignal, inputCover, rawCover, stop := job.deflake(fuzzer, newSignal)
	if stop || stableSignal.Empty() {
		return
	}
	if job.flags&ProgMinimized == 0 {
		stop = job.minimize(fuzzer, stableSignal)
		if stop {
			return
		}
	}
	data := job.p.Serialize()
	fuzzer.Logf(2, "added new input for %q to the corpus:\n%s",
		logCallName, string(data))
	if job.flags&ProgSmashed == 0 {
		fuzzer.queueJob(&smashJob{
			p:    job.p.Clone(),
			call: job.call,
		})
	}
	fuzzer.Corpus.Save(job.p, inputSignal, hash.Hash(data))

	select {
	case <-fuzzer.ctx.Done():
	case fuzzer.NewInputs <- rpctype.Input{
		Call:     callName,
		CallID:   job.call,
		Prog:     data,
		Signal:   stableSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		RawCover: rawCover,
	}:
	}
}

func (job *triageJob) deflake(fuzzer *Fuzzer, newSignal signal.Signal) (
	stableSignal signal.Signal, inputCover cover.Cover, rawCover []uint32,
	stop bool) {
	const signalRuns = 3
	// TODO: run all signalRuns in parallel?
	var notExecuted int
	for i := 0; i < signalRuns; i++ {
		result := fuzzer.execWait(job, &Request{
			Prog:         job.p,
			NeedSignal:   true,
			NeedCover:    true,
			NeedRawCover: fuzzer.Config.FetchRawCover,
			stat:         statTriage,
		})
		if result.Stop {
			stop = true
			return
		}
		info := result.Info
		if !reexecutionSuccess(info, &job.info, job.call) {
			// The call was not executed or failed.
			notExecuted++
			if notExecuted >= signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(job.p, info, job.call)
		if len(rawCover) == 0 && fuzzer.Config.FetchRawCover {
			rawCover = append([]uint32{}, thisCover...)
		}
		if stableSignal.Empty() {
			stableSignal = newSignal.Intersection(thisSignal)
		} else {
			stableSignal = stableSignal.Intersection(thisSignal)
		}
		if stableSignal.Empty() {
			return
		}
		inputCover.Merge(thisCover)
	}
	return
}

func (job *triageJob) minimize(fuzzer *Fuzzer, newSignal signal.Signal) (stop bool) {
	const minimizeAttempts = 3
	job.p, job.call = prog.Minimize(job.p, job.call, false,
		func(p1 *prog.Prog, call1 int) bool {
			if stop {
				return false
			}
			for i := 0; i < minimizeAttempts; i++ {
				result := fuzzer.execWait(job, &Request{
					Prog:       p1,
					NeedSignal: true,
					stat:       statMinimize,
				})
				if result.Stop {
					stop = true
					return false
				}
				info := result.Info
				if !reexecutionSuccess(info, &job.info, call1) {
					// The call was not executed or failed.
					continue
				}
				thisSignal, _ := getSignalAndCover(p1, info, call1)
				if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
					return true
				}
			}
			return false
		})
	return stop
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

type smashJob struct {
	p     *prog.Prog
	call  int
	short bool
}

func (job *smashJob) priority() priority {
	return smashJobPrio
}

func (job *smashJob) run(fuzzer *Fuzzer) {
	fuzzer.Logf(2, "smashing the following program (call=%d, short=%v):\n%s",
		job.call, job.short, string(job.p.Serialize()))
	if !job.short {
		job.scheduleSubjobs(fuzzer)
	}
	iters := 100
	if job.short {
		iters = 10
	}
	rnd := fuzzer.rand()
	choiceTable := fuzzer.ChoiceTable()
	corpusProgs := fuzzer.Corpus.Programs()
	for i := 0; i < iters; i++ {
		p := job.p.Clone()
		p.Mutate(rnd, prog.RecommendedCalls,
			choiceTable,
			fuzzer.Config.NoMutateCalls,
			corpusProgs)
		// TODO: don't wait every exec to finish, but rather
		// limit the numer of simultaneously running ones.
		stat := statSmash
		if job.short {
			stat = statFuzz
		}
		result := fuzzer.execWait(job, &Request{
			Prog:       p,
			NeedSignal: true,
			stat:       stat,
		})
		if result.Stop {
			return
		}
	}
}

func (job *smashJob) scheduleSubjobs(fuzzer *Fuzzer) {
	if fuzzer.Config.FaultInjection && job.call >= 0 {
		fuzzer.queueJob(&faultInjectionJob{
			p:    job.p.Clone(),
			call: job.call,
		})
	}
	if fuzzer.Config.Comparisons && job.call >= 0 {
		fuzzer.queueJob(&hintsJob{
			p:    job.p.Clone(),
			call: job.call,
		})
	}
	if fuzzer.Config.Collide {
		fuzzer.queueJob(&collideJob{
			p: job.p.Clone(),
		})
	}
}

type faultInjectionJob struct {
	p    *prog.Prog
	call int
}

func (job *faultInjectionJob) priority() priority {
	return smashJobPrio
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.execWait(job, &Request{
			Prog: job.p,
			stat: statSmash,
		})
		if result.Stop {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	p    *prog.Prog
	call int
}

func (job *hintsJob) priority() priority {
	return smashJobPrio
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program to dump comparisons from KCOV.
	p := job.p
	result := fuzzer.execWait(job, &Request{
		Prog:      p,
		NeedHints: true,
		stat:      statSeed,
	})
	if result.Stop || result.Info == nil {
		return
	}
	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	var stop bool
	p.MutateWithHints(job.call, result.Info.Calls[job.call].Comps,
		func(p *prog.Prog) {
			if stop {
				return
			}
			result := fuzzer.execWait(job, &Request{
				Prog:       p,
				NeedSignal: true,
				stat:       statHint,
			})
			stop = stop || result.Stop
		})
}

type collideJob struct {
	p *prog.Prog
}

func (job *collideJob) priority() priority {
	return smashJobPrio
}

func (job *collideJob) run(fuzzer *Fuzzer) {
	const collideIterations = 15
	rnd := fuzzer.rand()
	for i := 0; i < collideIterations; i++ {
		result := fuzzer.execWait(job, &Request{
			Prog: randomCollide(job.p, rnd),
			stat: statCollide,
		})
		if result.Stop {
			return
		}
	}
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}
