// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeflake(t *testing.T) {
	type Test struct {
		Info      triageCall
		Flags     ProgFlags
		PatchTest bool
		Exec      func(run uint64) (errno int32, signal []uint64, cover []uint64)
		Runs      uint64
	}
	tests := []Test{
		{
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 0),
				cover:     cover.FromRaw([]uint64{10, 20}),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				// For first, we return 1. For second, 2. And so on.
				return 0, []uint64{run}, []uint64{10, 20}
			},
			Runs: 3,
		},
		{
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0, 1, 2}, 0),
				// Cover is a union of all coverages.
				cover: cover.FromRaw([]uint64{10, 20, 30, 40, 100}),
				// 0, 2, 6 were in three resuls.
				stableSignal: signal.FromRaw([]uint64{0, 2, 6}, 0),
				// 0, 2 were also in newSignal.
				newStableSignal: signal.FromRaw([]uint64{0, 2, 6}, 0),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				switch run {
				case 1:
					return 0, []uint64{0, 2, 4, 6, 8}, []uint64{10, 20}
				case 2:
					// This one should be ignored -- it has a different errno.
					return 1, []uint64{0, 1, 2}, []uint64{100}
				case 3:
					return 0, []uint64{0, 2, 4, 6, 8}, []uint64{20, 30}
				case 4:
					return 0, []uint64{0, 2, 6}, []uint64{30, 40}
				}
				panic("unrechable")
			},
			Runs: 4,
		},
		{
			Info: triageCall{
				newSignal:       signal.FromRaw([]uint64{0, 1, 2, 3, 4}, 3),
				cover:           cover.FromRaw([]uint64{10, 20}),
				stableSignal:    signal.FromRaw([]uint64{2}, 0),
				newStableSignal: signal.FromRaw([]uint64{2}, 0),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				// For first, we return 0 and 1. For second, 1 and 2. And so on.
				return 0, []uint64{run, run + 1}, []uint64{10, 20}
			},
			Runs: 2,
		},
		{
			Flags: ProgFromCorpus,
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0}, 0),
				cover:     cover.FromRaw([]uint64{10, 20}),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				return 0, []uint64{run}, []uint64{10, 20}
			},
			// Since every run returns new signal, corpus deflake runs until deflakeTotalCorpusRuns (20).
			// Including the initial candidate run before deflake, that leaves 20 - 1 = 19 deflake runs.
			Runs: 19,
		},
		{
			Flags:     ProgFromCorpus,
			PatchTest: true,
			Info: triageCall{
				newSignal: signal.FromRaw([]uint64{0}, 0),
				cover:     cover.FromRaw([]uint64{10, 20}),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				return 0, []uint64{run}, []uint64{10, 20}
			},
			// In PatchTest mode, deflake stops at deflakeMaxRuns (5), which is 5 - 1 = 4 deflake runs.
			Runs: 4,
		},
		{
			Flags:     ProgFromCorpus,
			PatchTest: true,
			Info: triageCall{
				newSignal:       signal.FromRaw([]uint64{0}, 0),
				cover:           cover.FromRaw([]uint64{10, 20}),
				stableSignal:    signal.FromRaw([]uint64{0}, 0),
				newStableSignal: signal.FromRaw([]uint64{0}, 0),
			},
			Exec: func(run uint64) (int32, []uint64, []uint64) {
				return 0, []uint64{0}, []uint64{10, 20}
			},
			// In PatchTest mode, corpus deflake stops as soon as deflakeNeedCorpusRuns (2) is reached.
			Runs: 2,
		},
	}

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	assert.NoError(t, err)
	const anyTestProg = `syz_compare(&AUTO="00000000", 0x4, &AUTO=@conditional={0x0, @void, @void, @void}, AUTO)`
	prog, err := target.Deserialize([]byte(anyTestProg), prog.NonStrict)
	assert.NoError(t, err)

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			info := test.Info
			info.signals[0] = test.Info.newSignal.Copy()
			info.cover = nil
			info.stableSignal = nil
			info.newStableSignal = nil
			testJob := &triageJob{
				p:     prog,
				flags: test.Flags,
				calls: map[int]*triageCall{0: &info},
				fuzzer: &Fuzzer{
					Cover:  newCover(),
					Config: &Config{PatchTest: test.PatchTest},
				},
				info: &JobInfo{},
			}

			var run uint64
			stop := testJob.deflake(func(_ *queue.Request, _ ProgFlags) *queue.Result {
				run++
				errno, signal, cover := test.Exec(run)
				return &queue.Result{
					Info: &flatrpc.ProgInfo{
						Calls: []*flatrpc.CallInfo{{
							Error:  errno,
							Signal: signal,
							Cover:  cover,
						}},
					},
				}
			})

			assert.False(t, stop)
			assert.Equal(t, run, test.Runs)
			assert.ElementsMatch(t, info.cover.Serialize(), test.Info.cover.Serialize())
			assert.ElementsMatch(t, info.stableSignal.ToRaw(), test.Info.stableSignal.ToRaw())
			assert.ElementsMatch(t, info.newStableSignal.ToRaw(), test.Info.newStableSignal.ToRaw())
		})
	}
}

// syncExecutor is a queue.Executor for job unit tests that executes
// requests synchronously within Submit via the given function.
type syncExecutor func(req *queue.Request) *queue.Result

func (exec syncExecutor) Submit(req *queue.Request) {
	req.Done(exec(req))
}

func TestHintsJobSkipsRunsWithoutComps(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	p, err := target.Deserialize([]byte("test$int(0x1, 0x2, 0x3, 0x4, 0x5)\n"), prog.Strict)
	require.NoError(t, err)

	ctx := t.Context()
	fuzzer := NewFuzzer(ctx, &Config{
		Corpus: corpus.NewCorpus(ctx),
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["test$int"]: true,
		},
	}, rand.New(rand.NewSource(0)), target)

	seedRuns, hintRuns := 0, 0
	exec := syncExecutor(func(req *queue.Request) *queue.Result {
		if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps == 0 {
			hintRuns++
			return &queue.Result{Status: queue.Success}
		}
		seedRuns++
		call := &flatrpc.CallInfo{}
		// The first run returns no comparisons, which must not discard the following ones.
		if seedRuns > 1 {
			call.Comps = []*flatrpc.Comparison{{Pc: 1, Op1: 0x5, Op2: 0x12345678}}
		}
		return &queue.Result{
			Status: queue.Success,
			Info:   &flatrpc.ProgInfo{Calls: []*flatrpc.CallInfo{call}},
		}
	})
	job := &hintsJob{exec: exec, p: p, call: 0, info: &JobInfo{}}
	job.run(fuzzer)
	assert.Equal(t, 3, seedRuns)
	assert.Positive(t, hintRuns)
}

type fnJob func(*Fuzzer)

func (fn fnJob) run(fuzzer *Fuzzer) {
	fn(fuzzer)
}

func TestTierJobQueue(t *testing.T) {
	fuzzer, _ := newTriageTestFuzzer(t, &Config{
		Corpus: corpus.NewCorpus(t.Context()),
	})
	q := newTierJobQueue(fuzzer.statJobsHints, 2, 10, 3)

	var active, maxActive atomic.Int64
	var order []string
	var orderMu sync.Mutex
	record := func(name string) {
		orderMu.Lock()
		order = append(order, name)
		orderMu.Unlock()
	}
	step := make(chan struct{})
	makeJob := func(name string) job {
		return fnJob(func(*Fuzzer) {
			cur := active.Add(1)
			for {
				prev := maxActive.Load()
				if cur <= prev || maxActive.CompareAndSwap(prev, cur) {
					break
				}
			}
			record(name)
			<-step
			active.Add(-1)
		})
	}

	// Start 2 running jobs, queue 1 candidate (reaching maxCandidates=3), drop a 4th candidate,
	// and queue 1 new-input job (which must still be accepted and run ahead of cand3).
	q.submit(fuzzer, makeJob("cand1"), ProgSmashed)
	q.submit(fuzzer, makeJob("cand2"), ProgSmashed)
	q.submit(fuzzer, makeJob("cand3"), ProgSmashed)
	q.submit(fuzzer, makeJob("cand4_dropped"), ProgSmashed)
	q.submit(fuzzer, makeJob("new1"), 0)

	require.Eventually(t, func() bool {
		return active.Load() == 2
	}, time.Second, time.Millisecond)
	assert.Equal(t, 2, fuzzer.statJobsHints.Val())

	// Release one slot: new1 must start before cand3.
	step <- struct{}{}
	require.Eventually(t, func() bool {
		orderMu.Lock()
		defer orderMu.Unlock()
		return len(order) == 3
	}, time.Second, time.Millisecond)
	orderMu.Lock()
	assert.Equal(t, "new1", order[2])
	orderMu.Unlock()

	close(step)
	require.Eventually(t, func() bool {
		return fuzzer.statJobsHints.Val() == 0
	}, time.Second, time.Millisecond)
	assert.Equal(t, int64(2), maxActive.Load())
	assert.Equal(t, []string{"new1", "cand3"}, order[2:])
}

// newTriageTestFuzzer creates a fuzzer for triageJob.handleCalls tests and returns it
// with a 2-call test program. Nothing executes the requests of the started jobs, so they
// block until the test context is cancelled, and the job stats count the started jobs.
// cfg.Corpus must be created with t.Context().
func newTriageTestFuzzer(t *testing.T, cfg *Config) (*Fuzzer, *prog.Prog) {
	t.Cleanup(checkGoroutineLeaks)
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	p, err := target.Deserialize([]byte(`test$res0()
test$int(0x1, 0x2, 0x3, 0x4, 0x5)
`), prog.Strict)
	require.NoError(t, err)
	cfg.EnabledCalls = map[*prog.Syscall]bool{
		target.SyscallMap["test$res0"]: true,
		target.SyscallMap["test$int"]:  true,
	}
	return NewFuzzer(t.Context(), cfg, rand.New(rand.NewSource(0)), target), p
}

// triageCallWithPC returns a triageCall whose new signal and cover consist of the single pc.
func triageCallWithPC(pc uint64) *triageCall {
	return &triageCall{
		stableSignal:    signal.FromRaw([]uint64{pc}, 0),
		newStableSignal: signal.FromRaw([]uint64{pc}, 0),
		cover:           cover.FromRaw([]uint64{pc}),
	}
}

func TestHandleCallSmashDedup(t *testing.T) {
	fuzzer, p := newTriageTestFuzzer(t, &Config{
		Corpus:         corpus.NewCorpus(t.Context()),
		Comparisons:    true,
		FaultInjection: true,
	})
	job := &triageJob{
		p:      p,
		flags:  ProgMinimized,
		fuzzer: fuzzer,
		calls: map[int]*triageCall{
			0: triageCallWithPC(1),
			1: triageCallWithPC(2),
		},
		info: &JobInfo{},
	}
	job.handleCalls()
	// Both calls save the same program to the corpus: only one smash job should be
	// started, while per-call hints and fault injection jobs run for both calls.
	assert.Equal(t, 1, fuzzer.statJobsSmash.Val())
	assert.Equal(t, 2, fuzzer.statJobsHints.Val())
	assert.Equal(t, 2, fuzzer.statJobsFaultInjection.Val())
}

func TestFocusedCandidateSmashAndHints(t *testing.T) {
	const symbolsPC, filesPC, otherPC = 0x100, 0x200, 0x1
	fuzzer, p := newTriageTestFuzzer(t, &Config{
		Corpus: corpus.NewFocusedCorpus(t.Context(), nil, []corpus.FocusArea{
			{Name: "symbols", CoverPCs: map[uint64]struct{}{symbolsPC: {}}, Weight: 6.0},
			{Name: "files", CoverPCs: map[uint64]struct{}{filesPC: {}}, Weight: 3.0},
		}),
		Comparisons: true,
		PatchTest:   true,
	})
	symbols, files := fuzzer.tiers[0], fuzzer.tiers[1]

	// An unfocused candidate must not start smash or hints jobs.
	unfocusedJob := &triageJob{
		p:      p,
		flags:  ProgFromCorpus | ProgMinimized | ProgSmashed,
		fuzzer: fuzzer,
		calls:  map[int]*triageCall{0: triageCallWithPC(otherPC)},
		info:   &JobInfo{},
	}
	unfocusedJob.handleCalls()
	assert.Equal(t, 0, fuzzer.statJobsSmash.Val(), "unfocused call must not start smash job")
	assert.Equal(t, 0, fuzzer.statJobsHints.Val(), "unfocused call must not start hints job")

	// Saturate the candidate hints cap of the lower priority "files" tier. When call 0 reaches
	// "files" and call 1 reaches "symbols", the single smash job must be queued in the
	// higher priority "symbols" tier, and "symbols" still starts its hints job.
	files.hints.maxCandidates = 0
	focusedJob := &triageJob{
		p:      p,
		flags:  ProgFromCorpus | ProgMinimized | ProgSmashed,
		fuzzer: fuzzer,
		calls: map[int]*triageCall{
			0: triageCallWithPC(filesPC),
			1: triageCallWithPC(symbolsPC),
		},
		info: &JobInfo{},
	}
	focusedJob.handleCalls()
	assert.Equal(t, 1, fuzzer.statJobsSmash.Val(), "focused candidate must be smashed once despite ProgSmashed")
	assert.Equal(t, 1, fuzzer.statJobsHints.Val())
	require.Eventually(t, func() bool {
		return symbols.smashQueue.Next() != nil && symbols.hintsQueue.Next() != nil
	}, time.Second, time.Millisecond)
	assert.Nil(t, files.smashQueue.Next())

	// A candidate in the saturated "files" tier is smashed, but does not start hints jobs.
	p2 := p.Clone()
	p2.Calls = p2.Calls[:1]
	job2 := &triageJob{
		p:      p2,
		flags:  ProgFromCorpus | ProgMinimized | ProgSmashed,
		fuzzer: fuzzer,
		calls:  map[int]*triageCall{0: triageCallWithPC(filesPC)},
		info:   &JobInfo{},
	}
	job2.handleCalls()
	assert.Equal(t, 2, fuzzer.statJobsSmash.Val())
	assert.Equal(t, 1, fuzzer.statJobsHints.Val())
}
