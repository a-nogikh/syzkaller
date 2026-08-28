// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initTest(t *testing.T) (*rand.Rand, int) {
	iters := 1000
	if testing.Short() {
		iters = 100
	}
	return rand.New(testutil.RandSource(t)), iters
}

func TestBisect(t *testing.T) {
	ctx := &reproContext{
		stats: new(Stats),
		logf:  t.Logf,
	}

	rd, iters := initTest(t)
	for range iters {
		var progs []*prog.LogEntry
		numTotal := rd.Intn(300)
		numGuilty := 0
		for range numTotal {
			var prog prog.LogEntry
			if rd.Intn(30) == 0 {
				prog.Proc = 42
				numGuilty++
			}
			progs = append(progs, &prog)
		}
		if numGuilty == 0 {
			var prog prog.LogEntry
			prog.Proc = 42
			progs = append(progs, &prog)
			numGuilty++
		}
		progs, _ = ctx.bisectProgs(progs, func(p []*prog.LogEntry) (bool, error) {
			guilty := 0
			for _, prog := range p {
				if prog.Proc == 42 {
					guilty++
				}
			}
			return guilty == numGuilty, nil
		})
		if numGuilty > 6 && len(progs) == 0 {
			// Bisection has been aborted.
			continue
		}
		if len(progs) != numGuilty {
			t.Fatalf("bisect test failed: wrong number of guilty progs: got: %v, want: %v", len(progs), numGuilty)
		}
		for _, prog := range progs {
			if prog.Proc != 42 {
				t.Fatalf("bisect test failed: wrong program is guilty: progs: %v", progs)
			}
		}
	}
}

func TestSimplifies(t *testing.T) {
	opts := csource.Options{
		Threaded:     true,
		Repeat:       true,
		Procs:        10,
		Sandbox:      "namespace",
		NetInjection: true,
		NetDevices:   true,
		NetReset:     true,
		Cgroups:      true,
		UseTmpDir:    true,
		HandleSegv:   true,
	}
	var check func(opts csource.Options, i int)
	check = func(opts csource.Options, i int) {
		if err := opts.Check(targets.Linux); err != nil {
			t.Fatalf("opts are invalid: %v", err)
		}
		if i == len(cSimplifies) {
			return
		}
		check(opts, i+1)
		if cSimplifies[i](&opts) {
			check(opts, i+1)
		}
	}
	check(opts, 0)
}

type testExecInterface struct {
	// For now only do the simplest imitation.
	run func([]byte) (*instance.RunResult, error)
}

func (tei *testExecInterface) RunC(_ context.Context, p *prog.Prog, _ instance.RunOptions,
	_ instance.ExecutorLogger) (*instance.RunResult, error) {
	return tei.run(p.Serialize())
}

func (tei *testExecInterface) RunSyz(_ context.Context, syzProg []byte, _ instance.RunOptions,
	_ instance.ExecutorLogger) (*instance.RunResult, error) {
	return tei.run(syzProg)
}

func runTestRepro(t *testing.T, log string, exec execInterface) (*Result, *Stats, error) {
	mgrConfig := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: targets.AMD64,
			SysTarget:    targets.Get(targets.Linux, targets.AMD64),
		},
		Sandbox: "namespace",
	}
	var err error
	mgrConfig.Target, err = prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := report.NewReporter(mgrConfig)
	if err != nil {
		t.Fatal(err)
	}
	env := Environment{
		Config:   mgrConfig,
		Features: flatrpc.AllFeatures,
		Fast:     false,
		Reporter: reporter,
		logf:     t.Logf,
	}
	return runInner(context.Background(), []byte(log), env, exec)
}

const testReproLog = `
2015/12/21 12:18:05 executing program 1:
getpid()
pause()
2015/12/21 12:18:10 executing program 2:
getpid()
getuid()
2015/12/21 12:18:15 executing program 1:
alarm(0x5)
pause()
2015/12/21 12:18:20 executing program 3:
alarm(0xa)
getpid()
`

// Only crash if `pause()` is followed by `alarm(0xa)`.
var testCrashCondition = regexp.MustCompile(`(?s)pause\(\).*alarm\(0xa\)`)

var (
	expectedReproducer = "pause()\nalarm(0xa)\n"
)

func fakeCrashResult(title string) *instance.RunResult {
	ret := &instance.RunResult{}
	if title != "" {
		ret.Report = &report.Report{
			Title: title,
			Type:  crash.TitleToType(title),
		}
	}
	return ret
}

func testExecRunner(log []byte) (*instance.RunResult, error) {
	crash := testCrashCondition.Match(log)
	if crash {
		return fakeCrashResult("crashed"), nil
	}
	return fakeCrashResult(""), nil
}

// Just a pkg/repro smoke test: check that we can extract a two-call reproducer.
// No focus on error handling and minor corner cases.
func TestPlainRepro(t *testing.T) {
	result, _, err := runTestRepro(t, testReproLog, &testExecInterface{
		run: testExecRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, expectedReproducer, string(result.Prog.Serialize()))
}

// There happen to be transient errors like ssh/scp connection failures.
// Ensure that the code just retries.
func TestVMErrorResilience(t *testing.T) {
	fail := false
	result, _, err := runTestRepro(t, testReproLog, &testExecInterface{
		run: func(log []byte) (*instance.RunResult, error) {
			fail = !fail
			if fail {
				return nil, fmt.Errorf("some random error")
			}
			return testExecRunner(log)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, `pause()
alarm(0xa)
`, string(result.Prog.Serialize()))
}

func TestTooManyErrors(t *testing.T) {
	counter := 0
	_, _, err := runTestRepro(t, testReproLog, &testExecInterface{
		run: func(log []byte) (*instance.RunResult, error) {
			counter++
			if counter%4 != 0 {
				return nil, fmt.Errorf("some random error")
			}
			return testExecRunner(log)
		},
	})
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func TestProgConcatenation(t *testing.T) {
	// Since the crash condition is alarm() after pause(), the code
	// would have to work around the prog.MaxCall limitation.
	execLog := "2015/12/21 12:18:05 executing program 1:\n"
	for i := range prog.MaxCalls {
		if i == 10 {
			execLog += "pause()\n"
		} else {
			execLog += "getpid()\n"
		}
	}
	execLog += "2015/12/21 12:18:10 executing program 2:\n"
	for i := range prog.MaxCalls {
		if i == 10 {
			execLog += "alarm(0xa)\n"
		} else {
			execLog += "getpid()\n"
		}
	}
	result, _, err := runTestRepro(t, execLog, &testExecInterface{
		run: testExecRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, `pause()
alarm(0xa)
`, string(result.Prog.Serialize()))
}

func TestFlakyCrashes(t *testing.T) {
	t.Parallel()
	// A single flaky crash may divert the whole process.
	// Let's check if the Reliability score provides a reasonable cut-off for such fake results.

	r := rand.New(testutil.RandSource(t))
	iters := 250

	success := 0
	for range iters {
		counter, lastFake := 0, 0
		result, _, err := runTestRepro(t, testReproLog, &testExecInterface{
			run: func(log []byte) (*instance.RunResult, error) {
				// Throw in a fake crash with 5% probability,
				// but not more often than once in 10 consecutive runs.
				counter++
				if r.Intn(20) == 0 && counter-lastFake >= 10 {
					lastFake = counter
					return fakeCrashResult("flaky crash"), nil
				}
				return testExecRunner(log)
			},
		})
		// It should either find nothing (=> validation worked) or find the exact reproducer.
		require.NoError(t, err)
		if result == nil {
			continue
		}
		success++
		assert.Equal(t, expectedReproducer, string(result.Prog.Serialize()), "reliability: %.2f", result.Reliability)
	}

	// There was no deep reasoning behind the success rate. It's not 100% due to flakiness,
	// but there should still be some significant number of success cases.
	assert.Greater(t, success, iters/3*2, "must succeed >2/3 of cases")
}

func BenchmarkCalculateReliability(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for base := 0.0; base < 1.0; base += 0.1 {
		b.Run(fmt.Sprintf("p=%.2f", base), func(b *testing.B) {
			if b.N == 0 {
				return
			}
			neededRuns := make([]int, 0, b.N)
			reliability := make([]float64, 0, b.N)

			b.ResetTimer()
			for range b.N {
				runs := 0
				ret, err := calculateReliability(func() (bool, error) {
					runs++
					return r.Float64() < base, nil
				})
				require.NoError(b, err)
				neededRuns = append(neededRuns, runs)
				reliability = append(reliability, ret)
			}
			b.StopTimer()

			sort.Ints(neededRuns)
			b.ReportMetric(float64(neededRuns[len(neededRuns)/2]), "runs")

			sort.Float64s(reliability)
			b.ReportMetric(reliability[len(reliability)/10], "p10")
			b.ReportMetric(reliability[len(reliability)/2], "median")
			b.ReportMetric(reliability[len(reliability)*9/10], "p90")
		})
	}
}

func TestBrokenCompilerRepro(t *testing.T) {
	sysTarget := *targets.Get(targets.Linux, targets.AMD64)
	sysTarget.BrokenCompiler = "some compiler error"

	mgrConfig := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: targets.AMD64,
			SysTarget:    &sysTarget,
		},
		Sandbox: "namespace",
	}
	var err error
	mgrConfig.Target, err = prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	reporter, err := report.NewReporter(mgrConfig)
	require.NoError(t, err)
	env := Environment{
		Config:   mgrConfig,
		Features: flatrpc.AllFeatures,
		Fast:     false,
		Reporter: reporter,
		logf:     t.Logf,
	}

	result, _, err := runInner(context.Background(), []byte(testReproLog), env, &testExecInterface{
		run: testExecRunner,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, false, result.CRepro, "C repro should have been skipped")
}

func TestAvoidLostConnection(t *testing.T) {
	const log = `
2015/12/21 12:18:05 executing program 1:
pause()
2015/12/21 12:18:10 executing program 2:
alarm(0xa)
`
	panicLog := log + "\npanic: some error\n"

	result, _, err := runTestRepro(t, panicLog, &testExecInterface{
		run: func(p []byte) (*instance.RunResult, error) {
			if strings.Contains(string(p), "alarm(0xa)") && !strings.Contains(string(p), "pause()") {
				// alarm(0xa) alone causes a system failure.
				return &instance.RunResult{
					Report: &report.Report{
						Title: "lost connection to test machine",
						Type:  crash.LostConnection,
					},
				}, nil
			}
			if strings.Contains(string(p), "pause()") && strings.Contains(string(p), "alarm(0xa)") {
				// The combination causes the target bug.
				return fakeCrashResult("panic: some error"), nil
			}
			return fakeCrashResult(""), nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "pause()\nalarm(0xa)\n", string(result.Prog.Serialize()))
}

func TestCreateSlidingSubslices(t *testing.T) {
	makeEntries := func(n int) []*prog.LogEntry {
		entries := make([]*prog.LogEntry, n)
		for i := range entries {
			entries[i] = &prog.LogEntry{Proc: i}
		}
		return entries
	}

	// Logs smaller than minSlidingEntries (80) must return nil.
	require.Nil(t, createSlidingSubslices(makeEntries(50)))

	// For a 300-entry log, verify sliding window properties.
	subslices := createSlidingSubslices(makeEntries(300))
	require.Len(t, subslices, 10)
	require.Equal(t, 299, subslices[0][len(subslices[0])-1].Proc) // newest entry first
	require.Equal(t, 0, subslices[len(subslices)-1][0].Proc)      // oldest entry last
	for i, sub := range subslices {
		require.GreaterOrEqual(t, len(sub), minWindowSize)
		if i > 0 {
			// Adjacent subslices must overlap.
			prevStart := subslices[i-1][0].Proc
			currEnd := sub[len(sub)-1].Proc
			require.GreaterOrEqual(t, currEnd, prevStart)
		}
	}
}

func TestSlidingWindowReplay(t *testing.T) {
	// Construct a log with 300 programs.
	// Only crash if the size of the executed block is <= 80 programs
	// and a particular bad program (at position 256) is in that block.
	const (
		totalProgs = 300
		badIndex   = 256
	)
	var b strings.Builder
	for i := range totalProgs {
		if i == badIndex {
			b.WriteString("2015/12/21 12:18:00 executing program 1:\npause()\nalarm(0xa)\n")
		} else {
			fmt.Fprintf(&b, "2015/12/21 12:18:%02d executing program 1:\ngetpid()\n", i%60)
		}
	}
	panicLog := b.String() + "\npanic: target bug\n"
	require.Equal(t, totalProgs, strings.Count(panicLog, "executing program"))

	mgrConfig := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: targets.AMD64,
			SysTarget:    targets.Get(targets.Linux, targets.AMD64),
		},
		Sandbox: "namespace",
	}
	var err error
	mgrConfig.Target, err = prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	reporter, err := report.NewReporter(mgrConfig)
	require.NoError(t, err)

	runTest := func(t *testing.T, sliding bool, crashTitle string) *Result {
		exec := &testExecInterface{
			run: func(p []byte) (*instance.RunResult, error) {
				str := string(p)
				blockSize := strings.Count(str, "executing program")
				if crashTitle != "" && blockSize <= 80 &&
					strings.Contains(str, "pause()") && strings.Contains(str, "alarm(0xa)") {
					return fakeCrashResult(crashTitle), nil
				}
				return fakeCrashResult(""), nil
			},
		}
		env := Environment{
			Config:        mgrConfig,
			Features:      flatrpc.AllFeatures,
			Fast:          true,
			Reporter:      reporter,
			SlidingWindow: sliding,
			logf:          t.Logf,
		}
		res, _, err := runInner(context.Background(), []byte(panicLog), env, exec)
		require.NoError(t, err)
		return res
	}

	t.Run("without sliding window whole log fails to crash", func(t *testing.T) {
		res := runTest(t, false, "panic: target bug")
		require.Nil(t, res)
	})

	t.Run("full replay unexpected crash proceeds without sliding window", func(t *testing.T) {
		exec := &testExecInterface{
			run: func(p []byte) (*instance.RunResult, error) {
				str := string(p)
				if strings.Contains(str, "pause()") && strings.Contains(str, "alarm(0xa)") {
					return fakeCrashResult("panic: other bug"), nil
				}
				return fakeCrashResult(""), nil
			},
		}
		env := Environment{
			Config:        mgrConfig,
			Features:      flatrpc.AllFeatures,
			Fast:          true,
			Reporter:      reporter,
			SlidingWindow: false,
			logf:          t.Logf,
		}
		res, _, err := runInner(context.Background(), []byte(panicLog), env, exec)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, "pause()\nalarm(0xa)\n", string(res.Prog.Serialize()))
	})

	t.Run("with sliding window reproduces expected crash", func(t *testing.T) {
		res := runTest(t, true, "panic: target bug")
		require.NotNil(t, res)
		require.Equal(t, "pause()\nalarm(0xa)\n", string(res.Prog.Serialize()))
	})

	t.Run("with sliding window falls back to observed crash", func(t *testing.T) {
		res := runTest(t, true, "panic: other bug")
		require.NotNil(t, res)
		require.Equal(t, "pause()\nalarm(0xa)\n", string(res.Prog.Serialize()))
	})

	t.Run("with sliding window and exact crash does not fall back to unrelated crash", func(t *testing.T) {
		exec := &testExecInterface{
			run: func(p []byte) (*instance.RunResult, error) {
				str := string(p)
				blockSize := strings.Count(str, "executing program")
				if blockSize <= 80 && strings.Contains(str, "pause()") && strings.Contains(str, "alarm(0xa)") {
					return fakeCrashResult("panic: other bug"), nil
				}
				return fakeCrashResult(""), nil
			},
		}
		env := Environment{
			Config:        mgrConfig,
			Features:      flatrpc.AllFeatures,
			Fast:          true,
			Reporter:      reporter,
			SlidingWindow: true,
			ExactCrash:    true,
			logf:          t.Logf,
		}
		res, _, err := runInner(context.Background(), []byte(panicLog), env, exec)
		require.NoError(t, err)
		require.Nil(t, res)
	})

	t.Run("with sliding window no crash skips bisection", func(t *testing.T) {
		res := runTest(t, true, "")
		require.Nil(t, res)
	})
}

func TestTitlesIntersect(t *testing.T) {
	tests := []struct {
		name string
		t1   string
		alt1 []string
		t2   string
		alt2 []string
		want bool
	}{
		{
			name: "exact title match",
			t1:   "BUG: test panic",
			t2:   "BUG: test panic",
			want: true,
		},
		{
			name: "alt1 matches t2",
			t1:   "BUG: other",
			alt1: []string{"BUG: test panic"},
			t2:   "BUG: test panic",
			want: true,
		},
		{
			name: "t1 matches alt2",
			t1:   "BUG: test panic",
			t2:   "BUG: other",
			alt2: []string{"BUG: test panic"},
			want: true,
		},
		{
			name: "alt1 matches alt2",
			t1:   "BUG: foo",
			alt1: []string{"BUG: shared"},
			t2:   "BUG: bar",
			alt2: []string{"BUG: shared"},
			want: true,
		},
		{
			name: "no match",
			t1:   "BUG: test panic",
			alt1: []string{"BUG: alt1"},
			t2:   "BUG: other panic",
			alt2: []string{"BUG: alt2"},
			want: false,
		},
		{
			name: "both empty",
			t1:   "",
			t2:   "",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TitlesIntersect(tt.t1, tt.alt1, tt.t2, tt.alt2)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExactCrashOption(t *testing.T) {
	mgrConfig := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: targets.AMD64,
			SysTarget:    targets.Get(targets.Linux, targets.AMD64),
		},
		Sandbox: "namespace",
	}
	var err error
	mgrConfig.Target, err = prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	reporter, err := report.NewReporter(mgrConfig)
	require.NoError(t, err)

	panicLog := testReproLog + "\npanic: target bug\n"

	t.Run("exact crash rejects unrelated crash", func(t *testing.T) {
		exec := &testExecInterface{
			run: func(p []byte) (*instance.RunResult, error) {
				if strings.Contains(string(p), "pause()") {
					return fakeCrashResult("panic: unrelated bug"), nil
				}
				return fakeCrashResult(""), nil
			},
		}
		env := Environment{
			Config:     mgrConfig,
			Features:   flatrpc.AllFeatures,
			Fast:       true,
			Reporter:   reporter,
			ExactCrash: true,
			logf:       t.Logf,
		}
		res, _, err := runInner(context.Background(), []byte(panicLog), env, exec)
		require.NoError(t, err)
		require.Nil(t, res)
	})

	t.Run("exact crash accepts target crash", func(t *testing.T) {
		exec := &testExecInterface{
			run: func(p []byte) (*instance.RunResult, error) {
				if strings.Contains(string(p), "pause()") && strings.Contains(string(p), "alarm(0xa)") {
					return fakeCrashResult("panic: target bug"), nil
				}
				return fakeCrashResult(""), nil
			},
		}
		env := Environment{
			Config:     mgrConfig,
			Features:   flatrpc.AllFeatures,
			Fast:       true,
			Reporter:   reporter,
			ExactCrash: true,
			logf:       t.Logf,
		}
		res, _, err := runInner(context.Background(), []byte(panicLog), env, exec)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, "pause()\nalarm(0xa)\n", string(res.Prog.Serialize()))
	})

	t.Run("exact crash accepts crash with matching AltTitles", func(t *testing.T) {
		exec := &testExecInterface{
			run: func(p []byte) (*instance.RunResult, error) {
				if strings.Contains(string(p), "pause()") && strings.Contains(string(p), "alarm(0xa)") {
					ret := fakeCrashResult("panic: different title")
					ret.Report.AltTitles = []string{"panic: target bug"}
					return ret, nil
				}
				return fakeCrashResult(""), nil
			},
		}
		env := Environment{
			Config:     mgrConfig,
			Features:   flatrpc.AllFeatures,
			Fast:       true,
			Reporter:   reporter,
			ExactCrash: true,
			logf:       t.Logf,
		}
		res, _, err := runInner(context.Background(), []byte(panicLog), env, exec)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, "pause()\nalarm(0xa)\n", string(res.Prog.Serialize()))
	})
}
