// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/stretchr/testify/assert"
)

const testTimeout = 15 * time.Second

func TestNeedReproForTitle(t *testing.T) {
	for title, skip := range map[string]bool{
		"no output from test machine":                          false,
		"SYZFAIL: read failed":                                 false,
		"lost connection to test machine":                      false,
		"INFO: rcu detected stall in clone":                    false,
		"WARNING in arch_install_hw_breakpoint":                true,
		"KASAN: slab-out-of-bounds Write in __bpf_get_stackid": true,
	} {
		assert.Equal(t, skip, needReproForTitle(title), "title=%q", title)
	}
}

func TestDiffBaseCrashInterception(t *testing.T) {
	diffCtx, base, newKernel := createMockContext(t, nil)

	// Inject base crash.
	base.CrashesCh <- &report.Report{Title: "base_crash"}

	// Mock Loop functions.
	base.LoopFunc = func(ctx context.Context) error { return nil }
	newKernel.LoopFunc = func(ctx context.Context) error { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error)
	go func() {
		done <- diffCtx.Loop(ctx)
	}()

	select {
	case title := <-diffCtx.cfg.BaseCrashes:
		assert.Equal(t, "base_crash", title)
	case <-time.After(testTimeout):
		t.Error("expected base crash")
	}

	cancel()
	<-done
}

func TestDiffExternalIgnore(t *testing.T) {
	// Scenario: Config ignores crash -> Patched crash ignored -> No repro.
	runReproCalled := false
	mockRunRepro := func(ctx context.Context, crashLog []byte, env repro.Environment) (*repro.Result,
		*repro.Stats, error) {
		runReproCalled = true
		return &repro.Result{Report: &report.Report{Title: "crash_title"}}, &repro.Stats{}, nil
	}

	diffCtx, _, newKernel := createMockContext(t, &Config{
		IgnoreCrash: func(ctx context.Context, title string) (bool, error) {
			if title == "ignored_crash" {
				return true, nil
			}
			return false, nil
		},
		runRepro: mockRunRepro,
		runner:   newMockRunner(nil),
	})
	newKernel.FinishCorpusTriage()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error)
	go func() { done <- diffCtx.Loop(ctx) }()

	// 1. Crash Ignored
	newKernel.CrashesCh <- &report.Report{Title: "ignored_crash", Report: []byte("log")}

	// Wait for the status update.
	// Wait for the status update.
	waitForStatus(t, diffCtx.store, "ignored_crash", manager.DiffBugStatusIgnored)
	assert.False(t, runReproCalled, "should not repro ignored crash")

	// 2. Crash Important
	newKernel.CrashesCh <- &report.Report{Title: "important_crash", Report: []byte("log")}

	// This one should trigger repro.
	waitForStatus(t, diffCtx.store, "important_crash", manager.DiffBugStatusReproducing)

	cancel()
	<-done
}

func TestDiffSuccess(t *testing.T) {
	// Scenario: Patched kernel crashes -> Repro succeeds -> Base kernel does NOT crash -> PatchedOnly reported.

	// Mock Runner (Repro on Base).
	mockRunner := newMockRunner(nil)
	mockRunner.runFunc = func(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) {
		// Simulate successful run on base without crash.
		mockRunner.doneCh <- reproRunnerResult{
			reproReport: r.Report,
			repro:       r,
			crashReport: nil, // No crash on base.
			fullRepro:   true,
		}
	}

	diffCtx, _, newKernel := createMockContext(t, &Config{
		runRepro: mockRepro("crash_title", nil),
		runner:   mockRunner,
	})
	newKernel.FinishCorpusTriage()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error)
	go func() {
		done <- diffCtx.Loop(ctx)
	}()

	// 1. Trigger crash on patched
	newKernel.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}

	// 2. Expect PatchedOnly report
	select {
	case bug := <-diffCtx.patchedOnly:
		assert.Equal(t, "crash_title", bug.Report.Title)
	case <-time.After(testTimeout):
		t.Fatal("expected patched only report")
	}

	cancel()
	<-done
}

func TestDiffFailNoRepro(t *testing.T) {
	// Scenario: Patched kernel crashes -> Repro fails -> No report.
	mockRunner := newMockRunner(nil)

	diffCtx, _, newKernel := createMockContext(t, &Config{
		runRepro: mockRepro("", errors.New("repro failed")),
		runner:   mockRunner,
	})
	newKernel.FinishCorpusTriage()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error)
	go func() { done <- diffCtx.Loop(ctx) }()

	newKernel.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}
	waitForStatus(t, diffCtx.store, "crash_title", manager.DiffBugStatusCompleted)

	cancel()
	<-done
}

func TestDiffFailBaseCrash(t *testing.T) {
	// Scenario: Patched kernel crashes -> Repro succeeds -> Base also crashes -> No PatchedOnly report.

	mockRunner := newMockRunner(nil)
	mockRunner.runFunc = func(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) {
		mockRunner.doneCh <- reproRunnerResult{
			reproReport: r.Report,
			repro:       r,
			crashReport: &report.Report{Title: "crash_title"}, // Base crashed.
		}
	}

	diffCtx, _, newKernel := createMockContext(t, &Config{
		runRepro: mockRepro("crash_title", nil),
		runner:   mockRunner,
	})
	newKernel.FinishCorpusTriage()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error)
	go func() { done <- diffCtx.Loop(ctx) }()

	newKernel.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}

	select {
	case <-diffCtx.patchedOnly:
		t.Fatal("unexpected patched only report")
	case <-diffCtx.cfg.BaseCrashes: // Should report to BaseCrashes.
		// Expected.
	case <-time.After(testTimeout):
		t.Fatal("expected base crash report")
	}

	waitForStatus(t, diffCtx.store, "crash_title", manager.DiffBugStatusCompleted)

	cancel()
	<-done
}

func TestDiffFailBaseCrashEarly(t *testing.T) {
	// Scenario: Base crashes first -> Patched crashes same title -> No reproduction attempt.
	runReproCalled := false
	mockRunRepro := func(ctx context.Context, crashLog []byte, env repro.Environment) (*repro.Result,
		*repro.Stats, error) {
		runReproCalled = true
		return &repro.Result{Report: &report.Report{Title: "crash_title"}}, &repro.Stats{}, nil
	}

	mockRunner := newMockRunner(nil)

	diffCtx, base, newKernel := createMockContext(t, &Config{
		runRepro: mockRunRepro,
		runner:   mockRunner,
	})
	newKernel.FinishCorpusTriage()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error)
	go func() { done <- diffCtx.Loop(ctx) }()

	// 1. Crash Base
	base.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}
	select {
	case <-diffCtx.cfg.BaseCrashes:
	case <-time.After(testTimeout):
		t.Fatal("expected base crash")
	}

	// 2. Crash Patched (Same Title)
	newKernel.CrashesCh <- &report.Report{Title: "crash_title", Report: []byte("log")}

	// 3. Verify No Repro
	waitForStatus(t, diffCtx.store, "crash_title", manager.DiffBugStatusIgnored)
	assert.False(t, runReproCalled, "WaitRepro should not be called")

	cancel()
	<-done
}
