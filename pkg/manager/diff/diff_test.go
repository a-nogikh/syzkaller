package diff

import (
	"context"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/vm"
)

// --- MockKernel ---.

type MockKernel struct {
	LoopFunc          func(ctx context.Context) error
	CrashesCh         chan *report.Report
	TriageProgressVal float64
	ProgsPerAreaVal   map[string]int
	CoverFiltersVal   manager.CoverageFilters
	ConfigVal         *mgrconfig.Config
	PoolVal           *vm.Dispatcher
	FeaturesVal       flatrpc.Feature
	ReporterVal       *report.Reporter
}

func (mk *MockKernel) Loop(ctx context.Context) error {
	if mk.LoopFunc != nil {
		return mk.LoopFunc(ctx)
	}
	<-ctx.Done()
	return nil
}

func (mk *MockKernel) Crashes() <-chan *report.Report {
	return mk.CrashesCh
}

func (mk *MockKernel) TriageProgress() float64 {
	return mk.TriageProgressVal
}

func (mk *MockKernel) ProgsPerArea() map[string]int {
	return mk.ProgsPerAreaVal
}

func (mk *MockKernel) CoverFilters() manager.CoverageFilters {
	return mk.CoverFiltersVal
}

func (mk *MockKernel) Config() *mgrconfig.Config {
	return mk.ConfigVal
}

func (mk *MockKernel) Pool() *vm.Dispatcher {
	return mk.PoolVal
}

func (mk *MockKernel) Features() flatrpc.Feature {
	return mk.FeaturesVal
}

func (mk *MockKernel) Reporter() *report.Reporter {
	return mk.ReporterVal
}

func (mk *MockKernel) NumVMs() int {
	return 1
}

func (mk *MockKernel) ResizeReproPool(size int) {
}

func (mk *MockKernel) FinishCorpusTriage() {
	mk.TriageProgressVal = 1.0
}

type mockRunner struct {
	runFunc func(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool)
	doneCh  chan reproRunnerResult
}

func newMockRunner(cb func(context.Context, Kernel, *repro.Result, bool)) *mockRunner {
	return &mockRunner{
		runFunc: cb,
		doneCh:  make(chan reproRunnerResult, 1),
	}
}

func (m *mockRunner) Run(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) {
	if m.runFunc != nil {
		m.runFunc(ctx, k, r, fullRepro)
	}
}

func (m *mockRunner) Results() <-chan reproRunnerResult {
	return m.doneCh
}

func mockRepro(title string, err error) func(context.Context, []byte, repro.Environment) (
	*repro.Result, *repro.Stats, error) {
	return func(ctx context.Context, crashLog []byte, env repro.Environment) (*repro.Result, *repro.Stats, error) {
		if err != nil {
			return nil, nil, err
		}
		return &repro.Result{
			Report: &report.Report{Title: title},
			Prog:   nil,
		}, &repro.Stats{}, nil
	}
}

func createMockContext(t *testing.T, cfg *Config) (*diffContext, *MockKernel, *MockKernel) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.Store == nil {
		cfg.Store = &manager.DiffFuzzerStore{BasePath: t.TempDir()}
	}
	if cfg.PatchedOnly == nil {
		cfg.PatchedOnly = make(chan *Bug, 1)
	}
	if cfg.BaseCrashes == nil {
		cfg.BaseCrashes = make(chan string, 1)
	}
	if cfg.runner == nil {
		cfg.runner = newMockRunner(nil)
	}
	// We normally don't want real repro.Run in tests unless specified.

	diffCtx := &diffContext{
		cfg:           *cfg,
		doneRepro:     make(chan *manager.ReproResult, 1),
		store:         cfg.Store,
		reproAttempts: map[string]int{},
		patchedOnly:   cfg.PatchedOnly,
	}

	base := &MockKernel{CrashesCh: make(chan *report.Report, 1)}
	newKernel := &MockKernel{CrashesCh: make(chan *report.Report, 1)}

	newKernel.PoolVal = &vm.Dispatcher{}
	newKernel.ConfigVal = &mgrconfig.Config{}

	diffCtx.base = base
	diffCtx.new = newKernel

	return diffCtx, base, newKernel
}

func waitForStatus(t *testing.T, store *manager.DiffFuzzerStore, title string, status manager.DiffBugStatus) {
	t.Helper()
	start := time.Now()
	for time.Since(start) < 15*time.Second {
		// We need to check the status.
		// Since we don't have direct access to internal map safely without iterating or exposing a getter,
		// and List() is safe.
		for _, bug := range store.List() {
			if bug.Title == title && bug.Status == status {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for status: %s", status)
}
