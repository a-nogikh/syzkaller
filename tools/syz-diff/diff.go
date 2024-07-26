// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

var (
	flagBaseConfig = flag.String("base", "", "base config")
	flagNewConfig  = flag.String("new", "", "new config")
	flagDebug      = flag.Bool("debug", false, "dump all VM output to console")
)

func main() {
	if prog.GitRevision == "" {
		log.Fatalf("bad syz-manager build: build with make, run bin/syz-manager")
	}
	flag.Parse()

	baseCfg, err := mgrconfig.LoadFile(*flagBaseConfig)
	if err != nil {
		log.Fatalf("base config: %v", err)
	}

	ctx := vm.ShutdownCtx()
	base := setup(ctx, "base", baseCfg)

	newCfg, err := mgrconfig.LoadFile(*flagNewConfig)
	if err != nil {
		log.Fatalf("new config: %v", err)
	}

	new := setup(ctx, "new", newCfg)

	diffCtx := &diffContext{
		base:       base,
		new:        new,
		seenOnBase: make(map[string]bool),
	}
	diffCtx.Loop(ctx)
}

type diffContext struct {
	base     *kernelContext
	new      *kernelContext
	reproMgr *manager.ReproManager

	mu         sync.Mutex
	seenOnBase map[string]bool
}

func (dc *diffContext) Loop(ctx context.Context) {
	dc.reproMgr = manager.NewReproManager(dc, dc.new.pool.Total()-1, true)
	go dc.reproMgr.Loop(ctx)

	go func() {
		// Let both base and patched instances progress in fuzzing.
		time.Sleep(15 * time.Minute)
		log.Logf(0, "starting bug reproductions")
		dc.reproMgr.StartReproduction()
	}()

	testRepro := &runRepro{
		done:   make(chan runReproResult, 2),
		kernel: dc.base,
	}

	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ticker.C:
			log.Logf(0, "base [%s], patched [%s]; reproducing %d",
				dc.base.stats(), dc.new.stats(), len(dc.reproMgr.Reproducing()),
			)
		case item := <-dc.new.corpusUpdates:
			if obj := dc.base.fuzzer.Load(); obj != nil {
				obj.AddCandidates([]fuzzer.Candidate{{
					Prog:  dc.new.corpus.Item(item.Sig).Prog,
					Flags: fuzzer.ProgMinimized,
				}})
			}
		case item := <-dc.base.corpusUpdates:
			if obj := dc.new.fuzzer.Load(); obj != nil {
				obj.AddCandidates([]fuzzer.Candidate{{
					Prog:  dc.base.corpus.Item(item.Sig).Prog,
					Flags: fuzzer.ProgMinimized,
				}})
			}
		case rep := <-dc.base.crashes:
			log.Logf(0, "base crash: %v", rep.Title)
			dc.mu.Lock()
			dc.seenOnBase[rep.Title] = true
			dc.mu.Unlock()
		case ret := <-testRepro.done:
			log.Logf(0, "result of running the repro on base: %s", ret.title)
		case ret := <-dc.reproMgr.Done:
			if ret.Repro != nil && ret.Repro.Report != nil {
				log.Logf(0, "FOUND REPRO for %q, took %.2f minutes",
					ret.Repro.Report.Title, ret.Stats.TotalTime.Minutes())

				name := fmt.Sprintf("%v.txt", time.Now().Unix())
				osutil.WriteFile(name, ret.Stats.FullLog())
				log.Logf(0, "wrote repro log to %s", name)

				go testRepro.Run(ret.Repro)
			} else {
				log.Logf(0, "failed repro for %q, err=%s",
					ret.Crash.Report.Title, ret.Err)
			}
		case rep := <-dc.new.crashes:
			crash := &manager.Crash{Report: rep}
			need := dc.NeedRepro(crash)
			log.Logf(0, "new crash: %v [need repro = %v]",
				rep.Title, need)
			if need {
				dc.reproMgr.Enqueue(crash)
			}

		}
	}
}

func (dc *diffContext) NeedRepro(crash *manager.Crash) bool {
	if strings.Contains(crash.Title, "no output") ||
		strings.Contains(crash.Title, "lost connection") ||
		strings.Contains(crash.Title, "stall") ||
		strings.Contains(crash.Title, "SYZ") {
		// Don't waste time reproducing these.
		return false
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return !dc.seenOnBase[crash.Title]
}

func (dc *diffContext) RunRepro(crash *manager.Crash) *manager.ReproResult {
	res, stats, err := repro.Run(crash.Output, dc.new.cfg, dc.new.features,
		dc.new.reporter, dc.new.pool, repro.Fast)
	return &manager.ReproResult{
		Crash: crash,
		Repro: res,
		Stats: stats,
		Err:   err,
	}
}

func (dc *diffContext) ResizeReproPool(size int) {
	dc.new.pool.ReserveForRun(size)
}

type runReproResult struct {
	title string
}

type runRepro struct {
	done    chan runReproResult
	running atomic.Int64
	kernel  *kernelContext
}

func (rr *runRepro) Run(r *repro.Result) {
	rr.running.Add(1)
	rr.kernel.pool.ReserveForRun(1)
	defer func() {
		val := rr.running.Add(-1)
		if val == 0 {
			rr.kernel.pool.ReserveForRun(0)
		}
	}()

	var result *instance.RunResult
	var err error
	rr.kernel.pool.Run(func(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
		var ret *instance.ExecProgInstance
		ret, err = instance.SetupExecProg(inst, rr.kernel.cfg, rr.kernel.reporter, nil)
		if err != nil {
			return
		}
		result, err = ret.RunSyzProg(r.Prog.Serialize(), time.Minute, r.Opts,
			instance.SyzExitConditions)
	})

	if err != nil {
		log.Errorf("failed to run repro: %v", err)
		return
	}
	title := ""
	if result != nil && result.Report != nil {
		title = result.Report.Title
	}
	rr.done <- runReproResult{title: title}
}

type kernelContext struct {
	ctx           context.Context
	cfg           *mgrconfig.Config
	name          string
	reporter      *report.Reporter
	corpus        *corpus.Corpus
	fuzzer        atomic.Pointer[fuzzer.Fuzzer]
	serv          *rpcserver.Server
	crashes       chan *report.Report
	pool          *dispatcher.Pool[*vm.Instance]
	features      flatrpc.Feature
	corpusUpdates chan corpus.NewItemEvent
	candidates    chan []fuzzer.Candidate
}

func setup(ctx context.Context, name string, cfg *mgrconfig.Config) *kernelContext {
	osutil.MkdirAll(cfg.Workdir)

	corpusUpdates := make(chan corpus.NewItemEvent, 1024)
	kernelCtx := &kernelContext{
		ctx:           ctx,
		cfg:           cfg,
		name:          name,
		corpus:        corpus.NewMonitoredCorpus(ctx, corpusUpdates),
		corpusUpdates: corpusUpdates,
		crashes:       make(chan *report.Report, 128),
		candidates:    make(chan []fuzzer.Candidate),
	}

	go func() {
		kernelCtx.candidates <- manager.LoadSeeds(cfg, true).Candidates
	}()

	var err error
	kernelCtx.reporter, err = report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("failed to create reporter for %q: %v", name, err)
	}

	kernelCtx.serv, err = rpcserver.New(cfg, kernelCtx, *flagDebug)
	if err != nil {
		log.Fatalf("failed to create rpc server for %q: %v", name, err)
	}

	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatalf("failed to create vm.Pool for %q: %v", name, err)
	}

	kernelCtx.pool = vm.NewDispatcher(vmPool, kernelCtx.fuzzerInstance)
	go kernelCtx.pool.Loop(ctx)
	return kernelCtx
}

func (kc *kernelContext) MaxSignal() signal.Signal {
	if fuzzer := kc.fuzzer.Load(); fuzzer != nil {
		return fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (kc *kernelContext) BugFrames() (leaks, races []string) {
	return nil, nil
}

func (kc *kernelContext) MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
	if len(syscalls) == 0 {
		log.Fatalf("all system calls are disabled")
	}
	log.Logf(0, "%s: machine check complete", kc.name)

	kc.features = features
	opts := fuzzer.DefaultExecOpts(kc.cfg, features, *flagDebug)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	fuzzerObj := fuzzer.NewFuzzer(context.Background(), &fuzzer.Config{
		Corpus:         kc.corpus,
		Coverage:       kc.cfg.Cover,
		FaultInjection: features&flatrpc.FeatureFault != 0,
		Comparisons:    features&flatrpc.FeatureComparisons != 0,
		Collide:        true,
		EnabledCalls:   syscalls,
		NoMutateCalls:  kc.cfg.NoMutateCalls,
		Logf: func(level int, msg string, args ...interface{}) {
			if level != 0 {
				return
			}
			log.Logf(level, msg, args...)
		},
	}, rnd, kc.cfg.Target)
	kc.fuzzer.Store(fuzzerObj)

	filtered := manager.FilterCandidates(<-kc.candidates, syscalls).Candidates
	log.Logf(0, "%s: adding %d seeds", kc.name, len(filtered))
	fuzzerObj.AddCandidates(filtered)

	go func() {
		if !kc.cfg.Cover {
			return
		}
		for {
			select {
			case <-time.After(time.Second):
			case <-kc.ctx.Done():
				return
			}
			newSignal := fuzzerObj.Cover.GrabSignalDelta()
			if len(newSignal) == 0 {
				continue
			}
			kc.serv.DistributeSignalDelta(newSignal)
		}
	}()
	return queue.DefaultOpts(fuzzerObj, opts)
}

func (kc *kernelContext) CoverageFilter(modules []*vminfo.KernelModule) []uint64 {
	return nil
}

func (kc *kernelContext) fuzzerInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	index := inst.Index()
	injectExec := make(chan bool, 10)
	kc.serv.CreateInstance(index, injectExec, updInfo)
	rep, err := kc.runInstance(ctx, inst, injectExec)
	if err != nil {
		log.Errorf("#%d run failed: %s", inst.Index(), err)
		return
	}
	lastExec, _ := kc.serv.ShutdownInstance(index, rep != nil)
	if rep != nil {
		rpcserver.PrependExecuting(rep, lastExec)
		kc.crashes <- rep
	}
}

func (kc *kernelContext) runInstance(ctx context.Context, inst *vm.Instance,
	injectExec <-chan bool) (*report.Report, error) {
	fwdAddr, err := inst.Forward(kc.serv.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}
	executorBin, err := inst.Copy(kc.cfg.ExecutorBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %w", err)
	}
	host, port, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manager's address")
	}
	cmd := fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	_, rep, err := inst.Run(kc.cfg.Timeouts.VMRunningTime, kc.reporter, cmd,
		vm.ExitTimeout, vm.StopContext(ctx), vm.InjectExecuting(injectExec),
		vm.EarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log and we want to prevent it.
			kc.serv.StopFuzzing(inst.Index())
		}),
	)
	return rep, err
}

func (kc *kernelContext) stats() string {
	stat := fmt.Sprintf("execs: %d, corpus: %d, VMs: %d",
		kc.serv.StatExecs.Val(),
		kc.corpus.StatProgs.Val(),
		kc.serv.StatNumFuzzing.Val(),
	)
	if fuzzer := kc.fuzzer.Load(); fuzzer != nil {
		stat += fmt.Sprintf(", signal: %d",
			fuzzer.Cover.MaxSignalLen(),
		)
	}
	return stat
}
