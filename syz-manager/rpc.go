// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type RPCServer struct {
	mgr                   RPCManagerView
	cfg                   *mgrconfig.Config
	modules               []host.KernelModule
	port                  int
	targetEnabledSyscalls map[*prog.Syscall]bool
	coverFilter           map[uint32]uint32
	stats                 *Stats
	canonicalModules      *cover.Canonicalizer

	mu          sync.Mutex
	runners     map[string]*Runner
	checkResult *rpctype.CheckArgs

	checkFailures int
	nextRequestID atomic.Int64
}

type Runner struct {
	name string

	machineInfo []byte
	instModules *cover.CanonicalizerInstance

	// The mutex protects newMaxSignal and requests.
	mu           sync.Mutex
	newMaxSignal signal.Signal
	requests     map[int64]*fuzzer.Request
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect([]host.KernelModule) (BugFrames, map[uint32]uint32, map[uint32]uint32, error)
	machineChecked(result *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool)
	getFuzzer() *fuzzer.Fuzzer
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	serv := &RPCServer{
		mgr:     mgr,
		cfg:     mgr.cfg,
		stats:   mgr.stats,
		runners: make(map[string]*Runner),
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return nil, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	serv.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	go func() {
		for {
			time.Sleep(time.Second)
			mgr.stats.rpcTraffic.add(int(s.TotalBytes.Swap(0)))
		}
	}()
	return serv, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.stats.vmRestarts.inc()

	if serv.canonicalModules == nil {
		serv.canonicalModules = cover.NewCanonicalizer(a.Modules, serv.cfg.Cover)
		serv.modules = a.Modules
	}
	bugFrames, coverFilter, execCoverFilter, err := serv.mgr.fuzzerConnect(serv.modules)
	if err != nil {
		return err
	}
	serv.coverFilter = coverFilter

	serv.mu.Lock()
	defer serv.mu.Unlock()

	runner := &Runner{
		name:        a.Name,
		machineInfo: a.MachineInfo,
		instModules: serv.canonicalModules.NewInstance(a.Modules),
		requests:    make(map[int64]*fuzzer.Request),
	}
	if serv.runners[a.Name] != nil {
		return fmt.Errorf("duplicate connection from %s", a.Name)
	}
	serv.runners[a.Name] = runner
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces

	instCoverFilter := runner.instModules.DecanonicalizeFilter(execCoverFilter)
	r.CoverFilterBitmap = createCoverageBitmap(serv.cfg.SysTarget, instCoverFilter)
	r.EnabledCalls = serv.cfg.Syscalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.cfg.Target.Revision
	r.CheckResult = serv.checkResult

	if fuzzer := serv.mgr.getFuzzer(); fuzzer != nil {
		// A Fuzzer object is created after the first Check() call.
		// If there was none, there would be no collected max signal either.
		runner.newMaxSignal = fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkResult != nil {
		return nil // another VM has already made the check
	}
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	if len(serv.cfg.EnabledSyscalls) != 0 && len(a.DisabledCalls[serv.cfg.Sandbox]) != 0 {
		disabled := make(map[string]string)
		for _, dc := range a.DisabledCalls[serv.cfg.Sandbox] {
			disabled[serv.cfg.Target.Syscalls[dc.ID].Name] = dc.Reason
		}
		for _, id := range serv.cfg.Syscalls {
			name := serv.cfg.Target.Syscalls[id].Name
			if reason := disabled[name]; reason != "" {
				log.Logf(0, "disabling %v: %v", name, reason)
			}
		}
	}
	if a.Error != "" {
		log.Logf(0, "machine check failed: %v", a.Error)
		serv.checkFailures++
		if serv.checkFailures == 10 {
			log.Fatalf("machine check failing")
		}
		return fmt.Errorf("machine check failed: %v", a.Error)
	}
	serv.targetEnabledSyscalls = make(map[*prog.Syscall]bool)
	for _, call := range a.EnabledCalls[serv.cfg.Sandbox] {
		serv.targetEnabledSyscalls[serv.cfg.Target.Syscalls[call]] = true
	}
	log.Logf(0, "machine check:")
	log.Logf(0, "%-24v: %v/%v", "syscalls", len(serv.targetEnabledSyscalls), len(serv.cfg.Target.Syscalls))
	for _, feat := range a.Features.Supported() {
		log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
	}
	serv.mgr.machineChecked(a, serv.targetEnabledSyscalls)
	a.DisabledCalls = nil
	serv.checkResult = a
	return nil
}

func (serv *RPCServer) ExchangeInfo(a *rpctype.ExchangeInfoRequest, r *rpctype.ExchangeInfoReply) error {
	fuzzer := serv.mgr.getFuzzer()
	if fuzzer == nil {
		// The fuzzer is not initialized yet.
		return nil
	}
	serv.stats.mergeNamed(a.StatsDelta)

	serv.mu.Lock()
	runner := serv.runners[a.Name]
	serv.mu.Unlock()
	if runner == nil {
		// There might be a parallel shutdownInstance().
		// Ignore the request then.
		return nil
	}

	// First query new inputs and only then post results.
	// It should foster a more even distribution of executions
	// across all VMs.
	for i := 0; i < a.NeedProgs; i++ {
		inp := fuzzer.NextInput()
		id := serv.nextRequestID.Add(1)
		r.Requests = append(r.Requests, runner.newRequest(id, inp))
	}

	for _, result := range a.Results {
		runner.doneRequest(result, fuzzer)
	}

	runner.mu.Lock()
	// Let's transfer new max signal in portions.
	const tranferMaxSignal = 150000
	maxSignalDiff := runner.newMaxSignal.Split(tranferMaxSignal)
	runner.mu.Unlock()

	r.NewMaxSignal = runner.instModules.Decanonicalize(maxSignalDiff.ToRaw())

	log.Logf(1, "exchange with %s: %d done, %d new requests, %d new max signal",
		a.Name, len(a.Results), len(r.Requests), len(r.NewMaxSignal))

	return nil
}

func (serv *RPCServer) updateFilteredCover(pcs []uint32) error {
	if len(pcs) == 0 || serv.coverFilter == nil {
		return nil
	}
	// Note: ReportGenerator is already initialized if coverFilter is enabled.
	rg, err := getReportGenerator(serv.cfg, serv.modules)
	if err != nil {
		return err
	}
	filtered := 0
	for _, pc := range pcs {
		if serv.coverFilter[uint32(rg.RestorePC(pc))] != 0 {
			filtered++
		}
	}
	serv.stats.corpusCoverFiltered.add(filtered)
	return nil
}

func (serv *RPCServer) shutdownInstance(name string) []byte {
	serv.mu.Lock()
	runner := serv.runners[name]
	if runner == nil {
		serv.mu.Unlock()
		return nil
	}
	delete(serv.runners, name)
	serv.mu.Unlock()

	runner.mu.Lock()
	if runner.requests == nil {
		// We are supposed to invoke this code only once.
		panic("Runner.requests is already nil")
	}
	oldRequests := runner.requests
	runner.requests = nil
	runner.mu.Unlock()

	// If the object does not exist, there would be no oldRequests either.
	fuzzerObj := serv.mgr.getFuzzer()
	for _, req := range oldRequests {
		// The VM likely crashed, so let's tell pkg/fuzzer to abort the affected jobs.
		// TODO: distinguish between real VM crashes and regular VM restarts?
		fuzzerObj.Done(req, &fuzzer.Result{Stop: true})
	}
	return runner.machineInfo
}

func (serv *RPCServer) distributeMaxSignal(delta signal.Signal) {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	for _, runner := range serv.runners {
		runner.mu.Lock()
		runner.newMaxSignal.Merge(delta)
		runner.mu.Unlock()
	}
}

func (runner *Runner) doneRequest(resp rpctype.ExecutionResult, fuzzerObj *fuzzer.Fuzzer) {
	runner.mu.Lock()
	req, ok := runner.requests[resp.ID]
	if ok {
		delete(runner.requests, resp.ID)
	}
	runner.mu.Unlock()
	if !ok {
		// There may be a concurrent shutdownInstance() call.
		return
	}
	info := &resp.Info
	for i := 0; i < len(info.Calls); i++ {
		call := &info.Calls[i]
		call.Cover = runner.instModules.Canonicalize(call.Cover)
		call.Signal = runner.instModules.Canonicalize(call.Signal)
	}
	info.Extra.Cover = runner.instModules.Canonicalize(info.Extra.Cover)
	info.Extra.Signal = runner.instModules.Canonicalize(info.Extra.Signal)
	fuzzerObj.Done(req, &fuzzer.Result{Info: info})
}

func (runner *Runner) newRequest(id int64, req *fuzzer.Request) rpctype.ExecutionRequest {
	var signalFilter signal.Signal
	if req.SignalFilter != nil {
		newRawSignal := runner.instModules.Decanonicalize(req.SignalFilter.ToRaw())
		// We don't care about specific priorities here.
		signalFilter = signal.FromRaw(newRawSignal, 0)
	}
	runner.mu.Lock()
	if runner.requests != nil {
		runner.requests[id] = req
	}
	runner.mu.Unlock()
	return rpctype.ExecutionRequest{
		ID:           id,
		ProgData:     req.Prog.Serialize(),
		NeedCover:    req.NeedCover,
		NeedSignal:   req.NeedSignal,
		SignalFilter: signalFilter,
		NeedHints:    req.NeedHints,
	}
}
