// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

type MachineInfo struct {
	ExecOpts flatrpc.ExecOpts
	Features flatrpc.Feature
	Syscalls map[*prog.Syscall]bool
}

type SourceCallback func(req MachineInfo) rpcserver.Source

type RPCPool struct {
	Reports        chan *report.Report
	StatExecs      *stats.Val
	StatNumFuzzing *stats.Val

	cfg             *mgrconfig.Config
	server          *rpcserver.Server
	enabledFeatures flatrpc.Feature
	callback        SourceCallback
	reporter        *report.Reporter
	checkDone       atomic.Bool
}

func NewRPCPool(cfg *mgrconfig.Config, reporter *report.Reporter, callback SourceCallback,
	coverFilter rpcserver.CoverFilterCallback, debug bool) *RPCPool {
	pool := &RPCPool{
		Reports:  make(chan *report.Report, 10),
		callback: callback,
		cfg:      cfg,
		reporter: reporter,
	}
	var err error
	pool.server, err = rpcserver.New(cfg, pool.machineChecked, coverFilter, debug)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	pool.StatExecs = pool.server.StatExecs
	pool.StatNumFuzzing = pool.server.StatNumFuzzing
	log.Logf(0, "serving rpc on tcp://%v", pool.Port())
	return pool
}

func (pool *RPCPool) Port() int {
	return pool.server.Port
}

func (pool *RPCPool) TriagedCorpus() {
	pool.server.TriagedCorpus()
}

func (pool *RPCPool) DistributeSignalDelta(plus signal.Signal) {
	pool.server.DistributeSignalDelta(plus)
}

func (pool *RPCPool) InstanceRunner(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	index := inst.Index()
	instanceName := fmt.Sprintf("vm-%d", index)
	injectExec := make(chan bool, 10)
	pool.server.CreateInstance(instanceName, injectExec, updInfo)
	rep, vmInfo, err := pool.runInstanceInner(ctx, inst, instanceName, injectExec)
	lastExec, machineInfo := pool.server.ShutdownInstance(instanceName, rep != nil)
	if rep != nil {
		prependExecuting(rep, lastExec)
		if len(vmInfo) != 0 {
			machineInfo = append(append(vmInfo, '\n'), machineInfo...)
		}
		rep.MachineInfo = machineInfo
	}
	if err == nil && rep != nil {
		pool.Reports <- rep
	}
	if err != nil {
		log.Logf(1, "%s: failed with error: %v", instanceName, err)
	}
}

func (pool *RPCPool) runInstanceInner(ctx context.Context, inst *vm.Instance, instanceName string,
	injectExec <-chan bool) (*report.Report, []byte, error) {
	fwdAddr, err := inst.Forward(pool.server.Port)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}

	// If ExecutorBin is provided, it means that syz-executor is already in the image,
	// so no need to copy it.
	executorBin := pool.cfg.SysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(pool.cfg.ExecutorBin)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// Run the fuzzer binary.
	start := time.Now()

	addrPort := strings.Split(fwdAddr, ":")
	cmd := fmt.Sprintf("%v runner %v %v %v", executorBin, instanceName, addrPort[0], addrPort[1])
	_, rep, err := inst.Run(pool.cfg.Timeouts.VMRunningTime, pool.reporter, cmd,
		vm.ExitTimeout, vm.StopContext(ctx), vm.InjectExecuting(injectExec),
		vm.EarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log and we want to prevent it.
			pool.server.StopFuzzing(instanceName)
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run fuzzer: %w", err)
	}
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "%s: running for %v, restarting", instanceName, time.Since(start))
		return nil, nil, nil
	}
	vmInfo, err := inst.Info()
	if err != nil {
		vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
	}
	return rep, vmInfo, nil
}

func prependExecuting(rep *report.Report, lastExec []rpcserver.ExecRecord) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "last executing test programs:\n\n")
	for _, exec := range lastExec {
		fmt.Fprintf(buf, "%v ago: executing program %v (id=%v):\n%s\n", exec.Time, exec.Proc, exec.ID, exec.Prog)
	}
	fmt.Fprintf(buf, "kernel console output (not intermixed with test programs):\n\n")
	rep.Output = append(buf.Bytes(), rep.Output...)
	n := len(buf.Bytes())
	rep.StartPos += n
	rep.EndPos += n
	rep.SkipPos += n
}

func (pool *RPCPool) machineChecked(features flatrpc.Feature, enabledSyscalls map[*prog.Syscall]bool) rpcserver.Source {
	if len(enabledSyscalls) == 0 {
		log.Fatalf("all system calls are disabled")
	}
	if pool.checkDone.Swap(true) {
		panic("MachineChecked called twice")
	}
	pool.enabledFeatures = features

	statSyscalls := stats.Create("syscalls", "Number of enabled syscalls",
		stats.Simple, stats.NoGraph, stats.Link("/syscalls"))
	statSyscalls.Add(len(enabledSyscalls))

	return pool.callback(MachineInfo{
		Features: features,
		Syscalls: enabledSyscalls,
		ExecOpts: pool.defaultExecOpts(),
	})
}

func (pool *RPCPool) defaultExecOpts() flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(pool.enabledFeatures, nil)
	if pool.cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if pool.cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(pool.cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !pool.cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: pool.cfg.SandboxArg,
	}
}
