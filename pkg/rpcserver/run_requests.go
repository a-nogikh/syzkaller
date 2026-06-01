// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"github.com/google/syzkaller/vm/vmimpl"
)

func (serv *server) RunRequests(ctx context.Context, inst *vm.Instance,
	reporter *report.Reporter, injectExec chan bool, updInfo dispatcher.UpdateInfo) (
	[]*report.Report, error) {
	serv.CreateInstance(inst.Index(), injectExec, updInfo)

	var err error
	var fwdAddr string
	if !serv.cfg.VMLess {
		fwdAddr, err = inst.Forward(serv.Port())
		if err != nil {
			return nil, fmt.Errorf("failed to setup port forwarding: %w", err)
		}
	}

	executorBin := serv.sysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(serv.cfg.ExecutorBin)
		if err != nil {
			return nil, fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	var cmd string
	if serv.cfg.VMLess {
		// Just a placeholder, actually VMLess uses local.go.
	} else {
		host, port, err := net.SplitHostPort(fwdAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse manager's address")
		}
		cmd = fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, serv.cfg.Timeouts.VMRunningTime)
	defer cancel()

	start := time.Now()
	_, reps, err := inst.Run(ctxTimeout, reporter, cmd,
		vm.WithExitCondition(vm.ExitTimeout),
		vm.WithInjectExecuting(injectExec),
		vm.WithEarlyFinishCb(func() {
			serv.StopFuzzing(inst.Index())
		}))

	if err != nil {
		if errors.Is(err, vmimpl.ErrPreempted) {
			log.Logf(0, "VM %v: preempted while executing", inst.Index())
		} else {
			err = fmt.Errorf("failed to run fuzzer: %w", err)
		}
	} else if len(reps) == 0 {
		log.Logf(0, "VM %v: running for %v, restarting", inst.Index(), time.Since(start))
	}

	// Fetch executor info and clean up instance.
	var extraExecs []report.ExecutorInfo
	if len(reps) != 0 && reps[0] != nil && reps[0].Executor != nil {
		extraExecs = []report.ExecutorInfo{*reps[0].Executor}
	}
	execRecords, machineInfo := serv.ShutdownInstance(inst.Index(), len(reps) != 0, extraExecs...)

	if len(reps) != 0 && reps[0] != nil {
		PrependExecuting(reps[0], execRecords)
		reps[0].MachineInfo = machineInfo
	}

	return reps, err
}
