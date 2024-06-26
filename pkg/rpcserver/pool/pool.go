// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package pool

import (
	"context"
	"time"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/vm"
)

type ExecutorPool struct {
	Failures chan Failure

	ctx context.Context
	cfg *Config
}

type Failure struct {
	Boot   bool
	Report *report.Report
	Err    error
}

type Config struct {
	Default queue.Source
	Pool    *vm.Pool
	RPC     *rpcserver.Config
}

type Task struct {
	Source   queue.Source
	Duration time.Duration
	Stop     chan stop
}

// TODO for the rpcserver:
// - varying number of procs.
// - accept per-VM sources.

// TODO: take the manager config.
func NewExecutorPool(ctx context.Context, cfg *Config) *ExecutorPool {
	return &ExecutorPool{
		Failures: make(chan Failure, 10),
		ctx:      ctx,
		cfg:      cfg,
	}
}

func (p *ExecutorPool) Loop() {
	// Construct an RPC server.
	for i := 0; i < p.pool.Count(); i++ {
		// Set up a loop for every VM.
	}
	// Wait for ctx.Done(), gracefully exit.
}

// Run() executes requests from the source and returns when:
// 1) The source runs out of requests.
// 2) The specifed duration passes.
// 3) The VM crashes.
func (p *ExecutorPool) Run(task *Task) (*report.Report, error) {
	//
}

// ReserveForRun() specifies the number of VMs reserved for Run().
func (p *ExecutorPool) ReserveForRun(VMs int) {
	if VMs > p.pool.Count() {
		panic("trying to reserve more VMs that available")
	}
	// If the number is increased, restart the longest running instance.
}

func (p *ExecutorPool) vmLoop(idx int) {
	for {
		// Boot a VM.
		// Wait for a source and duration.
		// Upload and start the executor.
		// Share the task with the rpc server.
	}
}
