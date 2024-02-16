// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestFuzz(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	executor := buildExecutor(t, target)
	defer os.Remove(executor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fuzzer := NewFuzzer(ctx, &Config{
		Logf: func(level int, msg string, args ...interface{}) {
			if level > 1 {
				return
			}
			t.Logf(msg, args...)
		},
		Coverage: true,
		EnabledCalls: map[*prog.Syscall]bool{
			target.SyscallMap["syz_test_fuzzer1"]: true,
		},
		Candidates: make(chan Candidate),
	}, rand.New(testutil.RandSource(t)), target)

	go func() {
		for c := range fuzzer.NewInputs {
			t.Logf("new prog:\n%s", c.Prog)
		}
	}()

	crashes := map[string]int{
		"first bug":  0,
		"second bug": 0,
	}
	proc := newProc(t, target, executor)
	defer proc.env.Close()

	for i := 0; i < 5000; i++ {
		// Let's save some CPU cycles.
		anyZero := false
		for _, v := range crashes {
			anyZero = anyZero || v == 0
		}
		if !anyZero {
			break
		}

		req := fuzzer.NextInput()
		res, crash, err := proc.execute(req)
		if err != nil {
			t.Fatal(err)
		}
		if crash != "" {
			t.Logf("CRASH: %s", crash)
			val, ok := crashes[crash]
			assert.True(t, ok, "unexpected crash: %q", crash)
			crashes[crash] = val + 1
			res = &Result{Stop: true}
		}
		fuzzer.Done(req, res)
		if i%10 == 0 {
			stat := fuzzer.Corpus.Stat()
			t.Logf("<iter %d>: corpus %d, signal %d, max signal %d",
				i+1, stat.Progs, stat.Signal, stat.MaxSignal)
		}
	}

	t.Logf("resulting corpus:")
	for _, p := range fuzzer.Corpus.Programs() {
		t.Logf("-----")
		t.Logf("%s", string(p.Serialize()))
	}

	t.Logf("crashes:")
	for title, cnt := range crashes {
		t.Logf("%s: %d", title, cnt)
	}

	for k, v := range crashes {
		assert.Greater(t, v, 0, "%q was not triggered", k)
	}

	t.Logf("stats:\n%v", fuzzer.GrabStats())
}

// TODO: it's already implemented in syz-fuzzer/proc.go,
// pkg/runtest and tools/syz-execprog.
// Looks like it's time to factor out this functionality.
type executorProc struct {
	env      *ipc.Env
	execOpts ipc.ExecOpts
}

func newProc(t *testing.T, target *prog.Target, executor string) *executorProc {
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		t.Fatal(err)
	}
	config.Executor = executor
	config.Flags |= ipc.FlagSignal
	env, err := ipc.MakeEnv(config, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &executorProc{
		env:      env,
		execOpts: *execOpts,
	}
}

var crashRe = regexp.MustCompile(`{{CRASH: (.*?)}}`)

func (proc *executorProc) execute(req *Request) (*Result, string, error) {
	execOpts := proc.execOpts
	// TODO: it's duplicated from fuzzer.go.
	if req.NeedSignal {
		execOpts.Flags |= ipc.FlagCollectSignal
	}
	if req.NeedCover {
		execOpts.Flags |= ipc.FlagCollectCover
	}
	// TODO: support req.NeedHints.
	output, info, _, err := proc.env.Exec(&execOpts, req.Prog)
	ret := crashRe.FindStringSubmatch(string(output))
	if ret != nil {
		return nil, ret[1], nil
	} else if err != nil {
		return nil, "", err
	}
	return &Result{Info: info}, "", nil
}

func buildExecutor(t *testing.T, target *prog.Target) string {
	executor, err := csource.BuildFile(target,
		filepath.FromSlash("../../executor/executor.cc"),
		"-fsanitize-coverage=trace-pc", "-g",
	)
	if err != nil {
		t.Fatal(err)
	}
	return executor
}
