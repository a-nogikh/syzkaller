// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/execbackend"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestCompileTargetMissingConsts(t *testing.T) {
	baseTarget, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	// Test a directory containing only a .txt file and no .const files.
	dir := t.TempDir()
	customTxt := `include <foo/bar.h>
define MY_DEF 123

custom_struct {
	f1	const[MY_MISSING_CONST_1, int32]
	f2	const[MY_MISSING_CONST_2, int32]
}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "custom.txt"), []byte(customTxt), 0644))

	res, err := compiler.CompileTarget(dir, baseTarget)
	require.NoError(t, err)
	require.Nil(t, res.Target)
	require.Len(t, res.MissingConsts, 3)
	require.Equal(t, "MY_DEF", res.MissingConsts[0].Name)
	require.Equal(t, "MY_MISSING_CONST_1", res.MissingConsts[1].Name)
	require.Equal(t, "custom.txt", res.MissingConsts[1].File)
	require.Equal(t, []string{"foo/bar.h"}, res.MissingConsts[1].Includes)
	require.Equal(t, "123", res.MissingConsts[1].Defines["MY_DEF"])
	require.Equal(t, "MY_MISSING_CONST_2", res.MissingConsts[2].Name)
}

func TestCompileTargetAndExecute(t *testing.T) {
	baseTarget, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	sysTarget := targets.Get(baseTarget.OS, baseTarget.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken compiler: %v", sysTarget.BrokenCompiler)
	}

	// Build syz-executor against the original static target.
	executorBin := csource.BuildExecutor(t, baseTarget, "../..")

	dir := copyTestDescriptions(t)
	customTxt := `custom_dyn_struct {
	f1	const[MY_CUSTOM_MAGIC, int32]
	f2	const[MY_EXTRA_CONST, int64]
}

syz_test_fuzzer1$dynprog_test(a ptr[in, custom_dyn_struct], b intptr, c intptr)
`
	customConst := `arches = 32, 32_fork, 64, 64_fork
MY_CUSTOM_MAGIC = 0x1337
MY_EXTRA_CONST = 0x42
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "custom.txt"), []byte(customTxt), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "custom.txt.const"), []byte(customConst), 0644))

	res, err := compiler.CompileTarget(dir, baseTarget)
	require.NoError(t, err)
	require.Empty(t, res.MissingConsts)
	require.NotNil(t, res.Target)
	require.Equal(t, baseTarget.Revision, res.Target.Revision)
	require.NotNil(t, res.Target.SyscallMap["syz_test_fuzzer1$dynprog_test"])
	require.Equal(t, uint64(0x1337), res.Target.ConstMap["MY_CUSTOM_MAGIC"])
	require.Equal(t, uint64(0x42), res.Target.ConstMap["MY_EXTRA_CONST"])

	progText := `syz_test_fuzzer1$dynprog_test(&(0x7f0000000000)={0x1337, 0x42}, 0x1, 0x2)`
	p, err := res.Target.Deserialize([]byte(progText), prog.Strict)
	require.NoError(t, err)

	done := make(chan *queue.Result, 1)
	req := &queue.Request{
		Prog: p,
		ExecOpts: flatrpc.ExecOpts{
			EnvFlags: flatrpc.ExecEnvSandboxNone,
		},
		ReturnOutput: true,
	}
	req.OnDone(func(r *queue.Request, qres *queue.Result) bool {
		done <- qres
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := queue.Plain()
	src.Submit(req)

	cfg := execbackend.LocalConfig{
		Target:      res.Target,
		ExecutorBin: executorBin,
		Dir:         t.TempDir(),
		Source:      src,
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := execbackend.RunLocal(ctx, cfg)
		errCh <- err
	}()

	var qres *queue.Result
	select {
	case qres = <-done:
		cancel()
		require.NoError(t, <-errCh)
	case err := <-errCh:
		require.NoError(t, err, "RunLocal exited prematurely")
	}

	require.Equal(t, queue.Success, qres.Status, "executor output: %s", string(qres.Output))
	require.NotNil(t, qres.Info)
	require.Len(t, qres.Info.Calls, 1)
	require.Equal(t, int32(0), qres.Info.Calls[0].Error)
}

func copyTestDescriptions(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	srcDir := filepath.FromSlash("../../sys/test")
	entries, err := os.ReadDir(srcDir)
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".txt" && filepath.Ext(name) != ".const" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcDir, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0644))
	}
	return dir
}
