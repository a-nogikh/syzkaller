// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestCompileDescriptions(t *testing.T) {
	base, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	sysDir := filepath.Join("..", "..", "..", "sys", targets.TestOS)

	target, err := compileDescriptions(sysDir, t.TempDir(), map[string]string{
		"new.txt":       "test$new_foo(a0 const[NEW_CONST])\n",
		"new.txt.const": "arches = 32, 32_fork, 64, 64_fork\nNEW_CONST = 1\n",
	}, base)
	require.NoError(t, err)
	require.NotNil(t, target.SyscallMap["test$new_foo"])
	require.Nil(t, base.SyscallMap["test$new_foo"])

	_, err = compileDescriptions(sysDir, t.TempDir(), map[string]string{
		"new.txt": "test$new_foo(a0 const[NEW_CONST])\n",
	}, base)
	require.EqualError(t, err, "missing consts, e.g. NEW_CONST")
}

func TestWithDescriptions(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	newConfig := func() *mgrconfig.Config {
		cfg := &mgrconfig.Config{
			Syzkaller: filepath.Join("..", "..", ".."),
			// A focused config.
			EnabledSyscalls:  []string{"test$int", "test$opt0", "test$opt1"},
			DisabledSyscalls: []string{"test$opt1"},
			Experimental:     mgrconfig.Experimental{DescriptionsMode: "manual"},
			Derived:          mgrconfig.Derived{TargetOS: targets.TestOS, TargetArch: targets.TestArch64},
		}
		cfg, err := cfg.WithTarget(target)
		require.NoError(t, err)
		return cfg
	}
	base, patched := newConfig(), newConfig()
	res := &ai.PatchDescriptionsResult{
		Files:            map[string]string{"new.txt": "test$new_foo(a0 intptr)\n"},
		NewSyscalls:      []string{"test$new_foo"},
		RelevantSyscalls: []string{"test$new_foo", "test$opt0", "test$opt1", "test$str0"},
	}

	newBase, newPatched, err := withDescriptions(base, patched, res, t.TempDir())
	require.NoError(t, err)
	newTarget := newPatched.Target
	require.Same(t, newTarget, newBase.Target)
	names := func(ids []int) []string {
		var ret []string
		for _, id := range ids {
			ret = append(ret, newTarget.Syscalls[id].Name)
		}
		return ret
	}
	enabled := []string{"test$int", "test$new_foo", "test$opt0", "test$str0"}
	require.ElementsMatch(t, enabled, names(newBase.Syscalls))
	require.ElementsMatch(t, enabled, names(newPatched.Syscalls))
	require.Empty(t, newBase.BoostedCalls)
	// The disabled test$opt1 is not boosted.
	require.ElementsMatch(t, []string{"test$new_foo", "test$opt0", "test$str0"}, names(newPatched.BoostedCalls))
	// The original configs are not changed.
	require.Same(t, target, patched.Target)
	require.Empty(t, patched.BoostedCalls)

	res.Files["new.txt"] = "test$new_foo(a0 intptr\n"
	_, _, err = withDescriptions(base, patched, res, t.TempDir())
	require.Error(t, err)
}
