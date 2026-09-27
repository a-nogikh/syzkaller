// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEnabledSyscalls(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	tests := []struct {
		name   string
		mode   DescriptionsMode
		enable []string
		// TODO: add disable tests as well.
		expectEnabled  []string
		expectDisabled []string
	}{
		{
			name:           "wildcard, no snapshot",
			mode:           ManualDescriptions,
			enable:         []string{"test"},
			expectDisabled: []string{"test$snapshot_only"},
		},
		{
			name:          "wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, no snapshot",
			mode:          ManualDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:   "automatic allowed",
			mode:   ManualDescriptions | AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
				"test$manual",
			},
		},
		{
			name:   "manual only",
			mode:   ManualDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic_helper",
				"test$manual",
			},
			expectDisabled: []string{
				"test$automatic",
			},
		},
		{
			name:   "auto only",
			mode:   AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
			},
			expectDisabled: []string{
				"test$manual",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ids, err := ParseEnabledSyscalls(target, test.enable,
				nil, test.mode)
			require.NoError(t, err)
			for _, enabled := range test.expectEnabled {
				assert.Contains(t, ids, target.SyscallMap[enabled].ID)
			}
			for _, disabled := range test.expectDisabled {
				assert.NotContains(t, ids, target.SyscallMap[disabled].ID)
			}
		})
	}
}

func TestCompleteDescriptionsMode(t *testing.T) {
	data := []byte(`{
		"target": "linux/amd64",
		"type": "none",
		"workdir": "/tmp",
		"syzkaller": "testdata/syzkaller",
		"experimental": {
			"descriptions_mode": "invalid"
		}
	}`)
	_, err := LoadData(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), `invalid descriptions_mode "invalid", must be one of: any, auto, manual`)
}

func TestFormatTarget(t *testing.T) {
	tests := []struct {
		os     string
		vmArch string
		arch   string
		want   string
	}{
		{targets.Linux, "amd64", "amd64", "linux/amd64"},
		{targets.Linux, "", "amd64", "linux/amd64"},
		{targets.Linux, "amd64", "386", "linux/amd64/386"},
		{targets.Linux, "arm64", "arm", "linux/arm64/arm"},
	}
	for _, tc := range tests {
		got := FormatTarget(tc.os, tc.vmArch, tc.arch)
		require.Equal(t, tc.want, got)
	}
}

func TestWithTarget(t *testing.T) {
	base, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	dir := t.TempDir()
	descriptions := "syz_mmap(addr vma, len len[addr])\ntest$foo(a intptr)\ntest$bar(a intptr)\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte(descriptions), 0644))
	res, err := compiler.CompileTarget(dir, base)
	require.NoError(t, err)
	target := res.Target

	cfg := &Config{
		EnabledSyscalls: []string{"test"},
		Experimental:    Experimental{DescriptionsMode: "manual"},
		Derived:         Derived{TargetOS: targets.TestOS, TargetArch: targets.TestArch64},
	}
	require.NoError(t, cfg.completeSyscalls(base))
	newCfg, err := cfg.WithTarget(target)
	require.NoError(t, err)
	require.Same(t, target, newCfg.Target)
	require.ElementsMatch(t, []int{target.SyscallMap["test$foo"].ID, target.SyscallMap["test$bar"].ID},
		newCfg.Syscalls)
	require.Same(t, base, cfg.Target)

	other, err := prog.GetTarget(targets.TestOS, targets.TestArch32)
	require.NoError(t, err)
	_, err = cfg.WithTarget(other)
	require.Error(t, err)
}
