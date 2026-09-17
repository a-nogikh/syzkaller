// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flatrpc

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestBuildSyscallEntries(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	entries := BuildSyscallEntries(target)
	require.Len(t, entries, len(target.Syscalls))
	// The executor relies on entries being indexed by prog.Syscall.ID.
	for i, call := range target.Syscalls {
		require.Equal(t, i, call.ID)
		entry := entries[i]
		require.Equal(t, call.Name, entry.Name)
		require.Equal(t, int32(call.NR), entry.Nr)
		require.Equal(t, call.Attrs.Timeout, entry.Timeout)
		require.Equal(t, call.Attrs.ProgTimeout, entry.ProgTimeout)
		require.Equal(t, call.Attrs.IgnoreReturn, entry.IgnoreReturn)
		require.Equal(t, call.Attrs.RemoteCover, entry.RemoteCover)
	}
	isPseudo := func(name string) bool {
		call := target.SyscallMap[name]
		require.NotNil(t, call, name)
		return entries[call.ID].PseudoSyscall
	}
	require.False(t, isPseudo("read"))
	require.False(t, isPseudo("openat$cgroup_ro"))
	require.True(t, isPseudo("syz_open_dev$loop"))
	require.True(t, isPseudo("syz_emit_ethernet"))
}
