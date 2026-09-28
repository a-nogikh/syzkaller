// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestWorkflowPatchDescriptionsRegistered(t *testing.T) {
	require.NotNil(t, aflow.Flows[string(ai.WorkflowPatchDescriptions)])
}

func TestCollectDescriptions(t *testing.T) {
	state := testDescriptionsState(t)
	aflow.TestAction(t, collectDescriptions, t.TempDir(), state,
		collectDescriptionsResult{Files: map[string]string{}}, "")

	writeScratchFile(t, state, "new.txt", "test$new_foo(a0 intptr)\n")
	aflow.TestAction(t, collectDescriptions, t.TempDir(), state,
		collectDescriptionsResult{
			Files:       map[string]string{"new.txt": "test$new_foo(a0 intptr)\n"},
			Diff:        "--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1,1 @@\n+test$new_foo(a0 intptr)\n",
			NewSyscalls: []string{"test$new_foo"},
		}, "")

	writeScratchFile(t, state, "new.txt", "test$new_foo(a0 intptr\n")
	aflow.TestAction(t, collectDescriptions, t.TempDir(), state, collectDescriptionsResult{},
		"parsing descriptions failed:\nnew.txt:1:23: unexpected '\\n', expecting ',', ')'")
}

func TestValidateDescriptionsWriterOutput(t *testing.T) {
	state := testDescriptionsState(t)
	writeScratchFile(t, state, "new.txt", "test$new_foo(a0 intptr)\n")
	ctx := aflow.NewTestContext(t)

	_, err := validateDescriptionsWriterOutput(ctx, state, descriptionsWriterOutput{
		RelevantSyscalls: []string{"test$new_foo"},
	})
	require.EqualError(t, err, "reasoning must be provided")

	res, err := validateDescriptionsWriterOutput(ctx, state, descriptionsWriterOutput{
		RelevantSyscalls: []string{"test$new_foo", "mutate0", "test$new_foo"},
		Reasoning:        "because",
	})
	require.NoError(t, err)
	require.Equal(t, []string{"mutate0", "test$new_foo"}, res.RelevantSyscalls)

	_, err = validateDescriptionsWriterOutput(ctx, state, descriptionsWriterOutput{
		RelevantSyscalls: []string{"test$new_foo", "test$missing", "test$automatic"},
		Reasoning:        "because",
	})
	require.EqualError(t, err, "bad RelevantSyscalls:\n"+
		"test$automatic is disabled or can't be generated\n"+
		"test$missing does not exist")

	_, err = validateDescriptionsWriterOutput(ctx, state, descriptionsWriterOutput{
		RelevantSyscalls: []string{"test"},
		Reasoning:        "because",
	})
	require.ErrorContains(t, err, "RelevantSyscalls match ")
	require.ErrorContains(t, err, "specify exact $ variants instead of base syscall names")

	writeScratchFile(t, state, "new.txt", "test$new_foo(a0 const[NEW_CONST])\n")
	_, err = validateDescriptionsWriterOutput(ctx, state, descriptionsWriterOutput{
		RelevantSyscalls: []string{"test$new_foo"},
		Reasoning:        "because",
	})
	require.EqualError(t, err, "the descriptions have problems, fix them first:\n"+
		"missing value for const NEW_CONST used in new.txt (add it to a .const file)")
}

func TestValidateRelevantSyscallsConfig(t *testing.T) {
	state := testDescriptionsState(t)
	// The new syscall needs syz_res, which is created by the existing test$res0.
	writeScratchFile(t, state, "new.txt", "test$new_foo(a0 syz_res)\n")
	ctx := aflow.NewTestContext(t)
	validate := func(relevant ...string) error {
		_, err := validateDescriptionsWriterOutput(ctx, state, descriptionsWriterOutput{
			RelevantSyscalls: relevant,
			Reasoning:        "because",
		})
		return err
	}

	// All syscalls are enabled.
	require.NoError(t, validate("test$new_foo"))

	// Only some syscalls are enabled, the resource constructor must be listed as well.
	state.EnabledSyscalls = []string{"mutate0"}
	err := validate("test$new_foo")
	require.ErrorContains(t, err, "some RelevantSyscalls won't be fuzzed:\n"+
		"test$new_foo: none of the enabled syscalls create its input resource"+
		" (the resource and its constructors: syz_res [")
	require.NoError(t, validate("test$new_foo", "test$res0"))

	// The constructor is disabled in the config.
	state.DisabledSyscalls = []string{"test$res0"}
	err = validate("test$new_foo", "test$res0")
	require.ErrorContains(t, err, "test$res0 is disabled in the fuzzer config")
	require.NoError(t, validate("test$new_foo", "test$res3"))
}

func testDescriptionsState(t *testing.T) descriptionsState {
	syzDir := t.TempDir()
	sysDir := filepath.Join(syzDir, "sys", targets.TestOS)
	require.NoError(t, osutil.CopyDirRecursively(filepath.Join("..", "..", "..", "..", "sys", targets.TestOS), sysDir))
	scratchDir := t.TempDir()
	require.NoError(t, osutil.CopyDirRecursively(sysDir, scratchDir))
	return descriptionsState{
		Syzkaller:              syzDir,
		TargetOS:               targets.TestOS,
		TargetArch:             targets.TestArch64,
		DescriptionsScratchDir: scratchDir,
	}
}

func writeScratchFile(t *testing.T, state descriptionsState, name, data string) {
	require.NoError(t, os.WriteFile(filepath.Join(state.DescriptionsScratchDir, name), []byte(data), 0644))
}
