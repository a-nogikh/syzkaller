// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

func init() {
	aflow.Register[ai.PatchDescriptionsArgs, ai.PatchDescriptionsResult](
		ai.WorkflowPatchDescriptions,
		"update syscall descriptions to let fuzzing reach the code modified by a patch series",
		&aflow.Flow{
			Consts: map[string]any{
				"DocSyscallDescriptionsSyntax": docs.SyscallDescriptionsSyntax,
			},
			Root: aflow.Pipeline(
				readPatchDiff,
				actionsyzlang.PrepareSyzFSScratch,
				&aflow.LLMAgent{
					Name:     "descriptions-writer",
					Model:    aflow.DeepReasoningModel,
					TaskType: aflow.FormalReasoningTask,
					Outputs:  aflow.ValidatedLLMOutputs[descriptionsWriterOutput](validateDescriptionsWriterOutput),
					Tools: aflow.Tools(
						grepper.Tool,
						codesearcher.FilesystemTools,
						ToolSeriesPatches,
						kernel.ToolConfigGrep,
						syzlang.ReadSyzSpec,
						syzlang.SyzGrepper,
						syzlang.EditSyzSpec,
						syzlang.RunCProgram,
					),
					Instruction: descriptionsWriterInstruction,
					Prompt:      descriptionsWriterPrompt,
				},
				collectDescriptions,
			),
		},
	)
}

type descriptionsWriterOutput struct {
	RelevantSyscalls []string `jsonschema:"Names of syscalls (e.g. ioctl$FOO) that reach the modified code."`
	Reasoning        string   `jsonschema:"Concise explanation of the changes and how the syscalls reach the code."`
}

type descriptionsState struct {
	Syzkaller              string
	TargetOS               string
	TargetArch             string
	DescriptionsScratchDir string
	EnabledSyscalls        []string `json:",omitempty"`
	DisabledSyscalls       []string `json:",omitempty"`
}

func validateDescriptionsWriterOutput(ctx *aflow.Context, state descriptionsState,
	args descriptionsWriterOutput) (descriptionsWriterOutput, error) {
	if args.Reasoning == "" {
		return args, aflow.BadCallError("reasoning must be provided")
	}
	res, err := syzspec.ValidateScratch(state.Syzkaller, state.TargetOS, state.TargetArch,
		state.DescriptionsScratchDir)
	if verr, ok := errors.AsType[*syzspec.ValidationError](err); ok {
		return args, aflow.BadCallError("the descriptions have problems, fix them first:\n%v", verr)
	} else if err != nil {
		return args, err
	}
	if err := checkRelevantSyscalls(res.Target, state, res.NewSyscalls, args.RelevantSyscalls); err != nil {
		return args, err
	}
	slices.Sort(args.RelevantSyscalls)
	args.RelevantSyscalls = slices.Compact(args.RelevantSyscalls)
	return args, nil
}

// checkRelevantSyscalls checks that the relevant syscalls will be fuzzed with the fuzzer config.
// The config may enable only a subset of syscalls, the fuzz step additionally enables
// the new and the relevant syscalls. The syscalls are still disabled during fuzzing
// if none of the enabled syscalls can create their input resources.
func checkRelevantSyscalls(target *prog.Target, state descriptionsState, newCalls, relevant []string) error {
	var problems []string
	for _, name := range relevant {
		call := target.SyscallMap[name]
		if call == nil {
			problems = append(problems, fmt.Sprintf("%v does not exist", name))
		} else if call.Attrs.Disabled || call.Attrs.NoGenerate {
			problems = append(problems, fmt.Sprintf("%v is disabled or can't be generated", name))
		}
	}
	if len(problems) != 0 {
		return aflow.BadCallError("bad RelevantSyscalls:\n%v", strings.Join(problems, "\n"))
	}
	enabledPatterns := state.EnabledSyscalls
	if len(enabledPatterns) != 0 {
		enabledPatterns = slices.Concat(enabledPatterns, newCalls, relevant)
	}
	ids, err := mgrconfig.ParseEnabledSyscalls(target, enabledPatterns, state.DisabledSyscalls,
		mgrconfig.ManualDescriptions)
	if err != nil {
		return err
	}
	enabled := map[*prog.Syscall]bool{}
	for _, id := range ids {
		enabled[target.Syscalls[id]] = true
	}
	_, disabled := target.TransitivelyEnabledCalls(enabled)
	for _, name := range relevant {
		call := target.SyscallMap[name]
		if !enabled[call] {
			problems = append(problems, fmt.Sprintf("%v is disabled in the fuzzer config", name))
		} else if reason := disabled[call]; reason != "" {
			problems = append(problems, fmt.Sprintf("%v: none of the enabled syscalls create its input resource"+
				" (the resource and its constructors: %v)", name, reason))
		}
	}
	if len(problems) != 0 {
		return aflow.BadCallError("some RelevantSyscalls won't be fuzzed:\n%v\n"+
			"Add syscalls that create the missing resources to RelevantSyscalls, or drop the listed syscalls.",
			strings.Join(problems, "\n"))
	}
	return nil
}

type collectDescriptionsResult struct {
	Files       map[string]string
	Diff        string
	NewSyscalls []string
}

var collectDescriptions = aflow.NewFuncAction("collect-descriptions",
	func(ctx *aflow.Context, args descriptionsState) (collectDescriptionsResult, error) {
		// The agent outputs validation has already checked the descriptions,
		// but we want to be sure about what we return. It costs a few seconds,
		// which is negligible compared to the agent run time.
		res, err := syzspec.ValidateScratch(args.Syzkaller, args.TargetOS, args.TargetArch,
			args.DescriptionsScratchDir)
		if err != nil {
			return collectDescriptionsResult{}, err
		}
		return collectDescriptionsResult{
			Files:       res.Files,
			Diff:        res.Diff,
			NewSyscalls: res.NewSyscalls,
		}, nil
	})

const descriptionsWriterInstruction = `
You are given a kernel patch series that is about to be fuzzed with syzkaller.
Your job is to make sure that the syzkaller syscall descriptions allow the fuzzer to reach
the code added or modified by the series, and to update the descriptions if they don't.

IMPORTANT: The changes have ALREADY been applied and committed as the HEAD commit in
your workspace. Do NOT rely on internal assumptions. You must actively use your code access
tools to inspect the actual source code, callers, and surrounding context.

Procedure:
1. Identify the modified kernel code and the userspace entry points that reach it
   (syscalls, ioctls, socket options, netlink families and attributes, file systems, etc.).
   Use kernel-config-grep to check that the relevant code is enabled in the kernel config.
2. Find the syzkaller syscall descriptions for these entry points with read-syz-spec
   and syz-grepper. Check that the specific commands, flags, attributes, struct fields,
   and values used by the modified code are described.
3. If something is missing, update the descriptions with edit-syz-spec:
   - Prefer adding new syscall variants (e.g. ioctl$FOO_NEW_CMD) and new types to a new
     description file named after the subsystem (e.g. foo_patch.txt and foo_patch.txt.const).
     Start a new description file with "include <...>" lines for the UAPI headers
     that define the used consts and types.
   - Modify the existing descriptions only when necessary (e.g. to add a new flag value,
     union option, netlink attribute, or struct field). Keep the changes backward compatible:
     don't remove or rename existing syscalls, don't change their attributes,
     don't change values of existing consts, and don't restructure existing types.
   - Type, resource, and flags names are global across all description files and must be unique.
   - Follow the style of the existing descriptions and reuse the existing types, flags,
     and resources where possible. Describe integer fields that hold bitmasks as flags listing
     all possible values, fields that hold file descriptors or other kernel handles as resources,
     and padding fields as const. For other integer fields, check how the kernel uses them
     to narrow down the range of values. Take the definitions from the kernel sources
     (especially include/uapi), not from man pages.
   - New pseudo-syscalls (syz_*) can't be added, only new variants of the existing ones
     (e.g. syz_genetlink_get_family_id$foo). Pseudo-syscalls are implemented in the executor,
     check their implementation with syz-grepper and read-syz-spec (e.g. PathPrefix "executor").
   - New syscalls must not use the fsck, snapshot, kfuzz_test, automatic, and automatic_helper
     attributes, and must not use larger timeout/prog_timeout values than the existing syscalls.
   - Every const used in the descriptions must have a value in a .const file.
     A new .const file must start with an "arches = {{.TargetArch}}" line followed by
     "NAME = value" lines; the values apply to all architectures listed on the arches line.
     Take the values from the kernel sources, or compute them with run-c-program
     (e.g. ioctl command numbers). Brand new syscalls need a "__NR_<name>" const
     with the syscall number (see the arch syscall table, e.g. arch/x86/entry/syscalls/syscall_64.tbl).
     Don't edit legacy per-arch const files (e.g. foo_amd64.const).
   - Don't change descriptions that are unrelated to the patch series.
   - After each edit, edit-syz-spec reports problems in the descriptions (compilation errors,
     missing consts, etc.). Fix all of them before reporting the results.
   If the existing descriptions already reach the modified code, don't change anything.
4. Report the names of the syscalls that reach the modified code (both existing and new ones,
   e.g. ioctl$FOO, sendmsg$nl_bar) in RelevantSyscalls. The fuzzer will prioritize them.
   Prefer specific syscall variants over generic ones and don't list ubiquitous syscalls
   (e.g. mmap, read, write, close).
   The fuzzer may run with only a subset of syscalls enabled. A syscall can only be fuzzed
   if its input resources (e.g. fd_foo in ioctl$FOO) can be created by the enabled syscalls,
   so also list the syscalls that create the necessary resources (e.g. openat$foo).
   Reporting the results fails while the descriptions have problems or some of the listed
   syscalls can't be fuzzed.

Document about syzlang system call descriptions syntax:
===
{{.DocSyscallDescriptionsSyntax}}
===
`

const descriptionsWriterPrompt = `Target architecture: {{.TargetArch}}

For your convenience, here is the diff of the changes:
{{.PatchDiff}}

{{.DescriptionFilesPrompt}}
`
