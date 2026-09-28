// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

const (
	maxChangedFiles = 20
	maxDiffSize     = 256 << 10
	// These must match kMaxSyscalls and kMaxSyscallNamesSize in executor/executor.cc.
	maxSyscalls         = 16 << 10
	maxSyscallNamesSize = 1 << 20
	// Max number of reported problems of the same kind.
	maxProblems = 10
	// Max number of reported compiler error lines.
	maxErrorLines = 20
)

// ValidatedDescriptions is the result of a successful descriptions validation.
type ValidatedDescriptions struct {
	// Target compiled from the descriptions.
	Target *prog.Target
	// New and modified description files with their full contents.
	Files map[string]string
	// Unified diff of the changes.
	Diff string
	// Syscalls that are not present in the base target.
	NewSyscalls []string
}

// ValidationError lists problems in the descriptions that need to be fixed.
type ValidationError struct {
	Problems []string
}

func (err *ValidationError) Error() string {
	return strings.Join(err.Problems, "\n")
}

// ValidateScratch validates the descriptions in scratchDir (a modified copy of sys/<targetOS>)
// against the pristine descriptions in the syzkaller checkout.
// The base target is the one compiled into the current binary.
func ValidateScratch(syzkaller, targetOS, targetArch, scratchDir string) (*ValidatedDescriptions, error) {
	base, err := prog.GetTarget(targetOS, targetArch)
	if err != nil {
		return nil, err
	}
	return ValidateDescriptions(filepath.Join(syzkaller, "sys", targetOS), scratchDir, base)
}

// ValidateDescriptions checks that descriptions in dir (a modified copy of pristineDir)
// can be compiled and safely used for fuzzing with the executor built for the base target.
// Problems in the descriptions are returned as *ValidationError.
func ValidateDescriptions(pristineDir, dir string, base *prog.Target) (*ValidatedDescriptions, error) {
	files, diff, err := ChangedDescriptions(pristineDir, dir)
	if err != nil {
		return nil, err
	}
	if problems := checkChangedFiles(files, diff); len(problems) != 0 {
		return nil, &ValidationError{Problems: problems}
	}
	res := &ValidatedDescriptions{
		Target: base,
		Files:  files,
		Diff:   diff,
	}
	if len(files) == 0 {
		return res, nil
	}
	target, problems := compileTarget(dir, base)
	if len(problems) != 0 {
		return nil, &ValidationError{Problems: problems}
	}
	res.Target = target
	generatable := generatableSyscalls(target)
	newCalls, problems := checkSyscalls(target, base, generatable)
	if len(problems) != 0 {
		return nil, &ValidationError{Problems: problems}
	}
	for _, call := range newCalls {
		res.NewSyscalls = append(res.NewSyscalls, call.Name)
	}
	return res, nil
}

// generatableSyscalls returns the names of syscalls that the fuzzer can generate.
func generatableSyscalls(target *prog.Target) map[string]bool {
	enabled := map[*prog.Syscall]bool{}
	for _, call := range target.Syscalls {
		if !call.Attrs.Disabled && !call.Attrs.NoGenerate {
			enabled[call] = true
		}
	}
	supported, _ := target.TransitivelyEnabledCalls(enabled)
	ret := map[string]bool{}
	for call := range supported {
		ret[call.Name] = true
	}
	return ret
}

func checkChangedFiles(files map[string]string, diff string) []string {
	var problems []string
	if len(files) > maxChangedFiles {
		problems = append(problems, fmt.Sprintf("too many changed files: %v (max %v)",
			len(files), maxChangedFiles))
	}
	if len(diff) > maxDiffSize {
		problems = append(problems, fmt.Sprintf("the changes are too large: %v bytes (max %v)",
			len(diff), maxDiffSize))
	}
	for file := range files {
		if IsAutoTxt(file) {
			problems = append(problems, fmt.Sprintf("auto-generated file %v must not be changed", file))
		}
	}
	slices.Sort(problems)
	return problems
}

func compileTarget(dir string, base *prog.Target) (target *prog.Target, problems []string) {
	defer func() {
		// Target initialization may panic on unexpected descriptions (e.g. on missing syscalls).
		if err := recover(); err != nil {
			target, problems = nil, []string{fmt.Sprintf("target initialization panicked: %v", err)}
		}
	}()
	res, err := compiler.CompileTarget(dir, base)
	if err != nil {
		// Don't expose the temp dir names.
		msg := strings.ReplaceAll(err.Error(), dir+string(filepath.Separator), "")
		lines := strings.Split(msg, "\n")
		if len(lines) > maxErrorLines {
			lines = append(lines[:maxErrorLines:maxErrorLines],
				fmt.Sprintf("... and %v more lines", len(lines)-maxErrorLines))
		}
		return nil, []string{strings.Join(lines, "\n")}
	}
	for _, c := range res.MissingConsts {
		problems = append(problems, fmt.Sprintf("missing value for const %v used in %v "+
			"(add it to a .const file)", c.Name, c.File))
	}
	return res.Target, limitProblems(problems, "missing consts")
}

func checkSyscalls(target, base *prog.Target, generatable map[string]bool) ([]*prog.Syscall, []string) {
	var problems []string
	sysTarget := targets.Get(target.OS, target.Arch)
	baseCallNames := map[string]bool{}
	var maxTimeout, maxProgTimeout uint64
	for _, call := range base.Syscalls {
		baseCallNames[call.CallName] = true
		maxTimeout = max(maxTimeout, call.Attrs.Timeout)
		maxProgTimeout = max(maxProgTimeout, call.Attrs.ProgTimeout)
	}
	var newCalls []*prog.Syscall
	namesSize := 0
	for _, call := range target.Syscalls {
		namesSize += len(call.Name) + 1
		if baseCall := base.SyscallMap[call.Name]; baseCall != nil {
			if call.Attrs != baseCall.Attrs {
				problems = append(problems, fmt.Sprintf("attributes of existing syscall %v "+
					"must not be changed", call.Name))
			}
			continue
		}
		newCalls = append(newCalls, call)
		if sysTarget.IsPseudoSyscall(call.CallName) && !baseCallNames[call.CallName] {
			problems = append(problems, fmt.Sprintf("syscall %v: new pseudo-syscall %v is not "+
				"implemented in the executor, only variants of the existing ones can be added",
				call.Name, call.CallName))
		}
		problems = append(problems, checkNewSyscallAttrs(call, maxTimeout, maxProgTimeout)...)
		if err := checkNeutralize(target, call); err != nil {
			problems = append(problems, fmt.Sprintf("new syscall %v has incompatible arguments for %v: %v",
				call.Name, call.CallName, err))
		}
	}
	var removed []string
	for _, call := range base.Syscalls {
		if target.SyscallMap[call.Name] == nil {
			removed = append(removed, fmt.Sprintf("existing syscall %v was removed or renamed", call.Name))
		}
	}
	problems = append(problems, limitProblems(removed, "removed syscalls")...)
	if len(target.Syscalls) > maxSyscalls {
		problems = append(problems, fmt.Sprintf("too many syscalls: %v (max %v)",
			len(target.Syscalls), maxSyscalls))
	}
	if namesSize > maxSyscallNamesSize {
		problems = append(problems, fmt.Sprintf("syscall names are too long: %v bytes (max %v)",
			namesSize, maxSyscallNamesSize))
	}
	for _, call := range newCalls {
		if !call.Attrs.Disabled && !call.Attrs.NoGenerate && !generatable[call.Name] {
			problems = append(problems, fmt.Sprintf("new syscall %v can't be generated: "+
				"some of its input resources can't be created by any syscall", call.Name))
		}
	}
	problems = append(problems, checkDirOpenFlags(target, newCalls)...)
	return newCalls, problems
}

// checkNeutralize checks that target.Neutralize does not panic on a default call
// (e.g. if an ioctl variant is missing its cmd argument or has a non-const cmd type).
func checkNeutralize(target *prog.Target, call *prog.Syscall) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	args := make([]prog.Arg, len(call.Args))
	for i, field := range call.Args {
		args[i] = field.Type.DefaultArg(field.Dir(prog.DirIn))
	}
	return target.Neutralize(prog.MakeCall(call, args), true)
}

func checkDirOpenFlags(target *prog.Target, newCalls []*prog.Syscall) []string {
	dirResources := map[string]bool{}
	for _, call := range target.Syscalls {
		if strings.HasSuffix(call.CallName, "at") && len(call.Args) > 0 {
			if res, ok := call.Args[0].Type.(*prog.ResourceType); ok {
				dirResources[res.Desc.Name] = true
			}
		}
	}
	var problems []string
	for _, call := range newCalls {
		if call.CallName != "openat" || len(call.Args) < 3 {
			continue
		}
		ret, ok := call.Ret.(*prog.ResourceType)
		if !ok || !dirResources[ret.Desc.Name] {
			continue
		}
		if flags, ok := call.Args[2].Type.(*prog.FlagsType); ok && flags.Name() == "open_flags" {
			problems = append(problems, fmt.Sprintf("new syscall %v opens a directory fd (%v) "+
				"with flags[open_flags] (use const[O_RDONLY] or const[O_PATH] instead)",
				call.Name, ret.Desc.Name))
		}
	}
	return problems
}

// checkNewSyscallAttrs checks that new syscalls don't use attributes that change
// the fuzzer/executor behavior in ways that we can't validate.
func checkNewSyscallAttrs(call *prog.Syscall, maxTimeout, maxProgTimeout uint64) []string {
	var problems []string
	attrs := call.Attrs
	forbidden := []struct {
		name string
		set  bool
	}{
		{"fsck", attrs.Fsck != ""},
		{"snapshot", attrs.Snapshot},
		{"kfuzz_test", attrs.KFuzzTest},
		{"automatic", attrs.Automatic},
		{"automatic_helper", attrs.AutomaticHelper},
	}
	for _, attr := range forbidden {
		if attr.set {
			problems = append(problems, fmt.Sprintf("new syscall %v: attribute %v is not allowed",
				call.Name, attr.name))
		}
	}
	if attrs.Timeout > maxTimeout {
		problems = append(problems, fmt.Sprintf("new syscall %v: timeout %v is too large (max %v)",
			call.Name, attrs.Timeout, maxTimeout))
	}
	if attrs.ProgTimeout > maxProgTimeout {
		problems = append(problems, fmt.Sprintf("new syscall %v: prog_timeout %v is too large (max %v)",
			call.Name, attrs.ProgTimeout, maxProgTimeout))
	}
	return problems
}

// limitProblems leaves at most maxProblems entries in the list.
func limitProblems(problems []string, what string) []string {
	if len(problems) <= maxProblems {
		return problems
	}
	return append(problems[:maxProblems:maxProblems],
		fmt.Sprintf("... and %v more %v", len(problems)-maxProblems, what))
}
