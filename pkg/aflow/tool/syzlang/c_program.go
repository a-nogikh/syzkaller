// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

var RunCProgram = aflow.NewFuncTool("run-c-program", runCProgram, `
The tool compiles and runs a C program on the host and returns its output.
Use it to get values for .const files that are hard to compute manually
(e.g. ioctl command numbers, sizeof/offsetof of structs).
Only the program output (stdout and stderr) is returned, so the program must print
all the values it computes (e.g. with printf), preferably in the "NAME = value" format.
The program is compiled against the UAPI headers of the kernel being fuzzed (if available)
and the host's system headers. If some definitions are missing there (e.g. kernel-internal ones),
copy them from the kernel sources into the program.
`)

type runCProgramState struct {
	TargetOS   string
	TargetArch string
	// Optional dir with the kernel headers installed with "make headers_install" (contains include/).
	UAPIHeaders string
}

type runCProgramArgs struct {
	Program string `jsonschema:"Full source code of a C program that prints the required values to stdout."`
}

type runCProgramResult struct {
	Output string `jsonschema:"Output of the program."`
}

const maxCProgramOutput = 64 << 10

func runCProgram(ctx *aflow.Context, state runCProgramState, args runCProgramArgs) (runCProgramResult, error) {
	sysTarget := targets.Get(state.TargetOS, state.TargetArch)
	if sysTarget == nil {
		return runCProgramResult{}, fmt.Errorf("unknown target %v/%v", state.TargetOS, state.TargetArch)
	}
	if sysTarget.Arch != runtime.GOARCH {
		return runCProgramResult{Output: "The tool is not available for this target architecture, " +
			"find the values in the kernel sources."}, nil
	}
	dir, err := os.MkdirTemp("", "syz-c-program")
	if err != nil {
		return runCProgramResult{}, err
	}
	defer os.RemoveAll(dir)
	if err := osutil.WriteFile(filepath.Join(dir, "prog.c"), []byte(args.Program)); err != nil {
		return runCProgramResult{}, err
	}
	if err := osutil.SandboxChown(dir); err != nil {
		return runCProgramResult{}, err
	}
	// Both compilation and execution are sandboxed since the program is LLM-generated
	// (e.g. it may #include arbitrary files and leak them via compiler errors).
	compileArgs := []string{"prog.c", "-o", "prog", "-w"}
	if state.UAPIHeaders != "" {
		compileArgs = append(compileArgs, "-I", filepath.Join(state.UAPIHeaders, "include"))
	}
	compile := osutil.Command(sysTarget.CCompiler, append(compileArgs, sysTarget.CFlags...)...)
	if out, err := runSandboxed(dir, time.Minute, compile); err != nil {
		if _, ok := errors.AsType[*osutil.VerboseError](err); ok {
			return runCProgramResult{}, aflow.BadCallError("compilation failed:\n%s", truncateOutput(out))
		}
		return runCProgramResult{}, err
	}
	out, err := runSandboxed(dir, 10*time.Second, osutil.Command(filepath.Join(dir, "prog")))
	output := truncateOutput(out)
	if errors.Is(err, osutil.ErrTimeout) {
		output += "\n[the program timed out]"
	} else if verr, ok := errors.AsType[*osutil.VerboseError](err); ok {
		output += fmt.Sprintf("\n[the program exited with code %v]", verr.ExitCode)
	} else if err != nil {
		return runCProgramResult{}, err
	}
	return runCProgramResult{Output: output}, nil
}

func runSandboxed(dir string, timeout time.Duration, cmd *exec.Cmd) ([]byte, error) {
	cmd.Dir = dir
	if err := osutil.Sandbox(cmd, true, true); err != nil {
		return nil, err
	}
	return osutil.Run(timeout, cmd)
}

func truncateOutput(out []byte) string {
	if len(out) > maxCProgramOutput {
		return string(out[:maxCProgramOutput]) + "\n[output truncated]"
	}
	return string(out)
}
