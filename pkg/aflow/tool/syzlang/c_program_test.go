// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestRunCProgram(t *testing.T) {
	skipIfCantRunC(t)
	headers := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(headers, "include", "linux"), 0755))
	require.NoError(t, osutil.WriteFile(filepath.Join(headers, "include", "linux", "syz_new_uapi.h"),
		[]byte("#define SYZ_NEW_CONST 42\n")))
	state := runCProgramState{TargetOS: targets.Linux, TargetArch: targets.AMD64, UAPIHeaders: headers}
	aflow.TestTool(t, RunCProgram, state,
		runCProgramArgs{Program: `
#include <stdio.h>
#include <linux/fs.h>
#include <linux/syz_new_uapi.h>
struct foo { int a; long b; };
int main() {
	printf("FS_IOC_GETFLAGS = 0x%lx\n", (unsigned long)FS_IOC_GETFLAGS);
	printf("SYZ_NEW_CONST = %d\n", SYZ_NEW_CONST);
	printf("sizeof(struct foo) = %zu\n", sizeof(struct foo));
	return 0;
}
`},
		runCProgramResult{Output: "FS_IOC_GETFLAGS = 0x80086601\nSYZ_NEW_CONST = 42\nsizeof(struct foo) = 16\n"}, "")
	aflow.TestTool(t, RunCProgram, state,
		runCProgramArgs{Program: `
#include <stdio.h>
int main() {
	printf("failing\n");
	return 3;
}
`},
		runCProgramResult{Output: "failing\n\n[the program exited with code 3]"}, "")
	aflow.TestTool(t, RunCProgram, runCProgramState{TargetOS: targets.Linux, TargetArch: targets.S390x},
		runCProgramArgs{Program: "int main() { return 0; }"},
		runCProgramResult{Output: "The tool is not available for this target architecture, " +
			"find the values in the kernel sources."}, "")
}

func TestRunCProgramCompileError(t *testing.T) {
	skipIfCantRunC(t)
	_, err := runCProgram(nil, runCProgramState{TargetOS: targets.Linux, TargetArch: targets.AMD64},
		runCProgramArgs{Program: "int main() { return UNDEFINED_CONST; }"})
	require.ErrorContains(t, err, "compilation failed")
	require.ErrorContains(t, err, "UNDEFINED_CONST")
}

func skipIfCantRunC(t *testing.T) {
	if runtime.GOARCH != targets.AMD64 {
		t.Skip("the test requires an amd64 host")
	}
	if broken := targets.Get(targets.Linux, targets.AMD64).BrokenCompiler; broken != "" {
		t.Skip(broken)
	}
}
