// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package checkpatch provides a tool to run checkpatch.pl on the workspace.
package checkpatch

import (
	"bytes"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/patchdiff"
	"github.com/google/syzkaller/pkg/osutil"
)

var Tool = aflow.NewFuncTool("checkpatch", checkpatch, `
The tool runs the Linux kernel's checkpatch.pl script on the current uncommitted changes in the workspace.
Use this tool to verify that your code modifications comply with the kernel's coding style.
If the tool reports errors or warnings, you must fix them using code editing tools before finishing your task.
`)

type state struct {
	KernelScratchSrc string
}

type args struct{}

type result struct {
	Output string `jsonschema:"Output of the checkpatch.pl command."`
}

func checkpatch(ctx *aflow.Context, state state, args args) (result, error) {
	if state.KernelScratchSrc == "" {
		return result{}, aflow.BadCallError("KernelScratchSrc is not set")
	}

	checkpatchPath := "scripts/checkpatch.pl"
	if !osutil.IsExist(filepath.Join(state.KernelScratchSrc, checkpatchPath)) {
		return result{Output: "checkpatch.pl not found (not a Linux kernel tree)."}, nil
	}

	// We need to run checkpatch on the uncommitted changes.
	// checkpatch.pl can read a patch from stdin. We can generate a diff and pipe it.
	diff, err := patchdiff.Diff(state.KernelScratchSrc, "HEAD")
	if err != nil {
		return result{}, aflow.FlowError(err)
	}

	cmd := osutil.Command("./scripts/checkpatch.pl", "--no-tree", "--no-signoff",
		"--ignore", "COMMIT_MESSAGE,GIT_COMMIT_ID", "-")
	cmd.Dir = state.KernelScratchSrc
	cmd.Stdin = bytes.NewReader(diff)
	output, _ := osutil.Run(time.Minute, cmd)

	return result{Output: string(output)}, nil
}
