// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/aflow/tool/codeeditor"
	"github.com/google/syzkaller/pkg/osutil"
)

var EditSyzSpec = aflow.NewFuncTool("edit-syz-spec", editSyzSpec, `
The tool does one edit of a syzlang description file (e.g. sys.txt) or a const file (e.g. sys.txt.const)
by replacing full lines with new provided lines. If NewCode is empty, current lines will be deleted.
Provide full lines of code including new line characters.
To create a new file, provide empty CurrentCode and the full file contents as NewCode.
The tool should be called multiple times to do all required changes one-by-one.
The edits are visible via read-syz-spec and syz-grepper tools.
After each edit, the tool compiles all descriptions and checks that they can be used for fuzzing.
It reports compilation errors, missing const values, and other problems that need to be fixed.
Problems may be expected in the middle of a multi-step change (e.g. a new const value is not added yet).
`)

type editSyzSpecState struct {
	SyzFS                  *syzspec.SyzFS
	Syzkaller              string
	TargetOS               string
	TargetArch             string
	DescriptionsScratchDir string
}

type editSyzSpecArgs struct {
	File        string `jsonschema:"Description or const file name, e.g. sys.txt or sys.txt.const."`
	CurrentCode string `jsonschema:"The current lines to be replaced (empty to create a new file)." json:",omitempty"`
	NewCode     string `jsonschema:"New lines to replace the current lines."`
}

type editSyzSpecResult struct {
	Output string `jsonschema:"Compilation and validation results of the descriptions after the edit."`
}

func editSyzSpec(ctx *aflow.Context, state editSyzSpecState, args editSyzSpecArgs) (editSyzSpecResult, error) {
	if err := editSyzSpecFile(state, args); err != nil {
		return editSyzSpecResult{}, err
	}
	res, err := syzspec.ValidateScratch(state.Syzkaller, state.TargetOS, state.TargetArch,
		state.DescriptionsScratchDir)
	if verr, ok := errors.AsType[*syzspec.ValidationError](err); ok {
		return editSyzSpecResult{Output: "The edit is done, but the descriptions have problems " +
			"that need to be fixed:\n" + verr.Error()}, nil
	} else if err != nil {
		return editSyzSpecResult{}, err
	}
	output := "The edit is done. The descriptions are OK, there are no changes."
	if len(res.Files) != 0 {
		output = fmt.Sprintf("The edit is done. The descriptions are OK.\nChanged files: %v\nNew syscalls: %v",
			strings.Join(slices.Sorted(maps.Keys(res.Files)), ", "), strings.Join(res.NewSyscalls, ", "))
	}
	return editSyzSpecResult{Output: output}, nil
}

func editSyzSpecFile(state editSyzSpecState, args editSyzSpecArgs) error {
	name := state.SyzFS.CleanPath(args.File)
	if strings.Contains(name, "/") || !syzspec.IsDescriptionFile(name) || syzspec.IsAutoTxt(name) {
		return aflow.BadCallError("File %q is not an editable description file: "+
			"provide a base file name with .txt or .txt.const extension (auto.txt can't be edited)", args.File)
	}
	file := filepath.Join(state.DescriptionsScratchDir, name)
	exists := osutil.IsExist(file)
	if exists && args.CurrentCode == "" {
		return aflow.BadCallError("File %q already exists, provide CurrentCode to edit it", args.File)
	}
	if exists {
		return codeeditor.EditFile(file, args.CurrentCode, args.NewCode)
	}
	if args.CurrentCode != "" {
		return aflow.BadCallError("File %q does not exist, to create it, "+
			"provide empty CurrentCode and the full file contents as NewCode", args.File)
	}
	if strings.TrimSpace(args.NewCode) == "" {
		return aflow.BadCallError("NewCode is empty")
	}
	if !strings.HasSuffix(args.NewCode, "\n") {
		args.NewCode += "\n"
	}
	return osutil.WriteFile(file, []byte(args.NewCode))
}
