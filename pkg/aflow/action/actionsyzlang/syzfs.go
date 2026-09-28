// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"fmt"
	"path/filepath"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/google/syzkaller/pkg/osutil"
)

var PrepareSyzFS = aflow.NewFuncAction("prepare-syzfs", prepareSyzFSFunc)

type PrepareSyzFSArgs struct {
	Syzkaller string
	TargetOS  string
}

type PrepareSyzFSResult struct {
	SyzFS                  *syzspec.SyzFS
	DescriptionFilesPrompt string
	SkillsPrompt           string
}

func prepareSyzFSFunc(ctx *aflow.Context, args PrepareSyzFSArgs) (PrepareSyzFSResult, error) {
	if args.TargetOS == "" || args.Syzkaller == "" {
		return PrepareSyzFSResult{}, aflow.FlowError(fmt.Errorf("target OS and syzkaller path must be non-empty"))
	}
	syzFS := syzspec.NewSyzFS(args.Syzkaller, args.TargetOS)
	return PrepareSyzFSResult{
		SyzFS:                  syzFS,
		DescriptionFilesPrompt: syzlang.DescriptionFilesPrompt(syzFS),
		SkillsPrompt:           syzlang.SkillsPrompt(syzFS),
	}, nil
}

// PrepareSyzFSScratch action is like PrepareSyzFS, but the description files are served
// from a private copy that lives only for the duration of the workflow.
// It's supposed to be used for description edits.
var PrepareSyzFSScratch = aflow.NewFuncAction("prepare-syzfs-scratch", prepareSyzFSScratchFunc)

type PrepareSyzFSScratchResult struct {
	SyzFS                  *syzspec.SyzFS
	DescriptionFilesPrompt string
	// Temp dir with the copy of sys/<TargetOS>.
	DescriptionsScratchDir string
}

func prepareSyzFSScratchFunc(ctx *aflow.Context, args PrepareSyzFSArgs) (PrepareSyzFSScratchResult, error) {
	res, err := prepareSyzFSFunc(ctx, args)
	if err != nil {
		return PrepareSyzFSScratchResult{}, err
	}
	dir, err := ctx.TempDir()
	if err != nil {
		return PrepareSyzFSScratchResult{}, err
	}
	srcDir := filepath.Join(res.SyzFS.SyzkallerPath(), "sys", res.SyzFS.OSTarget())
	if err := osutil.CopyDirRecursively(srcDir, dir); err != nil {
		return PrepareSyzFSScratchResult{}, err
	}
	syzFS := res.SyzFS.WithSysDir(dir)
	return PrepareSyzFSScratchResult{
		SyzFS:                  syzFS,
		DescriptionFilesPrompt: res.DescriptionFilesPrompt,
		DescriptionsScratchDir: dir,
	}, nil
}
