package patching

import (
	"bytes"
	_ "embed"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/tool/checkpatch"
	"github.com/google/syzkaller/pkg/aflow/tool/codeeditor"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/patchdiff"
	"github.com/google/syzkaller/pkg/osutil"
)

func formatPatchFlow() aflow.Action {
	return aflow.Pipeline(
		lightweightClangFormat,
		&aflow.DoWhile{
			While:         "CheckpatchErrors",
			MaxIterations: 10,
			Do: aflow.Pipeline(
				getPatchDiff,
				&aflow.LLMAgent{
					Name:        "patch-formatter",
					Model:       aflow.GoodBalancedModel,
					Reply:       "FormatExplanation",
					TaskType:    aflow.FormalReasoningTask,
					Instruction: formatInstruction,
					Prompt:      formatPrompt,
					Tools:       aflow.Tools(codesearcher.FilesystemTools, codeeditor.Tool, patchdiff.Tool, checkpatch.Tool),
				},
				dropFormatOutputs,
				runCheckpatch,
			),
		},
		dropCheckpatchErrors,
	)
}

//go:embed lightweight.clang-format
var lightweightClangFormatStyle string

var lightweightClangFormat = aflow.NewFuncAction("lightweight-clang-format", func(ctx *aflow.Context, args struct {
	KernelScratchSrc string
}) (struct{}, error) {
	return struct{}{}, applyLightweightClangFormat(args.KernelScratchSrc)
})

func applyLightweightClangFormat(repo string) error {
	diff, err := patchdiff.Diff(repo, "HEAD", "-U0")
	if err != nil {
		return err
	}
	if len(diff) == 0 {
		return nil
	}

	formatDiff, err := findClangFormatDiff()
	if err != nil {
		return err
	}

	cmd := exec.Command(formatDiff, "-p1", "-i", "-style="+lightweightClangFormatStyle)
	cmd.Stdin = bytes.NewReader(diff)
	cmd.Dir = repo
	if output, err := osutil.Run(10*time.Minute, cmd); err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

func findClangFormatDiff() (string, error) {
	paths := []string{
		"/usr/lib/clang-format*/clang-format-diff.py",
		"/usr/share/clang/clang-format*/clang-format-diff.py",
	}
	for _, path := range paths {
		files, _ := filepath.Glob(path)
		if len(files) == 0 {
			continue
		}
		slices.Sort(files)
		return files[len(files)-1], nil
	}
	return "", fmt.Errorf("can't find clang-format-diff.py, install clang-format package")
}

const formatInstruction = `
You are an experienced Linux kernel developer tasked with formatting a kernel patch.
The patch has already been generated and modified, and a lightweight clang-format has been applied to it.
Your objective is purely formatting: ensure that the patch complies with the kernel's coding style and checkpatch.pl.
Do not think about the patch logic itself, but you MUST preserve the code logic exactly as it is.

Stop once the requested formatting changes are done.
Do not question the requested changes unless they are obviously wrong.
If the code already conforms to the requested changes and checkpatch.pl is happy,
just finish your task.

Use the {{.toolCodeeditor}} tool to do code edits.
Note: you will not see your changes when looking at the code using codesearch tools.
Use the {{.toolPatchDiff}} tool to review the modifications you applied.
Use the {{.toolCheckpatch}} tool to verify that your code modifications comply with the kernel's coding style.
If checkpatch.pl reports errors or warnings, you must fix them before finishing your task.
CRITICAL: checkpatch.pl notes are more important than user comments. Always prioritize fixing checkpatch.pl errors.
Pay special attention to using tabs instead of spaces for indentation, aligning struct fields properly,
and keeping lines within the 100-character limit.

Make sure to adjust the patch to match the surrounding code,
and ensure formatting did not change from the previous code significantly without any important reasons,
until there are no unnecessary changes to the surrounding code and the fix fits it completely.

Your final reply should contain an explanation of what formatting changes you made.
`

const formatPrompt = `
The patch currently applied to the tree is:

{{.CurrentPatchDiff}}

{{if .StyleItems}}
The reviewers have previously provided the following feedback regarding the code style:
{{range $item := .StyleItems}}
- {{$item}}
{{end}}
{{end}}

{{if .CheckpatchErrors}}
The checkpatch.pl script reported the following errors/warnings:
{{.CheckpatchErrors}}
{{end}}

Please use the checkpatch tool to find any remaining style issues and fix them.
`

var getPatchDiff = aflow.NewFuncAction("get-patch-diff", func(ctx *aflow.Context, args struct {
	KernelScratchSrc string
}) (struct {
	CurrentPatchDiff string
}, error) {
	diff, err := patchdiff.Diff(args.KernelScratchSrc, "HEAD")
	if err != nil {
		return struct{ CurrentPatchDiff string }{}, err
	}
	return struct{ CurrentPatchDiff string }{CurrentPatchDiff: string(diff)}, nil
})

var dropFormatOutputs = aflow.NewFuncAction("drop-format-outputs", func(ctx *aflow.Context, args struct {
	FormatExplanation string
	CurrentPatchDiff  string
}) (struct{}, error) {
	return struct{}{}, nil
})

var runCheckpatch = aflow.NewFuncAction("run-checkpatch", func(ctx *aflow.Context, args struct {
	KernelScratchSrc string
}) (struct {
	CheckpatchErrors string
}, error) {
	diff, err := patchdiff.Diff(args.KernelScratchSrc, "HEAD")
	if err != nil {
		return struct{ CheckpatchErrors string }{}, err
	}

	cmd := osutil.Command("./scripts/checkpatch.pl", "--no-tree", "--no-signoff",
		"--ignore", "COMMIT_MESSAGE,GIT_COMMIT_ID", "-")
	cmd.Dir = args.KernelScratchSrc
	cmd.Stdin = bytes.NewReader(diff)
	output, _ := osutil.Run(time.Minute, cmd)

	// checkpatch.pl returns 0 if no errors/warnings, otherwise non-zero.
	// We can just check if the output contains "total: 0 errors, 0 warnings".
	if bytes.Contains(output, []byte("total: 0 errors, 0 warnings")) {
		return struct{ CheckpatchErrors string }{}, nil
	}
	return struct{ CheckpatchErrors string }{CheckpatchErrors: string(output)}, nil
})

var dropCheckpatchErrors = aflow.NewFuncAction("drop-checkpatch-errors", func(ctx *aflow.Context, args struct {
	CheckpatchErrors string
}) (struct{}, error) {
	return struct{}{}, nil
})
