// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestEditSyzSpec(t *testing.T) {
	syzDir := t.TempDir()
	sysDir := filepath.Join(syzDir, "sys", targets.TestOS)
	require.NoError(t, osutil.CopyDirRecursively(filepath.Join("..", "..", "..", "..", "sys", targets.TestOS), sysDir))
	scratchDir := t.TempDir()
	require.NoError(t, osutil.CopyDirRecursively(sysDir, scratchDir))
	state := editSyzSpecState{
		SyzFS:                  syzspec.NewSyzFS(syzDir, targets.TestOS).WithSysDir(scratchDir),
		Syzkaller:              syzDir,
		TargetOS:               targets.TestOS,
		TargetArch:             targets.TestArch64,
		DescriptionsScratchDir: scratchDir,
	}
	readFile := func(name string) string {
		data, err := os.ReadFile(filepath.Join(scratchDir, name))
		require.NoError(t, err)
		return string(data)
	}

	aflow.TestTool(t, EditSyzSpec, state,
		editSyzSpecArgs{File: "new.txt", NewCode: "test$new_foo(a0 intptr)"},
		editSyzSpecResult{Output: "The edit is done. The descriptions are OK.\n" +
			"Changed files: new.txt\nNew syscalls: test$new_foo"}, "")
	require.Equal(t, "test$new_foo(a0 intptr)\n", readFile("new.txt"))

	aflow.TestTool(t, EditSyzSpec, state,
		editSyzSpecArgs{
			File:        "sys/test/new.txt",
			CurrentCode: "test$new_foo(a0 intptr)",
			NewCode:     "test$new_foo(a0 const[NEW_CONST])",
		},
		editSyzSpecResult{Output: "The edit is done, but the descriptions have problems that need to be fixed:\n" +
			"missing value for const NEW_CONST used in new.txt (add it to a .const file)"}, "")
	require.Equal(t, "test$new_foo(a0 const[NEW_CONST])\n", readFile("new.txt"))

	aflow.TestTool(t, EditSyzSpec, state,
		editSyzSpecArgs{File: "new.txt.const", NewCode: "arches = 32, 32_fork, 64, 64_fork\nNEW_CONST = 1"},
		editSyzSpecResult{Output: "The edit is done. The descriptions are OK.\n" +
			"Changed files: new.txt, new.txt.const\nNew syscalls: test$new_foo"}, "")
	require.Equal(t, "arches = 32, 32_fork, 64, 64_fork\nNEW_CONST = 1\n", readFile("new.txt.const"))

	for _, file := range []string{"auto.txt", "test/foo", "../foo.txt", "init.go", "/etc/passwd"} {
		aflow.TestTool(t, EditSyzSpec, state,
			editSyzSpecArgs{File: file, NewCode: "foo()"},
			editSyzSpecResult{}, `File "`+file+`" is not an editable description file: `+
				`provide a base file name with .txt or .txt.const extension (auto.txt can't be edited)`)
	}
	aflow.TestTool(t, EditSyzSpec, state,
		editSyzSpecArgs{File: "missing.txt", CurrentCode: "foo()", NewCode: "bar()"},
		editSyzSpecResult{}, `File "missing.txt" does not exist, to create it, `+
			`provide empty CurrentCode and the full file contents as NewCode`)
	aflow.TestTool(t, EditSyzSpec, state,
		editSyzSpecArgs{File: "new.txt", NewCode: "bar()"},
		editSyzSpecResult{}, `File "new.txt" already exists, provide CurrentCode to edit it`)
}
