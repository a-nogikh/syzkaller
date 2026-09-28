// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestValidateDescriptions(t *testing.T) {
	t.Parallel()
	base, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	pristineDir := filepath.Join("..", "..", "..", "sys", targets.TestOS)

	tests := []struct {
		name        string
		files       map[string]string
		edit        func(t *testing.T, dir string)
		newSyscalls []string
		problems    []string
	}{
		{
			name: "no changes",
		},
		{
			name: "new syscalls",
			files: map[string]string{
				"new.txt": `
test$new_foo(a ptr[in, new_struct], fd fd0)
syz_mmap$new(addr vma, len len[addr])

new_struct {
	f0	int32
	f1	flags[new_flags, int32]
}

new_flags = NEW_FLAG1, NEW_FLAG2
`,
				"new.txt.const": `
arches = 32, 32_fork, 64, 64_fork
NEW_FLAG1 = 1
NEW_FLAG2 = 2
`,
			},
			newSyscalls: []string{"syz_mmap$new", "test$new_foo"},
		},
		{
			name: "syntax error",
			files: map[string]string{
				"new.txt": "test$new_foo(a int32\n",
			},
			problems: []string{"parsing descriptions failed:\n" +
				"new.txt:1:21: unexpected '\\n', expecting ',', ')'"},
		},
		{
			name: "missing const",
			files: map[string]string{
				"new.txt": "test$new_foo(a const[NEW_CONST])\n",
			},
			problems: []string{"missing value for const NEW_CONST used in new.txt (add it to a .const file)"},
		},
		{
			name: "new pseudo syscall",
			files: map[string]string{
				"new.txt": "syz_new_thing(a int32)\n",
			},
			problems: []string{"syscall syz_new_thing: new pseudo-syscall syz_new_thing is not implemented " +
				"in the executor, only variants of the existing ones can be added"},
		},
		{
			name: "not generatable",
			files: map[string]string{
				"new.txt": `
resource new_res1[int32]
resource new_res2[int32]
test$new_foo1(a new_res2) new_res1
test$new_foo2(a new_res1) new_res2
`,
			},
			problems: []string{
				"new syscall test$new_foo1 can't be generated: " +
					"some of its input resources can't be created by any syscall",
				"new syscall test$new_foo2 can't be generated: " +
					"some of its input resources can't be created by any syscall",
			},
		},
		{
			name: "removed syscall",
			edit: func(t *testing.T, dir string) {
				replaceInFile(t, filepath.Join(dir, "exec.txt"), "syz_errno(v int32)\n", "")
			},
			problems: []string{"existing syscall syz_errno was removed or renamed"},
		},
		{
			name: "changed attributes",
			edit: func(t *testing.T, dir string) {
				replaceInFile(t, filepath.Join(dir, "exec.txt"),
					"(timeout[4000], no_generate", "(timeout[3000], no_generate")
			},
			problems: []string{"attributes of existing syscall syz_compare_zlib must not be changed"},
		},
		{
			name: "forbidden attributes",
			files: map[string]string{
				"new.txt": "test$new_foo(a0 intptr) (fsck[\"fsck.foo\"], snapshot, remote_cover, " +
					"timeout[5000], prog_timeout[2000])\n",
			},
			problems: []string{
				"new syscall test$new_foo: attribute fsck is not allowed",
				"new syscall test$new_foo: attribute snapshot is not allowed",
				"new syscall test$new_foo: timeout 5000 is too large (max 4000)",
				"new syscall test$new_foo: prog_timeout 2000 is too large (max 1000)",
			},
		},
		{
			name: "dir open_flags",
			files: map[string]string{
				"new.txt": `
resource fd_new_dir[int32]
openat$new_dir(fd intptr, file ptr[in, string], flags flags[open_flags], mode intptr) fd_new_dir
openat$new_file(fd fd_new_dir, file ptr[in, string], flags flags[open_flags], mode intptr)
`,
				"new.txt.const": `
arches = 32, 32_fork, 64, 64_fork
__NR_openat = 1
`,
			},
			problems: []string{
				"new syscall openat$new_dir opens a directory fd (fd_new_dir) " +
					"with flags[open_flags] (use const[O_RDONLY] or const[O_PATH] instead)",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			require.NoError(t, osutil.CopyDirRecursively(pristineDir, dir))
			for name, data := range test.files {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0644))
			}
			if test.edit != nil {
				test.edit(t, dir)
			}
			res, err := ValidateDescriptions(pristineDir, dir, base)
			if test.problems != nil {
				var verr *ValidationError
				require.ErrorAs(t, err, &verr)
				require.Equal(t, test.problems, verr.Problems)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.newSyscalls, res.NewSyscalls)
			if len(test.files) == 0 && test.edit == nil {
				require.Same(t, base, res.Target)
				require.Empty(t, res.Files)
				return
			}
			require.Equal(t, test.files, res.Files)
			for _, name := range test.newSyscalls {
				require.NotNil(t, res.Target.SyscallMap[name])
			}
		})
	}
}

func replaceInFile(t *testing.T, file, old, new string) {
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Contains(t, string(data), old)
	data = []byte(strings.Replace(string(data), old, new, 1))
	require.NoError(t, os.WriteFile(file, data, 0644))
}
