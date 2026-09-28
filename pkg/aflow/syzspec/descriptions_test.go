// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestDescriptionsScratch(t *testing.T) {
	syzDir := t.TempDir()
	srcDir := filepath.Join(syzDir, "sys", "linux")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "test"), 0755))
	writeFile(t, filepath.Join(srcDir, "a.txt"), "foo()\n")
	writeFile(t, filepath.Join(srcDir, "a.txt.const"), "arches = amd64\n")
	writeFile(t, filepath.Join(srcDir, "test", "seed"), "foo()\n")

	dstDir := t.TempDir()
	require.NoError(t, osutil.CopyDirRecursively(srcDir, dstDir))

	syzFS := NewSyzFS(syzDir, "linux").WithSysDir(dstDir)
	require.Equal(t, []string{"a.txt", "a.txt.const"}, syzFS.DescriptionFiles())
	require.Equal(t, []string{"test/seed"}, syzFS.TestSeeds())

	files, diff, err := ChangedDescriptions(srcDir, dstDir)
	require.NoError(t, err)
	require.Empty(t, files)
	require.Empty(t, diff)

	// Changes in the scratch copy must not affect the original.
	writeFile(t, filepath.Join(dstDir, "a.txt"), "foo()\nbar()\n")
	writeFile(t, filepath.Join(dstDir, "b.txt"), "baz()\n")
	writeFile(t, filepath.Join(dstDir, "c.txt"), "")
	data, err := syzFS.ReadFile("a.txt")
	require.NoError(t, err)
	require.Equal(t, "foo()\nbar()\n", string(data))
	data, err = NewSyzFS(syzDir, "linux").ReadFile("a.txt")
	require.NoError(t, err)
	require.Equal(t, "foo()\n", string(data))

	files, diff, err = ChangedDescriptions(srcDir, dstDir)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"a.txt": "foo()\nbar()\n",
		"b.txt": "baz()\n",
		"c.txt": "",
	}, files)
	require.Equal(t, `--- a/a.txt
+++ b/a.txt
@@ -1 +1,2 @@
 foo()
+bar()
--- /dev/null
+++ b/b.txt
@@ -0,0 +1,1 @@
+baz()
--- /dev/null
+++ b/c.txt
`, diff)

	require.NoError(t, os.Remove(filepath.Join(dstDir, "a.txt.const")))
	_, _, err = ChangedDescriptions(srcDir, dstDir)
	require.EqualError(t, err, "description file a.txt.const was removed")
	var verr *ValidationError
	require.ErrorAs(t, err, &verr)
}

func writeFile(t *testing.T, file, data string) {
	require.NoError(t, os.WriteFile(file, []byte(data), 0644))
}
