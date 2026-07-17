package patching

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

func TestLightweightClangFormat(t *testing.T) {
	files, err := filepath.Glob("testdata/clang_format/*")
	require.NoError(t, err)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			content, err := os.ReadFile(file)
			require.NoError(t, err)

			parts := strings.Split(string(content), "======\n")
			require.Len(t, parts, 3, "invalid test file format: expected 3 parts")

			base := parts[0]
			diffBefore := strings.TrimSpace(parts[1])
			diffAfterExpected := strings.TrimSpace(parts[2])

			repo := vcs.MakeTestRepo(t, t.TempDir())
			filePath := filepath.Join(repo.Dir, "fuse.c")

			// Write base and commit.
			err = os.WriteFile(filePath, []byte(base), 0644)
			require.NoError(t, err)
			repo.Git("add", "fuse.c")
			repo.Git("commit", "-m", "base")

			if diffBefore != "" {
				cmd := osutil.Command("git", "apply", "--unidiff-zero")
				cmd.Dir = repo.Dir
				cmd.Stdin = strings.NewReader(diffBefore + "\n")
				_, err = osutil.Run(time.Minute, cmd)
				require.NoError(t, err, "git apply failed")
			}

			// Run lightweightClangFormat.
			err = applyLightweightClangFormat(repo.Dir)
			require.NoError(t, err)

			diff, err := osutil.RunCmd(time.Minute, repo.Dir, "git", "diff", "HEAD")
			require.NoError(t, err)

			diffStr := strings.TrimSpace(string(diff))
			require.Equal(t, diffAfterExpected, diffStr, "formatting mismatch")
		})
	}
}
