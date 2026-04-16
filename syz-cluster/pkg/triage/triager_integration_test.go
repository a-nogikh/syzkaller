package triage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVerdict_Series(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	client := controller.TestServer(t, env)

	// Set up the fake Git repository.
	baseDir := t.TempDir()
	repo := vcs.MakeTestRepo(t, baseDir)
	osutil.WriteFile(filepath.Join(baseDir, "file.txt"), []byte("First\nSecond\nThird\n"))
	repo.Git("add", "file.txt")
	base := repo.CommitChange("base")
	repo.SetTag("test-tree/master")

	// The app environment's config needs to know about our tree.
	env.Config.Trees = []*api.Tree{
		{Name: "test-tree", URL: "http://test", Branch: "master"},
	}
	env.Config.FuzzTargets = []*api.FuzzTriageTarget{
		{EmailLists: []string{"test@email"}, Campaigns: []*api.KernelFuzzConfig{{Track: "test-track"}}},
	}

	ops, err := NewGitTreeOps(baseDir, false)
	require.NoError(t, err)

	series := &api.Series{
		ExtID:       "ext-id",
		Title:       "test series",
		Cc:          []string{"test@email"},
		PublishedAt: time.Now(),
		Patches: []api.SeriesPatch{
			{
				Body: []byte(`From 708670e05c0462d3783f774cef82f9a3b3099f9a Mon Sep 17 00:00:00 2001
From: Test Syzkaller <test@syzkaller.com>
Date: Tue, 10 Dec 2024 17:57:37 +0100
Subject: [PATCH] change1

---
 file.txt | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/file.txt b/file.txt
index ab7c514..97c39a4 100644
--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
-First
+First1
 Second
-Third
+Third1
--
`),
			},
		},
		BaseCommitHint: base.Hash,
	}

	// Upload the series to the database via API.
	ids := controller.UploadTestSeries(t, ctx, client, series)

	triager := &Triager{
		DebugTracer: &debugtracer.NullTracer{},
		Client:      client,
		Ops:         ops,
	}

	res, err := triager.GetVerdict(ctx, ids.SessionID)
	require.NoError(t, err)
	require.NotNil(t, res)

	// We expect the series to be accepted for fuzzing, pointing to our tree.
	assert.Empty(t, res.SkipReason)
	assert.Len(t, res.Targets, 1)

	target := res.Targets[0]
	assert.Equal(t, "test-tree", target.Base.TreeName)
	assert.Equal(t, base.Hash, target.Base.CommitHash)
}
