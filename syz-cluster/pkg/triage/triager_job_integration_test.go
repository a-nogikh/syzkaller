package triage

import (
	"testing"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVerdict_Job(t *testing.T) {
	env, ctx := app.TestEnvironment(t)
	env.Config.Trees = append(env.Config.Trees, &api.Tree{
		Name: "mainline",
	})
	client := controller.TestServer(t, env)

	// Create a series and findings so we can submit a job against it.
	series := controller.DummySeries()
	seriesIDs := controller.FakeSeriesWithFindings(t, ctx, env, client, series)
	
	// Create a report based on the session.
	report := controller.UploadTestSessionReport(t, env, seriesIDs.SessionID)

	// Submit a job.
	resp, err := client.SubmitJob(ctx, &api.SubmitJobRequest{
		Type:      api.JobPatchTest,
		ReportID:  report.ID,
		Reporter:  api.LKMLReporter,
		User:      "test-user@vger.kernel.org",
		ExtID:     "test-message-id",
		PatchData: []byte("patch content"),
	})
	require.NoError(t, err)

	triager := &Triager{
		DebugTracer: &debugtracer.NullTracer{},
		Client:      client,
		Ops:         nil, // Job processing doesn't need GitTreeOps!
	}

	res, err := triager.GetVerdict(ctx, resp.SessionID)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Empty(t, res.SkipReason)
	// Expect targets since the dummy findings should yield finding groups.
	assert.NotEmpty(t, res.Targets)
	
	// Ensure the targets match the tree defined in DummyBuild.
	assert.Equal(t, "mainline", res.Targets[0].Patched.TreeName)
}
