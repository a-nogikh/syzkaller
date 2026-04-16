package triage

import (
	"testing"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareJobTask(t *testing.T) {
	triager := &Triager{
		DebugTracer: &debugtracer.NullTracer{},
	}

	trees := []*api.Tree{
		{Name: "mainline"},
		{Name: "next"},
	}

	series := &api.Series{ID: "series-id"}

	tests := []struct {
		name     string
		job      *api.Job
		expected *api.TriageResult
	}{
		{
			name: "unknown tree",
			job: &api.Job{
				FindingGroups: []api.FindingGroup{
					{
						Build: api.Build{TreeName: "unknown"},
					},
				},
			},
			expected: &api.TriageResult{
				SkipReason: `tree "unknown" is no longer known`,
			},
		},
		{
			name: "no tasks",
			job: &api.Job{
				FindingGroups: []api.FindingGroup{},
			},
			expected: &api.TriageResult{
				SkipReason: "job has no testing tasks available",
			},
		},
		{
			name: "success with finding groups",
			job: &api.Job{
				ID: "job-id",
				FindingGroups: []api.FindingGroup{
					{
						Build: api.Build{
							TreeName:   "mainline",
							TreeURL:    "url",
							ConfigName: "config",
							CommitHash: "commit",
							Arch:       "amd64",
						},
						FindingIDs: []string{"finding1"},
					},
					{
						Build: api.Build{
							TreeName:   "next",
							TreeURL:    "url2",
							ConfigName: "config2",
							CommitHash: "commit2",
							Arch:       "amd64",
						},
						FindingIDs: []string{"finding2", "finding3"},
					},
				},
			},
			expected: &api.TriageResult{
				Targets: []*api.TestTarget{
					{
						Track: "build 0",
						Patched: api.BuildRequest{
							TreeName:   "mainline",
							TreeURL:    "url",
							ConfigName: "config",
							CommitHash: "commit",
							Arch:       "amd64",
							SeriesID:   "series-id",
							JobID:      "job-id",
						},
						Retest: &api.RetestTask{Findings: []string{"finding1"}},
					},
					{
						Track: "build 1",
						Patched: api.BuildRequest{
							TreeName:   "next",
							TreeURL:    "url2",
							ConfigName: "config2",
							CommitHash: "commit2",
							Arch:       "amd64",
							SeriesID:   "series-id",
							JobID:      "job-id",
						},
						Retest: &api.RetestTask{Findings: []string{"finding2", "finding3"}},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := triager.prepareJobTask(series, tc.job, trees)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, res)
		})
	}
}
