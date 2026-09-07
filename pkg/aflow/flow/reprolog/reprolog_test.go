// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reprolog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestEntriesToLogPrograms(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	p1, err := target.Deserialize([]byte("test$res0()\n"), prog.Strict)
	require.NoError(t, err)
	p2, err := target.Deserialize([]byte("test$res0()\n"), prog.Strict)
	require.NoError(t, err)

	entries := []*prog.LogEntry{
		{P: p1, Proc: 0, ID: 101},
		{P: p2, Proc: 1, ID: 102},
	}

	progs, idMap := EntriesToLogPrograms(entries, []*prog.LogEntry{entries[0]})
	require.Len(t, progs, 2)
	require.Len(t, idMap, 2)

	require.NotEmpty(t, progs[0].UUID)
	require.NotEmpty(t, progs[1].UUID)
	require.NotEqual(t, progs[0].UUID, progs[1].UUID)

	require.Equal(t, 1, progs[0].Position)
	require.Equal(t, 0, progs[0].Proc)
	require.Equal(t, 101, progs[0].ExecID)
	require.Equal(t, []string{"test$res0"}, progs[0].Calls)
	require.True(t, progs[0].TestedFailed)

	require.Equal(t, 0, progs[1].Position)
	require.Equal(t, 1, progs[1].Proc)
	require.Equal(t, 102, progs[1].ExecID)
	require.Equal(t, []string{"test$res0"}, progs[1].Calls)
	require.False(t, progs[1].TestedFailed)

	filtered := FilterEntriesByUUIDs(entries, idMap, []string{progs[1].UUID})
	require.Len(t, filtered, 1)
	require.Equal(t, entries[1], filtered[0])

	filteredBoth := FilterEntriesByUUIDs(entries, idMap, []string{progs[0].UUID, progs[1].UUID})
	require.Len(t, filteredBoth, 2)
	require.Equal(t, entries[0], filteredBoth[0])
	require.Equal(t, entries[1], filteredBoth[1])
}

func TestLogConversionRoundtrip(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	rawLog := []byte(`
15s ago: executing program 0:
test$res0()
0s ago: executing program 1:
test$res0()
`)

	entries := target.ParseLog(rawLog, prog.NonStrict)
	progs, idMap := EntriesToLogPrograms(entries, nil)
	require.Len(t, progs, 2)
	require.Len(t, entries, 2)
	require.Len(t, idMap, 2)

	require.Equal(t, 1, progs[0].Position)
	require.Equal(t, "15s", progs[0].TimeBeforeCrash)

	require.Equal(t, 0, progs[1].Position)
	require.Equal(t, "0s", progs[1].TimeBeforeCrash)

	// Even if the LLM returns UUIDs in reverse order with duplicates,
	// FilterEntriesByUUIDs should return deduplicated entries in chronological order.
	filtered := FilterEntriesByUUIDs(entries, idMap, []string{progs[1].UUID, progs[0].UUID, progs[1].UUID})
	require.Len(t, filtered, 2)
	require.Equal(t, entries[0], filtered[0])
	require.Equal(t, entries[1], filtered[1])

	// Test nil entry handling in EntriesToLogPrograms.
	progsWithNil, idMapWithNil := EntriesToLogPrograms([]*prog.LogEntry{nil, entries[0], {P: nil}}, nil)
	require.Len(t, progsWithNil, 1)
	require.Len(t, idMapWithNil, 1)
}

func TestPrepareLogContext(t *testing.T) {
	programs := []ai.LogProgram{
		{
			UUID:            "uuid-1",
			Position:        1,
			TimeBeforeCrash: "5s",
			Proc:            0,
			ExecID:          100,
			Calls:           []string{"call1", "call2"},
			Prog:            "call1()\ncall2()\n",
			TestedFailed:    true,
		},
		{
			UUID:            "uuid-2",
			Position:        0,
			TimeBeforeCrash: "0s",
			Proc:            1,
			ExecID:          200,
			Calls:           []string{"call3"},
			Prog:            "call3()\n",
		},
	}

	res, err := prepareLogContextFunc(&aflow.Context{}, prepareLogContextArgs{Programs: programs})
	require.NoError(t, err)
	require.Equal(t, []string{"uuid-1", "uuid-2"}, res.ValidProgIDs)
	require.Equal(t, []string{"uuid-1"}, res.TestedProgIDs)
	require.Contains(t, res.LogOverview, "uuid-1")
	require.Contains(t, res.LogOverview, "Position 1 (5s before crash)")
	require.Contains(t, res.LogOverview, "ExecID 100")
	require.Contains(t, res.LogOverview, "[ALREADY TESTED STANDALONE: FAILED TO REPRODUCE]")
	require.Contains(t, res.LogOverview, "uuid-2")
	require.Contains(t, res.LogOverview, "Position 0 (0s before crash)")
	require.Contains(t, res.LogOverview, "ExecID 200")
	require.Contains(t, res.LogOverview, "call1, call2")
}

func TestLogTools(t *testing.T) {
	programs := []ai.LogProgram{
		{
			UUID:            "uuid-1",
			Position:        1,
			TimeBeforeCrash: "10s",
			Proc:            0,
			ExecID:          10,
			Calls:           []string{"openat", "read"},
			Prog:            "openat()\nread()\n",
		},
		{
			UUID:            "uuid-2",
			Position:        0,
			TimeBeforeCrash: "0s",
			Proc:            1,
			ExecID:          20,
			Calls:           []string{"ioctl"},
			Prog:            "ioctl()\n",
		},
	}
	state := logToolState{Programs: programs}

	t.Run("GetLogProgram_Success", func(t *testing.T) {
		aflow.TestTool(t, ToolGetLogProgram, state, getLogProgramArgs{UUID: "uuid-1"}, getLogProgramResult{
			UUID:            "uuid-1",
			Position:        1,
			TimeBeforeCrash: "10s",
			Proc:            0,
			ExecID:          10,
			Calls:           []string{"openat", "read"},
			Prog:            "openat()\nread()\n",
		}, "")
	})

	t.Run("GetLogProgram_NotFound", func(t *testing.T) {
		aflow.TestTool(t, ToolGetLogProgram, state, getLogProgramArgs{UUID: "unknown"}, getLogProgramResult{},
			`program with UUID "unknown" not found in execution log`)
	})

	t.Run("SearchLogPrograms_Match", func(t *testing.T) {
		aflow.TestTool(t, ToolSearchLogPrograms, state, searchLogProgramsArgs{Query: "openat"},
			searchLogProgramsResult{
				Matches: []searchMatch{
					{
						UUID:            "uuid-1",
						Position:        1,
						TimeBeforeCrash: "10s",
						Proc:            0,
						ExecID:          10,
						Calls:           []string{"openat", "read"},
						LineMatches:     []string{"openat()"},
					},
				},
				Count: 1,
			}, "")
	})

	t.Run("SearchLogPrograms_EmptyQuery", func(t *testing.T) {
		aflow.TestTool(t, ToolSearchLogPrograms, state, searchLogProgramsArgs{Query: "  "},
			searchLogProgramsResult{}, "query must not be empty")
	})

	t.Run("ListLogPrograms_FilterProc", func(t *testing.T) {
		proc0 := 0
		aflow.TestTool(t, ToolListLogPrograms, state, listLogProgramsArgs{Proc: &proc0},
			listLogProgramsResult{
				Programs: []programSummary{
					{
						UUID:            "uuid-1",
						Position:        1,
						TimeBeforeCrash: "10s",
						Proc:            0,
						ExecID:          10,
						Calls:           []string{"openat", "read"},
					},
				},
				Total: 1,
			}, "")
	})
}

func TestSearchLogProgramsBlobReplacementAndProximitySort(t *testing.T) {
	// A program with a huge hex blob in double quotes.
	hugeBlob := strings.Repeat("0123456789abcdef", 16) // 256 chars >= 128
	progWithBlob := "mount(&(0x7f0000000000)=\"" + hugeBlob + "\")\n"

	programs := []ai.LogProgram{
		{
			UUID:            "uuid-old",
			Position:        10,
			TimeBeforeCrash: "30s",
			Proc:            0,
			Calls:           []string{"mount"},
			Prog:            "mount()\n",
		},
		{
			UUID:            "uuid-recent",
			Position:        1,
			TimeBeforeCrash: "1s",
			Proc:            1,
			Calls:           []string{"mount"},
			Prog:            progWithBlob,
		},
	}
	state := logToolState{Programs: programs}

	res, err := searchLogProgramsFunc(nil, state, searchLogProgramsArgs{Query: "mount"})
	require.NoError(t, err)
	require.Equal(t, 2, res.Count)
	require.Len(t, res.Matches, 2)

	// Sorted closest to crash first (position 1 before position 10).
	require.Equal(t, "uuid-recent", res.Matches[0].UUID)
	require.Equal(t, 1, res.Matches[0].Position)
	require.Equal(t, "1s", res.Matches[0].TimeBeforeCrash)
	// Blob must be replaced with $BLOB placeholder.
	require.Len(t, res.Matches[0].LineMatches, 1)
	require.Contains(t, res.Matches[0].LineMatches[0], "$BLOB_")
	require.NotContains(t, res.Matches[0].LineMatches[0], hugeBlob)

	require.Equal(t, "uuid-old", res.Matches[1].UUID)
	require.Equal(t, 10, res.Matches[1].Position)
}

func TestGetLogProgramBlobReplacement(t *testing.T) {
	hugeBlob := strings.Repeat("0123456789abcdef", 16) // 256 chars >= 128
	progWithBlob := "mount(&(0x7f0000000000)=\"" + hugeBlob + "\")\n"

	state := logToolState{
		Programs: []ai.LogProgram{
			{
				UUID:            "uuid-blob",
				Position:        0,
				TimeBeforeCrash: "0s",
				Proc:            0,
				ExecID:          1,
				Calls:           []string{"mount"},
				Prog:            progWithBlob,
			},
		},
	}

	aflow.TestTool(t, ToolGetLogProgram, state, getLogProgramArgs{UUID: "uuid-blob"},
		func(got getLogProgramResult) {
			require.Equal(t, "uuid-blob", got.UUID)
			require.Contains(t, got.Prog, "$BLOB_")
			require.NotContains(t, got.Prog, hugeBlob)
		}, "")
}

func TestEntriesToLogProgramsTiming(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	p, err := target.Deserialize([]byte("test$res0()"), prog.NonStrict)
	require.NoError(t, err)

	entries := []*prog.LogEntry{
		{P: p, Proc: 0, ID: 1, Time: 15 * time.Second, HasTime: true},
		{P: p, Proc: 1, ID: 2, Time: 0, HasTime: true},
		{P: p, Proc: 2, ID: 3, HasTime: false},
	}
	progs, _ := EntriesToLogPrograms(entries, nil)
	require.Len(t, progs, 3)
	require.Equal(t, "15s", progs[0].TimeBeforeCrash)
	require.Equal(t, 2, progs[0].Position)
	require.Equal(t, "0s", progs[1].TimeBeforeCrash)
	require.Equal(t, 1, progs[1].Position)
	require.Equal(t, "", progs[2].TimeBeforeCrash)
	require.Equal(t, 0, progs[2].Position)
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input time.Duration
		want  string
	}{
		{0, "0s"},
		{-5 * time.Second, "0s"},
		{50 * time.Millisecond, "<0.1s"},
		{500 * time.Millisecond, "0.5s"},
		{2 * time.Second, "2s"},
		{9500 * time.Millisecond, "9.5s"},
		{59600 * time.Millisecond, "1m"},
		{60 * time.Second, "1m"},
		{119600 * time.Millisecond, "2m"},
		{125 * time.Second, "2m5s"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, formatDuration(tt.input))
	}
}

func TestValidateFilterAgentOutputs(t *testing.T) {
	state := filterAgentState{
		ValidProgIDs:  []string{"uuid-1", "uuid-2"},
		TestedProgIDs: []string{"uuid-1"},
	}

	t.Run("Valid", func(t *testing.T) {
		got, err := validateFilterAgentOutputs(nil, state, filterAgentOutputs{
			SelectedProgIDs: []string{"uuid-2"},
			Reasoning:       "test reason",
		})
		require.NoError(t, err)
		require.Equal(t, []string{"uuid-2"}, got.SelectedProgIDs)
		require.Equal(t, "test reason", got.Reasoning)
	})

	t.Run("TestedSingleRejected", func(t *testing.T) {
		_, err := validateFilterAgentOutputs(nil, state, filterAgentOutputs{
			SelectedProgIDs: []string{"uuid-1"},
			Reasoning:       "test reason",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "ALREADY tested in isolation")
	})

	t.Run("TestedMultipleAccepted", func(t *testing.T) {
		got, err := validateFilterAgentOutputs(nil, state, filterAgentOutputs{
			SelectedProgIDs: []string{"uuid-1", "uuid-2"},
			Reasoning:       "test reason",
		})
		require.NoError(t, err)
		require.Equal(t, []string{"uuid-1", "uuid-2"}, got.SelectedProgIDs)
	})

	t.Run("EmptyReasoning", func(t *testing.T) {
		_, err := validateFilterAgentOutputs(nil, state, filterAgentOutputs{
			SelectedProgIDs: []string{"uuid-2"},
			Reasoning:       "",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Reasoning must be provided")
	})

	t.Run("GiveUpValid", func(t *testing.T) {
		got, err := validateFilterAgentOutputs(nil, state, filterAgentOutputs{
			SelectedProgIDs: []string{},
			GiveUp:          true,
			Reasoning:       "requires physical hardware not present",
		})
		require.NoError(t, err)
		require.Empty(t, got.SelectedProgIDs)
		require.True(t, got.GiveUp)
	})

	t.Run("GiveUpWithProgsRejected", func(t *testing.T) {
		_, err := validateFilterAgentOutputs(nil, state, filterAgentOutputs{
			SelectedProgIDs: []string{"uuid-2"},
			GiveUp:          true,
			Reasoning:       "test reason",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "SelectedProgIDs must be empty when GiveUp is true")
	})

	t.Run("UnknownUUID", func(t *testing.T) {
		_, err := validateFilterAgentOutputs(nil, state, filterAgentOutputs{
			SelectedProgIDs: []string{"uuid-fake"},
			Reasoning:       "test reason",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown program UUIDs")
	})
}

type mockTester struct {
	result *TestProgramsResult
	err    error
	called []string
}

func (m *mockTester) TestPrograms(ctx context.Context, progIDs []string,
	timeout time.Duration) (*TestProgramsResult, error) {
	m.called = progIDs
	return m.result, m.err
}

func TestToolTestCandidatePrograms(t *testing.T) {
	state := testToolState{
		BugTitle:     "KASAN: slab-use-after-free in foo",
		ValidProgIDs: []string{"uuid-1", "uuid-2"},
	}

	t.Run("NoTester", func(t *testing.T) {
		ctx := aflow.NewTestContext(t)
		res, err := testCandidateProgramsFunc(ctx, state, testCandidateProgramsArgs{ProgIDs: []string{"uuid-1"}})
		require.NoError(t, err)
		require.False(t, res.Crashed)
		require.Contains(t, res.ExecutionSummary, "Interactive VM testing is not available")
	})

	t.Run("UnknownUUID", func(t *testing.T) {
		ctx := aflow.NewTestContext(t)
		_, err := testCandidateProgramsFunc(ctx, state, testCandidateProgramsArgs{ProgIDs: []string{"uuid-invalid"}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown program UUIDs")
	})

	t.Run("CrashTargetReproduced", func(t *testing.T) {
		mock := &mockTester{
			result: &TestProgramsResult{
				Crashed:     true,
				CrashTitle:  "KASAN: slab-use-after-free in foo",
				IsTargetBug: true,
				Duration:    5 * time.Second,
			},
		}
		bgCtx := ContextWithProgramTester(context.Background(), mock)
		ctx := aflow.NewTestContext(t)
		ctx.Context = bgCtx
		res, err := testCandidateProgramsFunc(ctx, state, testCandidateProgramsArgs{
			ProgIDs: []string{"uuid-1", "uuid-2"},
		})
		require.ErrorIs(t, err, ErrCrashFound)
		require.True(t, res.Crashed)
		require.True(t, res.IsTargetBug)
		require.Equal(t, "KASAN: slab-use-after-free in foo", res.CrashTitle)
		require.Equal(t, []string{"uuid-1", "uuid-2"}, mock.called)
	})

	t.Run("NoCrashReturnsSummary", func(t *testing.T) {
		mock := &mockTester{
			result: &TestProgramsResult{
				Crashed:   false,
				RawOutput: []byte("[   5.123] syz_mount_image: failed with errno 2: No such file or directory\n"),
				Duration:  10 * time.Second,
			},
		}
		bgCtx := ContextWithProgramTester(context.Background(), mock)
		ctx := aflow.NewTestContext(t)
		ctx.Context = bgCtx
		res, err := testCandidateProgramsFunc(ctx, state, testCandidateProgramsArgs{
			ProgIDs: []string{"uuid-1"},
		})
		require.NoError(t, err)
		require.False(t, res.Crashed)
		require.Contains(t, res.ExecutionSummary, "errno 2")
		require.Equal(t, 10.0, res.DurationSeconds)
	})
}

type dummyProvider struct{}

func (p *dummyProvider) Client(ctx context.Context) (backend.Client, error) {
	return nil, fmt.Errorf("dummy client error")
}

func (p *dummyProvider) Models(ctx context.Context) ([]string, error) { return nil, nil }

func (p *dummyProvider) ResolveModels(category backend.ModelCategory) []string {
	return []string{"model1"}
}

func (p *dummyProvider) Close() error { return nil }

func TestReproLogFilterFlowInputs(t *testing.T) {
	flow := aflow.Flows[string(ai.WorkflowReproLogFilter)]
	require.NotNil(t, flow)

	args := ai.ReproLogFilterArgs{
		BugTitle:    "kernel BUG in test",
		CrashReport: "kernel BUG at fs/test.c:123!",
		ConsoleLog:  "[  12.345678] test kernel console log line\n",
		Programs: []ai.LogProgram{
			{
				UUID:            "test-uuid-1",
				Position:        0,
				TimeBeforeCrash: "1.5s",
				Proc:            0,
				ExecID:          1,
				Calls:           []string{"test$res0"},
				Prog:            "test$res0()\n",
			},
		},
		KernelSrc:  "/tmp",
		Syzkaller:  "/tmp",
		TargetOS:   "linux",
		TargetArch: "amd64",
	}

	argsBytes, err := json.Marshal(args)
	require.NoError(t, err)

	var initialState map[string]any
	err = json.Unmarshal(argsBytes, &initialState)
	require.NoError(t, err)

	_, err = flow.Execute(context.Background(), initialState, aflow.ExecuteOptions{
		Provider: &dummyProvider{},
	})
	require.EqualError(t, err, "failed to initialize LLM client: dummy client error")
}
