// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/require"
)

func TestShouldSkipCrash(t *testing.T) {
	tests := []struct {
		title string
		skip  bool
	}{
		{"", true},
		{"syzfail: failed to boot VM", true},
		{"SYZFATAL: executor died", true},
		{"lost connection to test machine", true},
		{"Lost Connection to test machine", true},
		{"no output from test machine", true},
		{"No Output from test machine", true},
		{"BUG: MAX_LOCKDEP_KEYS too low!", true},
		{"bug: max_lockdep_keys too low!", true},
		{"KASAN: slab-out-of-bounds in test_function", false},
		{"BUG: unable to handle kernel paging request in foo", false},
		{"WARNING: refcount leak in bar", false},
	}
	for _, tt := range tests {
		got := ShouldSkipCrash(tt.title)
		require.Equal(t, tt.skip, got, "title: %q", tt.title)
	}
}

func TestDiscoverBugs(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)

	workdir := t.TempDir()
	crashesDir := filepath.Join(workdir, "crashes")
	require.NoError(t, os.MkdirAll(crashesDir, 0755))

	progBytes := target.DataMmapProg().Serialize()
	validLog := fmt.Sprintf("executing program 0:\n%s\nkernel console output:\n[ 1.0] BUG: test", progBytes)

	crashes := map[string]struct {
		desc string
		log  string
	}{
		"c1": {"KASAN: use-after-free in foo", validLog},
		"c2": {"syzfatal: executor died", validLog},
		"c3": {"lost connection to test machine", validLog},
		"c4": {"no output from test machine", validLog},
		"c5": {"WARNING: lockdep warning", ""},              // empty log.
		"c6": {"WARNING: uninit value", "some junk output"}, // no progs.
		"c7": {"BUG: bad page state", validLog},
	}

	for id, c := range crashes {
		dir := filepath.Join(crashesDir, id)
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "description"), []byte(c.desc+"\n"), 0644))
		if c.log != "" {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "log0"), []byte(c.log), 0644))
		}
	}

	bugs, err := DiscoverBugs(workdir, target)
	require.NoError(t, err)
	require.Len(t, bugs, 2)

	// Sorted by title: "BUG: bad page state", then "KASAN: use-after-free in foo".
	require.Equal(t, "c7", bugs[0].ID)
	require.Equal(t, "BUG: bad page state", bugs[0].Title)
	require.Equal(t, "c1", bugs[1].ID)
	require.Equal(t, "KASAN: use-after-free in foo", bugs[1].Title)
}

func TestFilterLog(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)

	p := target.DataMmapProg()
	pBytes := p.Serialize()

	// Create a log with 10 programs for proc 0 and 10 programs for proc 1, interleaved.
	var logBuf bytes.Buffer
	for range 10 {
		fmt.Fprintf(&logBuf, "executing program 0:\n%s", pBytes)
		fmt.Fprintf(&logBuf, "executing program 1:\n%s", pBytes)
	}
	const consolePart = "kernel console output (not intermixed with test programs):\n\n[ 10.0] BUG: test panic\n"
	logBuf.WriteString(consolePart)
	rawLog := logBuf.Bytes()

	// Initial check: rawLog has 20 programs.
	initialEntries := target.ParseLog(rawLog, prog.NonStrict)
	require.Len(t, initialEntries, 20)

	// Test maxPerProc = 6: should keep 6 for proc 0 + 6 for proc 1 = 12 programs.
	filtered6 := FilterLog(target, nil, rawLog, 6)
	entries6 := target.ParseLog(filtered6, prog.NonStrict)
	require.Len(t, entries6, 12)
	p0Count, p1Count := 0, 0
	for _, ent := range entries6 {
		switch ent.Proc {
		case 0:
			p0Count++
		case 1:
			p1Count++
		}
	}
	require.Equal(t, 6, p0Count)
	require.Equal(t, 6, p1Count)
	// Check that the console output banner and BUG text are preserved at the end.
	require.Contains(t, string(filtered6), consolePart)

	// Test maxPerProc = 25: since 10 < 25, all 20 programs should be retained.
	filtered25 := FilterLog(target, nil, rawLog, 25)
	entries25 := target.ParseLog(filtered25, prog.NonStrict)
	require.Len(t, entries25, 20)
	require.Contains(t, string(filtered25), consolePart)

	// Test maxPerProc = 0: raw log as is.
	filteredRaw := FilterLog(target, nil, rawLog, 0)
	require.Equal(t, rawLog, filteredRaw)
}

func TestReproExpExecutionAndPersistence(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)

	sourceWorkdir := t.TempDir()
	actualWorkdir := t.TempDir()

	crashesDir := filepath.Join(sourceWorkdir, "crashes")
	require.NoError(t, os.MkdirAll(crashesDir, 0755))

	pBytes := target.DataMmapProg().Serialize()
	validLog := fmt.Sprintf("executing program 0:\n%s\nkernel console output:\n[ 1.0] BUG: test", pBytes)

	// Create 2 bugs in the read-only source workdir.
	for _, id := range []string{"crash1", "crash2"} {
		dir := filepath.Join(crashesDir, id)
		require.NoError(t, os.MkdirAll(dir, 0755))
		title := "BUG: crash " + id
		require.NoError(t, os.WriteFile(filepath.Join(dir, "description"), []byte(title+"\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "log0"), []byte(validLog), 0644))
	}

	cfg := &mgrconfig.Config{
		Workdir: actualWorkdir,
		Derived: mgrconfig.Derived{
			Target: target,
		},
	}

	exp := NewReproExp(cfg, sourceWorkdir, nil, nil)

	// Mock runRepro:
	// For crash1 + 6_progs -> C repro.
	// For crash1 + 25_progs_sliding -> syz repro.
	// For crash2 + 6_progs -> error.
	// For others -> failed (no repro).
	callCount := 0
	exp.runRepro = func(ctx context.Context, log []byte, cfg ReproConfig) (*repro.Result, *repro.Stats, error) {
		callCount++
		stats := &repro.Stats{Log: []byte("mock repro output")}
		if callCount == 1 {
			return &repro.Result{CRepro: true, Report: &report.Report{Title: "BUG: crash crash1"}}, stats, nil
		}
		if callCount == 2 {
			return &repro.Result{CRepro: false, Report: &report.Report{Title: "BUG: crash crash1"}}, stats, nil
		}
		if callCount == 6 {
			return nil, nil, fmt.Errorf("machine boot failed")
		}
		return nil, stats, nil
	}

	require.NoError(t, exp.Init())
	exp.Run(context.Background())

	// Total jobs = 2 bugs * 5 configs = 10 jobs.
	require.Equal(t, 10, callCount)

	// Verify sourceWorkdir was NOT modified (no repro-exp dir written there).
	require.NoFileExists(t, filepath.Join(sourceWorkdir, "repro-exp"))

	// Verify state and status files were written in actualWorkdir.
	statePath := filepath.Join(actualWorkdir, "repro-exp", "state.json")
	require.FileExists(t, statePath)
	statusPath := filepath.Join(actualWorkdir, "repro-exp", "status.json")
	require.FileExists(t, statusPath)

	// Verify UI table output.
	ui := exp.UI()
	require.Len(t, ui.Columns, 5)
	require.Len(t, ui.Rows, 2)
	require.Len(t, ui.Stats, 5)

	// Check that per-job folders exist with both truncated.log and repro.log.
	for _, row := range ui.Rows {
		for _, cell := range row.Cells {
			require.NotEmpty(t, cell.LogPath)
			absReproLog := filepath.Join(actualWorkdir, cell.LogPath)
			require.FileExists(t, absReproLog)

			require.NotEmpty(t, cell.TruncatedLog)
			absTruncatedLog := filepath.Join(actualWorkdir, cell.TruncatedLog)
			require.FileExists(t, absTruncatedLog)
		}
	}

	// Now simulate restart:
	// Create a new ReproExp on the same workdirs.
	expRestart := NewReproExp(cfg, sourceWorkdir, nil, nil)
	// Mock runner should NOT be called because all 10 jobs were already completed!
	expRestart.runRepro = func(ctx context.Context, log []byte, cfg ReproConfig) (*repro.Result, *repro.Stats, error) {
		t.Fatalf("runRepro should not be called for already completed jobs!")
		return nil, nil, nil
	}

	require.NoError(t, expRestart.Init())
	expRestart.Run(context.Background())

	// UI on restart should still have the loaded results!
	uiRestart := expRestart.UI()
	require.Len(t, uiRestart.Rows, 2)
	require.Equal(t, ui.Stats, uiRestart.Stats)
}

func TestReproConfigs(t *testing.T) {
	require.Len(t, ReproConfigs, 5)
	expectedKeys := []string{"6_progs", "25_progs_sliding", "as_is", "as_is_sliding", "as_is_sliding_exact"}
	expectedExact := []bool{false, false, false, false, true}
	for i, cfg := range ReproConfigs {
		require.Equal(t, expectedKeys[i], cfg.Key)
		require.Equal(t, expectedExact[i], cfg.ExactCrash)
	}
}

func TestExecuteJobTitleMatching(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)

	workdir := t.TempDir()
	cfg := &mgrconfig.Config{
		Workdir: workdir,
		Derived: mgrconfig.Derived{
			Target: target,
		},
	}

	tests := []struct {
		name       string
		bugTitle   string
		bugAlt     []string
		reproTitle string
		reproAlt   []string
		wantStatus string
		wantC      bool
	}{
		{
			name:       "exact match",
			bugTitle:   "KASAN: slab-out-of-bounds in test",
			reproTitle: "KASAN: slab-out-of-bounds in test",
			wantStatus: ReproStatusCRepro,
			wantC:      true,
		},
		{
			name:       "alt title match in repro",
			bugTitle:   "KASAN: slab-out-of-bounds in test",
			reproTitle: "BUG: unable to handle kernel paging request",
			reproAlt:   []string{"KASAN: slab-out-of-bounds in test"},
			wantStatus: ReproStatusCRepro,
			wantC:      true,
		},
		{
			name:       "alt title match in bug",
			bugTitle:   "BUG: unable to handle kernel paging request",
			bugAlt:     []string{"KASAN: slab-out-of-bounds in test"},
			reproTitle: "KASAN: slab-out-of-bounds in test",
			wantStatus: ReproStatusCRepro,
			wantC:      true,
		},
		{
			name:       "unrelated crash rejected",
			bugTitle:   "KASAN: slab-out-of-bounds in test",
			reproTitle: "WARNING: refcount leak in other",
			wantStatus: ReproStatusFailed,
			wantC:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp := NewReproExp(cfg, workdir, nil, nil)
			exp.runRepro = func(ctx context.Context, log []byte, cfg ReproConfig) (*repro.Result, *repro.Stats, error) {
				return &repro.Result{
					CRepro: true,
					Report: &report.Report{
						Title:     tt.reproTitle,
						AltTitles: tt.reproAlt,
					},
				}, &repro.Stats{}, nil
			}
			exp.state.Bugs = []*ReproExpBugState{
				{
					ID:      "crash1",
					Title:   tt.bugTitle,
					Results: make(map[string]*ReproJobState),
				},
			}
			bug := &BugEntry{
				ID:        "crash1",
				Title:     tt.bugTitle,
				AltTitles: tt.bugAlt,
				Log:       []byte("executing program 0:\ngetpid()\n"),
			}
			exp.executeJob(context.Background(), bug, ReproConfigs[0])
			res := exp.state.Bugs[0].Results[ReproConfigs[0].Key]
			require.Equal(t, tt.wantStatus, res.Status)
			require.Equal(t, tt.wantC, res.CRepro)
		})
	}
}

func TestReproExpConcurrencyCalculation(t *testing.T) {
	tests := []struct {
		vmCount     int
		concurrency int
	}{
		{1, 1},
		{2, 1},
		{3, 2},
		{4, 3},
		{5, 4},
		{8, 6},
		{10, 8},
		{16, 12},
		{32, 25},
	}
	for _, tt := range tests {
		got := max(1, int(float64(tt.vmCount)/1.25))
		require.Equal(t, tt.concurrency, got, "vmCount: %d", tt.vmCount)
	}
}
