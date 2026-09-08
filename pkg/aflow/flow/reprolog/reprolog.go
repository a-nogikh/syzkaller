// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package reprolog provides an aflow workflow and tools for filtering crash log programs.
package reprolog

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/prog"
	"github.com/google/uuid"
)

func init() {
	aflow.Register[ai.ReproLogFilterArgs, ai.ReproLogFilterResult](
		ai.WorkflowReproLogFilter,
		"Pre-filter syzkaller execution log programs to identify likely causes of a kernel crash",
		reproLogFilterFlow(),
	)
}

func reproLogFilterFlow() *aflow.Flow {
	return &aflow.Flow{
		Root: aflow.Pipeline(
			actionsyzlang.PrepareSyzFS,
			actionPrepareLogContext,
			reproLogFilterAgent,
		),
	}
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < 100*time.Millisecond {
		return "<0.1s"
	}
	if d < 10*time.Second {
		sec := d.Seconds()
		if d%time.Second == 0 {
			return fmt.Sprintf("%ds", int(sec))
		}
		return fmt.Sprintf("%.1fs", sec)
	}
	totalSec := int(d.Round(time.Second).Seconds())
	m := totalSec / 60
	s := totalSec % 60
	if m == 0 {
		return fmt.Sprintf("%ds", s)
	}
	if s == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dm%ds", m, s)
}

func replaceBlobs(ctx *aflow.Context, text string) string {
	if ctx != nil {
		return ctx.ReplaceBlobs(text)
	}
	var store syzspec.BlobStore
	return store.ReplaceBlobs(text)
}

// EntriesToLogPrograms converts a slice of parsed prog.LogEntry items to ai.LogProgram structs
// with assigned UUIDs, Position counted backwards from the crash (0 = last program before crash),
// optional TimeBeforeCrash (from ent.Time if present), and marks whether any entry was already tested standalone.
// Returns the converted programs and a lookup map from UUID to the original LogEntry.
func EntriesToLogPrograms(entries, tested []*prog.LogEntry) ([]ai.LogProgram, map[string]*prog.LogEntry) {
	var validEntries []*prog.LogEntry
	for _, ent := range entries {
		if ent != nil && ent.P != nil {
			validEntries = append(validEntries, ent)
		}
	}

	testedMap := make(map[*prog.LogEntry]bool, len(tested))
	for _, ent := range tested {
		testedMap[ent] = true
	}

	n := len(validEntries)
	progs := make([]ai.LogProgram, 0, n)
	idMap := make(map[string]*prog.LogEntry, n)

	for i, ent := range validEntries {
		id := uuid.New().String()
		idMap[id] = ent
		callNames := make([]string, 0, len(ent.P.Calls))
		for _, c := range ent.P.Calls {
			callNames = append(callNames, c.Meta.Name)
		}
		var timeStr string
		if ent.HasTime {
			timeStr = formatDuration(ent.Time)
		}
		progs = append(progs, ai.LogProgram{
			UUID:            id,
			Position:        n - 1 - i,
			TimeBeforeCrash: timeStr,
			Proc:            ent.Proc,
			ExecID:          ent.ID,
			Calls:           callNames,
			Prog:            string(ent.P.Serialize()),
			TestedFailed:    testedMap[ent],
		})
	}
	return progs, idMap
}

// FilterEntriesByUUIDs returns the subset of entries matching the specified UUIDs,
// preserving the original chronological execution order from entries and deduplicating UUIDs.
func FilterEntriesByUUIDs(entries []*prog.LogEntry, idMap map[string]*prog.LogEntry,
	selectedIDs []string) []*prog.LogEntry {
	selected := make(map[*prog.LogEntry]bool, len(selectedIDs))
	for _, id := range selectedIDs {
		if ent, ok := idMap[id]; ok && ent != nil {
			selected[ent] = true
		}
	}
	var result []*prog.LogEntry
	for _, ent := range entries {
		if selected[ent] {
			result = append(result, ent)
		}
	}
	return result
}

type prepareLogContextArgs struct {
	Programs []ai.LogProgram
}

type prepareLogContextResult struct {
	LogOverview   string
	ValidProgIDs  []string
	TestedProgIDs []string
}

var actionPrepareLogContext = aflow.NewFuncAction("prepare-log-context", prepareLogContextFunc)

func prepareLogContextFunc(ctx *aflow.Context, args prepareLogContextArgs) (prepareLogContextResult, error) {
	validIDs := make([]string, 0, len(args.Programs))
	var testedIDs []string
	for _, p := range args.Programs {
		validIDs = append(validIDs, p.UUID)
		if p.TestedFailed {
			testedIDs = append(testedIDs, p.UUID)
		}
	}

	var overview strings.Builder
	const maxDirectOverview = 50
	displayProgs := args.Programs
	if len(displayProgs) > maxDirectOverview {
		fmt.Fprintf(&overview, "Total programs in log: %d. Showing the last %d programs closest to the crash:\n",
			len(args.Programs), maxDirectOverview)
		displayProgs = displayProgs[len(displayProgs)-maxDirectOverview:]
	} else {
		fmt.Fprintf(&overview, "Total programs in log: %d:\n", len(args.Programs))
	}

	for _, p := range displayProgs {
		timing := ""
		if p.TimeBeforeCrash != "" {
			timing = fmt.Sprintf(" (%s before crash)", p.TimeBeforeCrash)
		}
		testedTag := ""
		if p.TestedFailed {
			testedTag = " [ALREADY TESTED STANDALONE: FAILED TO REPRODUCE]"
		}
		fmt.Fprintf(&overview, "- UUID: %s [Position %d%s, Proc %d, ExecID %d]%s: %s\n",
			p.UUID, p.Position, timing, p.Proc, p.ExecID, testedTag, strings.Join(p.Calls, ", "))
	}

	if len(args.Programs) > maxDirectOverview {
		overview.WriteString(
			"\nNote: Earlier programs can be found using the search-log-programs or list-log-programs tools.\n")
	}

	return prepareLogContextResult{
		LogOverview:   overview.String(),
		ValidProgIDs:  validIDs,
		TestedProgIDs: testedIDs,
	}, nil
}

// Log inspection tools.

type logToolState struct {
	Programs []ai.LogProgram
}

type getLogProgramArgs struct {
	UUID string `jsonschema:"The UUID of the program from the execution log to inspect."`
}

type getLogProgramResult struct {
	UUID            string   `jsonschema:"The UUID of the program."`
	Position        int      `jsonschema:"0-based position counted backwards from crash (0 = last program before crash)."`
	TimeBeforeCrash string   `jsonschema:"Approximate time before crash (e.g. '3.5s')." json:",omitempty"`
	Proc            int      `jsonschema:"The parallel process ID that executed the program."`
	ExecID          int      `jsonschema:"The execution ID of the program." json:",omitempty"`
	Calls           []string `jsonschema:"The list of system calls executed by the program."`
	Prog            string   `jsonschema:"The full serialized syzlang text of the program with blobs replaced."`
	TestedFailed    bool     `json:",omitempty" jsonschema:"Whether program failed standalone repro."`
}

var ToolGetLogProgram = aflow.NewFuncTool("get-log-program", getLogProgramFunc, `
Retrieve the full syzlang source text and metadata of an execution log program by its UUID.
Large binary blobs are replaced with placeholders.
Use this tool to closely inspect the syscall arguments, resources, and configurations of candidate programs.
`)

func getLogProgramFunc(ctx *aflow.Context, state logToolState, args getLogProgramArgs) (getLogProgramResult, error) {
	for _, p := range state.Programs {
		if p.UUID == args.UUID {
			return getLogProgramResult{
				UUID:            p.UUID,
				Position:        p.Position,
				TimeBeforeCrash: p.TimeBeforeCrash,
				Proc:            p.Proc,
				ExecID:          p.ExecID,
				Calls:           p.Calls,
				Prog:            replaceBlobs(ctx, p.Prog),
				TestedFailed:    p.TestedFailed,
			}, nil
		}
	}
	return getLogProgramResult{}, aflow.BadCallError("program with UUID %q not found in execution log", args.UUID)
}

type searchLogProgramsArgs struct {
	Query string `jsonschema:"Regex pattern to search for within log programs (e.g. syscall name, constant, or argument)."`
}

type searchMatch struct {
	UUID            string   `jsonschema:"The UUID of the matching program."`
	Position        int      `jsonschema:"0-based position counted backwards from crash (0 = last program before crash)."`
	TimeBeforeCrash string   `jsonschema:"Approximate time before crash (e.g. '3.5s')." json:",omitempty"`
	Proc            int      `jsonschema:"The parallel process ID that executed the program."`
	ExecID          int      `jsonschema:"The execution ID of the program." json:",omitempty"`
	Calls           []string `jsonschema:"List of syscall names in the program."`
	LineMatches     []string `jsonschema:"Lines with large binary blobs replaced."`
	TestedFailed    bool     `json:",omitempty" jsonschema:"Whether program failed standalone repro."`
}

type searchLogProgramsResult struct {
	Matches []searchMatch `jsonschema:"List of matching programs and lines, sorted closest to the crash first."`
	Count   int           `jsonschema:"Total number of matching programs."`
}

var ToolSearchLogPrograms = aflow.NewFuncTool("search-log-programs", searchLogProgramsFunc, `
Search across all programs in the execution log using a regular expression.
Returns matching program UUIDs, execution proximity/timing, and matching lines with large binary blobs replaced.
Matches are sorted by proximity to the crash (closest first).
Use this to find programs that call specific syscalls (e.g. 'bpf', 'mount'), open devices, or use flags.
`)

func searchLogProgramsFunc(ctx *aflow.Context, state logToolState,
	args searchLogProgramsArgs) (searchLogProgramsResult, error) {
	if strings.TrimSpace(args.Query) == "" {
		return searchLogProgramsResult{}, aflow.BadCallError("query must not be empty")
	}
	re, err := regexp.Compile(args.Query)
	if err != nil {
		return searchLogProgramsResult{}, aflow.BadCallError("invalid regular expression %q: %v", args.Query, err)
	}

	const maxMatches = 50
	const maxLinesPerProg = 10
	const maxLineLen = 500

	var matches []searchMatch
	for _, p := range state.Programs {
		var lineMatches []string
		for line := range strings.SplitSeq(p.Prog, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && re.MatchString(line) {
				lineMatches = append(lineMatches, line)
				if len(lineMatches) >= maxLinesPerProg {
					break
				}
			}
		}
		if len(lineMatches) > 0 {
			matches = append(matches, searchMatch{
				UUID:            p.UUID,
				Position:        p.Position,
				TimeBeforeCrash: p.TimeBeforeCrash,
				Proc:            p.Proc,
				ExecID:          p.ExecID,
				Calls:           p.Calls,
				LineMatches:     lineMatches,
				TestedFailed:    p.TestedFailed,
			})
		}
	}

	slices.SortFunc(matches, func(a, b searchMatch) int {
		return cmp.Compare(a.Position, b.Position)
	})

	total := len(matches)
	if len(matches) > maxMatches {
		matches = matches[:maxMatches]
	}
	for i := range matches {
		for j, line := range matches[i].LineMatches {
			line = replaceBlobs(ctx, line)
			if len(line) > maxLineLen {
				line = strings.ToValidUTF8(line[:maxLineLen], "") + "...[truncated]"
			}
			matches[i].LineMatches[j] = line
		}
	}
	return searchLogProgramsResult{
		Matches: matches,
		Count:   total,
	}, nil
}

type listLogProgramsArgs struct {
	Proc   *int   `jsonschema:"Optional filter by proc index (leave null/empty for all procs)." json:",omitempty"`
	Call   string `jsonschema:"Optional substring filter for syscall names in programs." json:",omitempty"`
	Offset int    `jsonschema:"0-based pagination offset (ordered by Position closest to crash first)." json:",omitempty"`
	Limit  int    `jsonschema:"Maximum number of program summaries to return (default 30, max 100)." json:",omitempty"`
}

type programSummary struct {
	UUID            string   `jsonschema:"The UUID of the program."`
	Position        int      `jsonschema:"0-based position counted backwards from crash (0 = last program before crash)."`
	TimeBeforeCrash string   `jsonschema:"Approximate time before crash (e.g. '3.5s')." json:",omitempty"`
	Proc            int      `jsonschema:"The process ID that executed the program."`
	ExecID          int      `jsonschema:"The execution ID of the program." json:",omitempty"`
	Calls           []string `jsonschema:"List of system calls in the program."`
	TestedFailed    bool     `json:",omitempty" jsonschema:"Whether program failed standalone repro."`
}

type listLogProgramsResult struct {
	Programs []programSummary `jsonschema:"List of program summaries."`
	Total    int              `jsonschema:"Total number of programs matching the filter."`
}

var ToolListLogPrograms = aflow.NewFuncTool("list-log-programs", listLogProgramsFunc, `
List program summaries (UUID, Proc, and Call names) from the execution log with optional filtering and pagination.
`)

func listLogProgramsFunc(_ *aflow.Context, state logToolState,
	args listLogProgramsArgs) (listLogProgramsResult, error) {
	var filtered []ai.LogProgram
	for _, p := range state.Programs {
		if args.Proc != nil && p.Proc != *args.Proc {
			continue
		}
		if args.Call != "" {
			matchedCall := slices.ContainsFunc(p.Calls, func(c string) bool {
				return strings.Contains(c, args.Call)
			})
			if !matchedCall {
				continue
			}
		}
		filtered = append(filtered, p)
	}

	slices.SortFunc(filtered, func(a, b ai.LogProgram) int {
		return cmp.Compare(a.Position, b.Position)
	})

	total := len(filtered)
	offset := min(max(args.Offset, 0), total)
	limit := args.Limit
	if limit <= 0 {
		limit = 30
	}
	limit = min(limit, 100)
	end := min(offset+limit, total)

	summaries := make([]programSummary, 0, end-offset)
	for _, p := range filtered[offset:end] {
		summaries = append(summaries, programSummary{
			UUID:            p.UUID,
			Position:        p.Position,
			TimeBeforeCrash: p.TimeBeforeCrash,
			Proc:            p.Proc,
			ExecID:          p.ExecID,
			Calls:           p.Calls,
			TestedFailed:    p.TestedFailed,
		})
	}

	return listLogProgramsResult{
		Programs: summaries,
		Total:    total,
	}, nil
}

// Program testing tool and interfaces.

// ProgramTester provides an interface for executing candidate programs in a test VM.
type ProgramTester interface {
	TestPrograms(ctx context.Context, progIDs []string, timeout time.Duration) (*TestProgramsResult, error)
}

// TestProgramsResult contains the outcome of executing candidate programs in a VM.
type TestProgramsResult struct {
	Crashed     bool
	CrashTitle  string
	IsTargetBug bool
	RawOutput   []byte
	Duration    time.Duration
}

type contextKeyType int

const programTesterKey contextKeyType = 1

// ContextWithProgramTester attaches a ProgramTester to the context.
func ContextWithProgramTester(ctx context.Context, tester ProgramTester) context.Context {
	return context.WithValue(ctx, programTesterKey, tester)
}

// ProgramTesterFromContext retrieves a ProgramTester from the context if present.
func ProgramTesterFromContext(ctx context.Context) ProgramTester {
	if val, ok := ctx.Value(programTesterKey).(ProgramTester); ok {
		return val
	}
	return nil
}

// ErrCrashFound is returned when a candidate program successfully reproduces the target crash.
var ErrCrashFound = errors.New("target crash reproduced successfully")

type testCandidateProgramsArgs struct {
	ProgIDs        []string `jsonschema:"Program UUIDs from execution log to execute together in chronological order."`
	TimeoutSeconds int      `json:",omitempty" jsonschema:"Optional test timeout in seconds (default/min 45, max 300)."`
	Rationale      string   `json:",omitempty" jsonschema:"Optional kernel state or race hypothesis being tested."`
}

type testCandidateProgramsResult struct {
	Crashed          bool    `jsonschema:"Whether a kernel crash occurred during execution."`
	CrashTitle       string  `json:",omitempty" jsonschema:"The title of the detected crash, if any."`
	IsTargetBug      bool    `json:",omitempty" jsonschema:"Whether the crash matches the target bug."`
	ExecutionSummary string  `jsonschema:"Summary of serial console and executor log highlighting failed syscalls."`
	DurationSeconds  float64 `jsonschema:"Elapsed execution time in seconds."`
}

type testToolState struct {
	BugTitle     string
	CrashReport  string
	Programs     []ai.LogProgram
	ValidProgIDs []string
}

var ToolTestCandidatePrograms = aflow.NewFuncTool("test-candidate-programs", testCandidateProgramsFunc, `
Execute candidate programs from the log inside an instrumented test VM to test whether they reproduce the crash.
You can specify multiple program UUIDs (e.g. [SetupProgramUUID, TriggerProgramUUID]) to execute multi-program sequences.
If the program crashes the kernel with the target bug, reproduction succeeds and completes automatically.
If the program does NOT crash, a sub-agent with knowledge of the crash call trace and your test rationale will inspect
the serial console and executor output to summarize syscall return codes (e.g. -ENOENT, -ENODEV) and kernel errors.
Optionally specify 'Rationale' to explain what kernel state or race you are testing so the sub-agent can evaluate it.
You have a budget of up to 10 candidate tests (timeout 45s - 300s / up to 5 minutes each).
`)

func testCandidateProgramsFunc(ctx *aflow.Context, state testToolState,
	args testCandidateProgramsArgs) (testCandidateProgramsResult, error) {
	if len(args.ProgIDs) == 0 {
		return testCandidateProgramsResult{}, aflow.BadCallError("ProgIDs cannot be empty")
	}
	var invalid []string
	for _, id := range args.ProgIDs {
		if !slices.Contains(state.ValidProgIDs, id) {
			invalid = append(invalid, id)
		}
	}
	if len(invalid) > 0 {
		return testCandidateProgramsResult{}, aflow.BadCallError(
			"unknown program UUIDs: %v. Only select UUIDs that exist in the execution log", invalid)
	}

	tester := ProgramTesterFromContext(ctx.Context)
	if tester == nil {
		return testCandidateProgramsResult{
			ExecutionSummary: "Interactive VM testing is not available in this environment. " +
				"Please analyze the execution log and kernel source directly to select candidates.",
		}, nil
	}

	timeout := time.Duration(args.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	timeout = min(max(timeout, 45*time.Second), 300*time.Second)

	res, err := tester.TestPrograms(ctx.Context, args.ProgIDs, timeout)
	if err != nil {
		return testCandidateProgramsResult{}, err
	}
	if res.Crashed {
		if res.IsTargetBug {
			return testCandidateProgramsResult{
				Crashed:         true,
				CrashTitle:      res.CrashTitle,
				IsTargetBug:     true,
				DurationSeconds: res.Duration.Seconds(),
				ExecutionSummary: fmt.Sprintf("Target crash '%s' successfully reproduced in %.1fs!",
					res.CrashTitle, res.Duration.Seconds()),
			}, ErrCrashFound
		}
		return testCandidateProgramsResult{
			Crashed:         true,
			CrashTitle:      res.CrashTitle,
			IsTargetBug:     false,
			DurationSeconds: res.Duration.Seconds(),
			ExecutionSummary: fmt.Sprintf("Kernel crashed with an unrelated crash '%s' (not the target bug).",
				res.CrashTitle),
		}, nil
	}

	crashSite := extractCrashSiteInfo(state.CrashReport)
	progSummary := formatTestedProgramsSummary(args.ProgIDs, state.Programs)
	summary, err := summarizeSerialOutput(ctx, state.BugTitle, crashSite, progSummary, args.Rationale, res.RawOutput)
	if err != nil {
		summary = fallbackSummarizeLog(res.RawOutput)
	}

	return testCandidateProgramsResult{
		Crashed:          false,
		ExecutionSummary: summary,
		DurationSeconds:  res.Duration.Seconds(),
	}, nil
}

func extractCrashSiteInfo(report string) string {
	if report == "" {
		return "No crash report available."
	}
	lines := strings.Split(report, "\n")
	var selected []string
	inTrace := false
	traceLines := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "BUG:") || strings.HasPrefix(trimmed, "WARNING:") ||
			strings.HasPrefix(trimmed, "INFO:") || strings.HasPrefix(trimmed, "Write of size") ||
			strings.HasPrefix(trimmed, "Read of size") {
			selected = append(selected, trimmed)
			continue
		}
		if strings.HasPrefix(trimmed, "Call Trace:") {
			inTrace = true
			selected = append(selected, trimmed)
			continue
		}
		if inTrace {
			if strings.Contains(line, "dump_stack") || strings.Contains(line, "kasan_report") ||
				strings.Contains(line, "print_report") || strings.Contains(line, "check_region") ||
				strings.Contains(line, "print_address") {
				continue
			}
			selected = append(selected, trimmed)
			traceLines++
			if traceLines >= 6 {
				break
			}
		}
	}
	if len(selected) == 0 {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				selected = append(selected, trimmed)
				if len(selected) >= 8 {
					break
				}
			}
		}
	}
	return strings.Join(selected, "\n")
}

func formatTestedProgramsSummary(progIDs []string, programs []ai.LogProgram) string {
	progMap := make(map[string]ai.LogProgram, len(programs))
	for _, p := range programs {
		progMap[p.UUID] = p
	}
	var lines []string
	for i, id := range progIDs {
		p, ok := progMap[id]
		if !ok {
			lines = append(lines, fmt.Sprintf("- Program #%d (UUID %s)", i+1, id))
			continue
		}
		calls := strings.Join(p.Calls, ", ")
		if len(calls) > 200 {
			calls = calls[:197] + "..."
		}
		timing := ""
		if p.TimeBeforeCrash != "" {
			timing = fmt.Sprintf(", %s before crash", p.TimeBeforeCrash)
		}
		lines = append(lines, fmt.Sprintf("- Program #%d (UUID %s, Proc %d, Position %d%s): %s",
			i+1, p.UUID, p.Proc, p.Position, timing, calls))
	}
	return strings.Join(lines, "\n")
}

func windowLogOutput(output []byte) string {
	const halfLog = 16 << 10 // 16 KB
	if len(output) <= 2*halfLog {
		return strings.ToValidUTF8(string(output), "")
	}
	head := output[:halfLog]
	tail := output[len(output)-halfLog:]
	if idx := bytes.IndexByte(tail, '\n'); idx != -1 && idx < 200 {
		tail = tail[idx+1:]
	}
	truncatedBytes := len(output) - len(head) - len(tail)
	return fmt.Sprintf("%s\n... [%d bytes omitted] ...\n%s",
		strings.ToValidUTF8(string(head), ""),
		truncatedBytes,
		strings.ToValidUTF8(string(tail), ""))
}

func summarizeSerialOutput(ctx *aflow.Context, bugTitle, crashSite, progSummary, rationale string,
	output []byte) (string, error) {
	if len(output) == 0 {
		return "Program completed without crashing. No console output recorded.", nil
	}
	cleanLog := windowLogOutput(output)

	if ctx == nil {
		return fallbackSummarizeLog(output), nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Target bug being investigated: %s\n", bugTitle)
	if crashSite != "" {
		fmt.Fprintf(&sb, "\nCrash Site & Call Trace:\n%s\n", crashSite)
	}
	if progSummary != "" {
		fmt.Fprintf(&sb, "\nTested Programs & Syscalls:\n%s\n", progSummary)
	}
	if rationale != "" {
		fmt.Fprintf(&sb, "\nAgent's Test Hypothesis:\n%s\n", rationale)
	}
	fmt.Fprintf(&sb, `
Below is the serial console and executor log from that execution in the test VM:

--- CONSOLE LOG START ---
%s
--- CONSOLE LOG END ---

Analyze the log and provide a concise 2-4 sentence technical summary:
1. Did any syscalls fail with errors (e.g. -ENOENT, -ENODEV, -EPERM, -EINVAL, or mount failures)?
2. Did the kernel print warnings, dmesg lines, or driver messages related to the crash?
3. What prerequisite setup or device configuration appears to be missing?
Focus only on actionable clues for why the crash was not triggered. Keep the summary under 100 words.`, cleanLog)

	prompt := sb.String()

	span := &trajectory.Span{
		Type: trajectory.SpanAgent,
		Name: "serial-output-analyzer",
	}
	_ = ctx.StartSpan(span)

	cfg := &backend.GenerateConfig{}
	req := []*backend.Message{
		{
			Role: backend.RoleUser,
			Parts: []backend.Part{
				{Text: prompt},
			},
		},
	}

	resp, err := ctx.GenerateContent(backend.LightweightModel, cfg, req)
	if err != nil {
		_ = ctx.FinishSpan(span, err)
		return fallbackSummarizeLog(output), nil
	}
	var summary string
	for _, part := range resp.Parts {
		if part.Text != "" {
			summary += part.Text
		}
	}
	summary = strings.TrimSpace(summary)
	span.Results = map[string]any{"summary": summary}
	_ = ctx.FinishSpan(span, nil)
	if summary == "" {
		return fallbackSummarizeLog(output), nil
	}
	return summary, nil
}

func fallbackSummarizeLog(output []byte) string {
	if len(output) == 0 {
		return "Execution completed without crash. No console output."
	}
	var matchingLines []string
	keywords := []string{
		"errno", "failed", "cannot", "no such", "permission denied",
		"invalid argument", "error", "warning", "BUG", "oops",
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				matchingLines = append(matchingLines, strings.TrimSpace(line))
				break
			}
		}
	}
	if len(matchingLines) == 0 {
		return "Execution completed without crash. Syscalls completed without obvious kernel errors."
	}
	if len(matchingLines) > 6 {
		matchingLines = matchingLines[len(matchingLines)-6:]
	}
	return "Execution completed without crash. Key console/executor messages:\n- " + strings.Join(matchingLines, "\n- ")
}

// Agent definition.

type filterAgentOutputs struct {
	SelectedProgIDs []string `jsonschema:"Program UUIDs from log causing crash, or empty if GiveUp is true."`
	GiveUp          bool     `json:",omitempty" jsonschema:"Set true if bug cannot be reproduced from log."`
	Reasoning       string   `jsonschema:"Technical reasoning for crash relationship or why repro is impossible."`
}

type filterAgentState struct {
	ValidProgIDs  []string
	TestedProgIDs []string
}

func validateFilterAgentOutputs(_ *aflow.Context, state filterAgentState,
	args filterAgentOutputs) (filterAgentOutputs, error) {
	if strings.TrimSpace(args.Reasoning) == "" {
		return filterAgentOutputs{}, aflow.BadCallError("Reasoning must be provided")
	}
	if args.GiveUp {
		if len(args.SelectedProgIDs) > 0 {
			return filterAgentOutputs{}, aflow.BadCallError("SelectedProgIDs must be empty when GiveUp is true")
		}
		return args, nil
	}
	var invalid []string
	for _, id := range args.SelectedProgIDs {
		if !slices.Contains(state.ValidProgIDs, id) {
			invalid = append(invalid, id)
		}
	}
	if len(invalid) > 0 {
		return filterAgentOutputs{}, aflow.BadCallError(
			"unknown program UUIDs: %v. Only select UUIDs that exist in the execution log", invalid)
	}
	if len(args.SelectedProgIDs) == 1 && slices.Contains(state.TestedProgIDs, args.SelectedProgIDs[0]) {
		return filterAgentOutputs{}, aflow.BadCallError(
			"program %s was ALREADY tested in isolation and failed to reproduce the crash. "+
				"Do NOT select it alone. It likely requires a prerequisite setup program (e.g. filesystem mount, "+
				"device creation, memory mapping, socket configuration) or concurrent execution with another program. "+
				"Identify and include the earlier setup program(s) or concurrent programs along with it in SelectedProgIDs.",
			args.SelectedProgIDs[0])
	}
	return args, nil
}

var reproLogFilterAgent = &aflow.LLMAgent{
	Name:          "repro-log-filter",
	Model:         aflow.CoreModel,
	TaskType:      aflow.FormalReasoningTask,
	MaxIterations: 35,
	Tools: aflow.Tools(
		grepper.Tool,
		codesearcher.ToolReadFile,
		codesearcher.ToolDirIndex,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
		ToolGetLogProgram,
		ToolSearchLogPrograms,
		ToolListLogPrograms,
		ToolTestCandidatePrograms,
	),
	Outputs: aflow.ValidatedLLMOutputs[filterAgentOutputs](validateFilterAgentOutputs),
	Instruction: `
You are an expert Linux kernel developer and security researcher specializing in crash triage.
You are given a kernel crash report, optional recent console log output, and a chronological log of
syzkaller test programs executed before the crash.

Your goal is to identify which program(s) from the log caused or contributed to the crash.

Investigation Tools:
1. Execution Log Inspection:
   - Use 'search-log-programs' to search across all log programs using regex (e.g. syscall names
     like 'mount', 'bpf', 'ioctl', or device strings). Matches are sorted closest to the crash first.
   - Use 'get-log-program' to read the full syzlang source text and syscall arguments of candidates.
   - Use 'list-log-programs' to browse programs or filter by specific parallel 'Proc' IDs.
2. Kernel Source & Syzlang Descriptions:
   - Use 'grepper' to search kernel source for functions, struct names, drivers, or error strings.
   - Use 'read-file' and 'codesearch-dir-index' to view kernel implementations at the crash site.
   - Use 'syz-grepper' and 'read-syz-spec' to inspect syscall definitions for faulting subsystems.
3. Interactive Candidate Testing inside VM:
   - Use 'test-candidate-programs' to execute candidate programs from the log inside an instrumented test VM.
   - You can provide multiple program UUIDs (e.g. [SetupUUID, TriggerUUID]) to test multi-program sequences.
   - You can specify 'TimeoutSeconds' (45s to 300s / 5 minutes). For potential race conditions, hung tasks,
     or timing-dependent bugs, use longer timeouts (e.g. 120s to 300s) to give the programs enough time.
   - Provide a brief 'Rationale' explaining what kernel state, setup, or race you expect this test to verify.
   - If the target crash reproduces during candidate testing, reproduction succeeds and completes automatically!
   - If the test does not crash, a sub-agent with access to the crash call trace and your test rationale will analyze
     the serial console and executor output to summarize syscall return codes, failed mounts, or missing devices.
   - You have a budget of up to 10 candidate tests. Use them to test your hypotheses.

Understanding Log Metadata & Placeholders:
- 'Position': The program's position counted backwards from the crash point
  (0 is the final program running when the crash occurred, 1 is the program immediately before it, etc.).
- 'TimeBeforeCrash': Approximate time elapsed between this program and the crash (e.g. "3.5s", "0s").
- 'Proc' numbers:
  * Each Proc corresponds to an independent parallel executor process inside the VM.
  * Programs with the SAME Proc executed sequentially within that process context (sharing FDs).
  * Programs with DIFFERENT Procs executed concurrently in parallel processes!
- Large Blobs: Strings like "$BLOB_abcdef012345" represent large binary literals (e.g. filesystem images,
  packet payloads, BPF bytecode) replaced with placeholders to conserve context.

Analyzing Crash Reports and Console Logs:
- Check the Crash Report and Recent Console Log for:
  * Task names: comm="syz.X.Y" directly indicates Proc X and ExecID Y. NOTE: ExecID Y was ALREADY tested
    in isolation and failed to reproduce the crash! Do NOT select ExecID Y alone. Look for earlier setup
    programs on Proc X or other Procs that initialized the necessary kernel state.
  * Subsystem error messages or warnings right before the crash (e.g. filesystem errors, driver probe
    failures, memory allocation warnings, RCU stalls).
  * The faulting function and call stack to identify the subsystem (e.g., fs/jffs2, drivers/media).
- If the Crash Report is empty or generic ("no output/lost connection"), rely on the Recent Console Log
  to determine which subsystem or Proc was active immediately before the kernel hung or disconnected.

ALREADY TESTED STANDALONE PROGRAMS (CRITICAL):
- Before invoking you, syzkaller ALREADY tested individual candidate programs in isolation (specifically the program
  matching comm="syz.X.Y" or the last program of each proc).
- Standalone execution of those programs FAILED to reproduce the crash!
- Any program marked with '[ALREADY TESTED STANDALONE: FAILED TO REPRODUCE]' CANNOT cause the crash on its own:
  * DO NOT select that program alone in SelectedProgIDs! Selecting it alone will fail validation.
  * If that program is the trigger (e.g. its syscalls match the crash stack trace), it REQUIRES prerequisite
    setup program(s) (e.g. mounting a filesystem image, opening/creating a device node, creating an mmap mapping/folio,
    configuring network namespaces/sockets/bpf, or initializing state) or concurrent execution on another Proc.
  * You MUST identify and include those earlier setup or concurrent programs along with the trigger program!
  * Syzkaller tests all selected programs together in chronological order during reproduction.

SETUP VS. TRIGGER SEQUENCES (CRITICAL):
Many kernel vulnerabilities require a multi-program sequence:
- Setup Program: Mounts a filesystem image (e.g. 'syz_mount_image', 'mount$ext4', 'mount$jffs2'), opens
  or creates a device node or pseudo-terminal ('syz_open_dev', 'openat$ptmx'), creates a network
  namespace or interface ('unshare', 'syz_net_dev'), or creates directory hierarchies ('mkdir', 'configfs').
- Trigger Program: Executes the faulting syscall ('read', 'write', 'ioctl', 'rmdir', 'close') on that
  mounted filesystem, device, or socket.
RULE: If a suspect program operates on a mounted filesystem or specific device/resource, you MUST
search earlier in the log for the setup program that mounted or initialized that resource, and INCLUDE
BOTH the setup program(s) AND the trigger program in 'SelectedProgIDs'! Syzkaller tests all selected
programs together in chronological order during reproduction. A trigger program alone will fail without
its prerequisite setup.

Concurrency, Hung Tasks & Deadlocks:
- Concurrency / Races: Look for programs executed around the same time across different Procs accessing
  the same objects, devices, or memory areas.
- Concurrency races are NOT a reason to give up!
  * When syzkaller replays programs, it runs them in parallel threads in an infinite loop.
  * If you identify the suspect racing programs (e.g. 1-2 programs), syzkaller will loop ONLY those programs,
    amplifying the race collision rate by 100x-300x compared to replaying the entire 300-program log.
  * When testing candidate programs for a suspected race with 'test-candidate-programs', use longer timeouts
    (e.g. 120s to 300s).
  * Even if 'test-candidate-programs' does not hit the race window within its test budget, do NOT give up if you
    have identified the plausible racing candidate programs! Return them in 'SelectedProgIDs' so syzkaller's
    reproduction engine can stress-test and loop them.
- Hung Tasks ("INFO: task hung in ..."): khungtaskd detects tasks blocked for >120 seconds. Check
  comm="syz.X.Y" in the trace for the stuck task. Search for programs on Proc X or programs manipulating
  the lock/resource the task is waiting on.
- Deadlocks / Lockdep ("possible deadlock in ..."): Lockdep detects circular lock dependencies (A -> B
  vs B -> A). The crash stack shows where the second lock was attempted. Search the log for programs
  that acquire conflicting locks or manipulate the same subsystem concurrently on other Procs.

GIVING UP (WHEN A BUG IS NOT REPRODUCIBLE FROM LOG):
Giving up is ONLY appropriate when the bug fundamentally cannot be reproduced from the log programs:
- External host actions or environment teardown (e.g. the console log shows the host triggered an external
  poweroff/reboot: 'The system is going down NOW!', 'reboot: Power down').
- Missing prerequisite state occurred before the log window began (e.g. a lockdep cycle where an earlier lock edge
  was acquired long before the 300-program log started, and no matching program exists in the log).
- Missing physical hardware or external network infrastructure completely unsupported by the VM environment.
DO NOT give up merely because a bug is a race condition or elusive concurrency issue! If you have identified the
racing candidate programs, return them in 'SelectedProgIDs' instead of giving up.
If after analyzing the log and kernel code you determine the bug fundamentally cannot be reproduced:
- Set 'GiveUp: true'
- Set 'SelectedProgIDs: []'
- In 'Reasoning', clearly explain why reproduction is impossible from this log.
Do NOT guess or hallucinate unrelated syscalls just to populate SelectedProgIDs.

Efficient Investigation Strategy:
1. Analyze the crash report / console log to identify key subsystem names, syscalls, or device nodes.
2. Search log programs immediately with 'search-log-programs' for those syscalls or device names.
3. Inspect matching candidate programs with 'get-log-program'.
4. Check if candidates require earlier setup programs (e.g. filesystem mounts).
5. Test your hypothesis using 'test-candidate-programs'. Inspect the sub-agent summary if it doesn't crash.
6. Use kernel code reading tools ('grepper', 'read-file') selectively when needed to clarify lock names
   or syscall semantics. Avoid deep dives into unrelated kernel code when log candidates are clear.

CRITICAL INSTRUCTIONS:
- Return SelectedProgIDs containing ONLY the UUIDs of identified programs, or an empty list if GiveUp is true.
- If you determine the bug cannot be reproduced from this log, set GiveUp to true and SelectedProgIDs to [].
- DO NOT copy or paste program code into the output.
- Explain your rationale in 'Reasoning', referencing the relevant kernel functions, call stacks, and syscalls.
`,
	Prompt: `
Target: {{.TargetOS}}/{{.TargetArch}}
Bug Title: {{.BugTitle}}

Crash Report:
{{.CrashReport}}
{{if .ConsoleLog}}
Recent Console Log (last 5KB):
{{.ConsoleLog}}
{{end}}
{{.DescriptionFilesPrompt}}

{{.SkillsPrompt}}

Execution Log Programs:
{{.LogOverview}}

Identify which program(s) from the log may have caused or contributed to this crash.
`,
}
