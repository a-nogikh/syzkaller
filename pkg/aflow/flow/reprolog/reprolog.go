// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package reprolog provides an aflow workflow and tools for filtering crash log programs.
package reprolog

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/actionsyzlang"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
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
// and optional TimeBeforeCrash (from ent.Time if present), and returns a lookup map from UUID to the original LogEntry.
func EntriesToLogPrograms(entries []*prog.LogEntry) ([]ai.LogProgram, map[string]*prog.LogEntry) {
	var validEntries []*prog.LogEntry
	for _, ent := range entries {
		if ent != nil && ent.P != nil {
			validEntries = append(validEntries, ent)
		}
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
	LogOverview  string
	ValidProgIDs []string
}

var actionPrepareLogContext = aflow.NewFuncAction("prepare-log-context", prepareLogContextFunc)

func prepareLogContextFunc(ctx *aflow.Context, args prepareLogContextArgs) (prepareLogContextResult, error) {
	validIDs := make([]string, 0, len(args.Programs))
	for _, p := range args.Programs {
		validIDs = append(validIDs, p.UUID)
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
		fmt.Fprintf(&overview, "- UUID: %s [Position %d%s, Proc %d]: %s\n",
			p.UUID, p.Position, timing, p.Proc, strings.Join(p.Calls, ", "))
	}

	if len(args.Programs) > maxDirectOverview {
		overview.WriteString(
			"\nNote: Earlier programs can be found using the search-log-programs or list-log-programs tools.\n")
	}

	return prepareLogContextResult{
		LogOverview:  overview.String(),
		ValidProgIDs: validIDs,
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
	Prog            string   `jsonschema:"The full serialized syzlang text of the program."`
}

var ToolGetLogProgram = aflow.NewFuncTool("get-log-program", getLogProgramFunc, `
Retrieve the full syzlang source text and metadata of an execution log program by its UUID.
Use this tool to closely inspect the syscall arguments, resources, and configurations of candidate programs.
`)

func getLogProgramFunc(_ *aflow.Context, state logToolState, args getLogProgramArgs) (getLogProgramResult, error) {
	for _, p := range state.Programs {
		if p.UUID == args.UUID {
			return getLogProgramResult{
				UUID:            p.UUID,
				Position:        p.Position,
				TimeBeforeCrash: p.TimeBeforeCrash,
				Proc:            p.Proc,
				ExecID:          p.ExecID,
				Calls:           p.Calls,
				Prog:            p.Prog,
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
	Calls           []string `jsonschema:"List of syscall names in the program."`
	LineMatches     []string `jsonschema:"Lines with large binary blobs replaced."`
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
				Calls:           p.Calls,
				LineMatches:     lineMatches,
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
		})
	}

	return listLogProgramsResult{
		Programs: summaries,
		Total:    total,
	}, nil
}

// Agent definition.

type filterAgentOutputs struct {
	SelectedProgIDs []string `jsonschema:"List of program UUIDs from the log that may cause the crash."`
	Reasoning       string   `jsonschema:"Detailed technical reasoning explaining how the programs relate to the crash."`
}

type filterAgentState struct {
	ValidProgIDs []string
}

func validateFilterAgentOutputs(_ *aflow.Context, state filterAgentState,
	args filterAgentOutputs) (filterAgentOutputs, error) {
	if strings.TrimSpace(args.Reasoning) == "" {
		return filterAgentOutputs{}, aflow.BadCallError("Reasoning must be provided")
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
	return args, nil
}

var reproLogFilterAgent = &aflow.LLMAgent{
	Name:     "repro-log-filter",
	Model:    aflow.CoreModel,
	TaskType: aflow.FormalReasoningTask,
	Tools: aflow.Tools(
		grepper.Tool,
		codesearcher.ToolReadFile,
		codesearcher.ToolDirIndex,
		syzlang.ReadSyzSpec,
		syzlang.SyzGrepper,
		ToolGetLogProgram,
		ToolSearchLogPrograms,
		ToolListLogPrograms,
	),
	Outputs: aflow.ValidatedLLMOutputs[filterAgentOutputs](validateFilterAgentOutputs),
	Instruction: `
You are an expert Linux kernel developer and security researcher specializing in crash triage and root cause analysis.
You are given a kernel crash report and a chronological log of syzkaller test programs executed before the crash.

Your goal is to identify which program(s) from the log may have caused or contributed to the crash.

Investigate using your tools:
1. Kernel source inspection:
   - Use 'grepper' to search the kernel source tree for functions in the stack trace, drivers, or errors.
   - Use 'read-file' and 'codesearch-dir-index' to view the kernel implementation at the crash site.
2. Syzlang descriptions:
   - Use 'syz-grepper' and 'read-syz-spec' to find syscall definitions matching the faulting kernel subsystems.
3. Execution log:
   - Use 'get-log-program' to read the full syzlang code of suspect programs.
   - Use 'search-log-programs' to search for specific syscalls, ioctls, or parameters in the log.
     Matches are sorted closest to the crash first, with large binary blobs replaced.
   - Use 'list-log-programs' if you need to browse earlier programs.

Understanding Log Metadata:
- 'Position': The program's position counted backwards from the crash point
  (0 is the final program running when the crash occurred, 1 is the program immediately before it, etc.).
- 'TimeBeforeCrash': Approximate time elapsed between this program and the crash (e.g. "3.5s", "0s").
- 'Proc' numbers:
  * Each Proc number corresponds to an independent parallel executor process running concurrently
    inside the VM (configured via syzkaller 'procs').
  * Programs with the SAME Proc number executed sequentially within that process context
    (sharing file descriptors and process state).
  * Programs with DIFFERENT Proc numbers executed concurrently in parallel processes!
  * For race conditions and concurrency bugs, look for programs executed around the same time
    across different Proc numbers that access the same objects, devices, sockets, or memory areas.

Temporal Proximity vs. Root Cause:
- A crash is NOT always caused by the program running directly before the crash!
- While the last executing program (Position = 0) is often guilty, delayed crashes are common:
  * Asynchronous memory corruption (use-after-free, slab/page heap corruption) may only panic later
    when an innocent subsystem accesses the corrupted memory.
  * Deferred workqueues, timer callbacks, RCU grace periods, and async tasklets scheduled by an
    earlier program may fire seconds after that program finished.
  * Background kernel daemons (e.g. kswapd, bdi-writeback, networking queues).
  * Multi-program setup sequences: an earlier program (higher Position) may have mounted
    a filesystem, created a network namespace, registered a character device, or loaded a BPF program,
    which subsequent programs then triggered.
- Always check the faulting subsystem in the stack trace and search for programs touching that
  subsystem, even if they ran earlier in the log.

Selection criteria:
A crash may be caused by:
- A single program directly executing the faulting syscall or ioctl.
- A sequence of programs: e.g. program A sets up a subsystem or mounts a filesystem, and program B triggers the bug.
- Concurrency / race conditions: programs on different procs interleaving calls to corrupt state.

CRITICAL INSTRUCTIONS:
- You must return SelectedProgIDs containing ONLY the UUIDs of the programs you identified.
- DO NOT copy or paste program code into the output.
- Explain your rationale in 'Reasoning', referencing the relevant kernel functions, call stacks, and syscalls.
`,
	Prompt: `
Target: {{.TargetOS}}/{{.TargetArch}}
Bug Title: {{.BugTitle}}

Crash Report:
{{.CrashReport}}

{{.DescriptionFilesPrompt}}

{{.SkillsPrompt}}

Execution Log Programs:
{{.LogOverview}}

Identify which program(s) from the log may have caused or contributed to this crash.
`,
}
