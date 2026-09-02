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
	Prog            string   `jsonschema:"The full serialized syzlang text of the program with blobs replaced."`
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
  * Task names: comm="syz.X.Y" directly indicates Proc X and ExecID Y! Use this to locate the program.
  * Subsystem error messages or warnings right before the crash (e.g. filesystem errors, driver probe
    failures, memory allocation warnings, RCU stalls).
  * The faulting function and call stack to identify the subsystem (e.g., fs/jffs2, drivers/media).
- If the Crash Report is empty or generic ("no output/lost connection"), rely on the Recent Console Log
  to determine which subsystem or Proc was active immediately before the kernel hung or disconnected.

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
- Hung Tasks ("INFO: task hung in ..."): khungtaskd detects tasks blocked for >120 seconds. Check
  comm="syz.X.Y" in the trace for the stuck task. Search for programs on Proc X or programs manipulating
  the lock/resource the task is waiting on.
- Deadlocks / Lockdep ("possible deadlock in ..."): Lockdep detects circular lock dependencies (A -> B
  vs B -> A). The crash stack shows where the second lock was attempted. Search the log for programs
  that acquire conflicting locks or manipulate the same subsystem concurrently on other Procs.

Efficient Investigation Strategy:
1. Analyze the crash report / console log to identify key subsystem names, syscalls, or device nodes.
2. Search log programs immediately with 'search-log-programs' for those syscalls or device names.
3. Inspect matching candidate programs with 'get-log-program'.
4. Check if candidates require earlier setup programs (e.g. filesystem mounts).
5. Use kernel code reading tools ('grepper', 'read-file') selectively when needed to clarify lock names
   or syscall semantics. Avoid deep dives into unrelated kernel code when log candidates are clear.

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
