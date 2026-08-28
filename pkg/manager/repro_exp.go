// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

type ConfigID int

const (
	Config6Progs ConfigID = iota
	Config25ProgsSliding
	ConfigAsIs
	ConfigAsIsSliding
	ConfigAsIsSlidingExact
)

const (
	ReproStatusPending  = "pending"
	ReproStatusRunning  = "running"
	ReproStatusCRepro   = "C repro"
	ReproStatusSyzRepro = "syz repro"
	ReproStatusFailed   = "failed"
	ReproStatusError    = "error"
)

type ReproConfig struct {
	ID            ConfigID `json:"id"`
	Key           string   `json:"key"`
	Name          string   `json:"name"`
	MaxPerProc    int      `json:"max_per_proc"`
	SlidingWindow bool     `json:"sliding_window"`
	ExactCrash    bool     `json:"exact_crash"`
}

var ReproConfigs = []ReproConfig{
	{
		ID:            Config6Progs,
		Key:           "6_progs",
		Name:          "6 progs/proc",
		MaxPerProc:    6,
		SlidingWindow: false,
		ExactCrash:    false,
	},
	{
		ID:            Config25ProgsSliding,
		Key:           "25_progs_sliding",
		Name:          "25 progs/proc + sliding",
		MaxPerProc:    25,
		SlidingWindow: true,
		ExactCrash:    false,
	},
	{
		ID:            ConfigAsIs,
		Key:           "as_is",
		Name:          "as is",
		MaxPerProc:    0,
		SlidingWindow: false,
		ExactCrash:    false,
	},
	{
		ID:            ConfigAsIsSliding,
		Key:           "as_is_sliding",
		Name:          "as is + sliding",
		MaxPerProc:    0,
		SlidingWindow: true,
		ExactCrash:    false,
	},
	{
		ID:            ConfigAsIsSlidingExact,
		Key:           "as_is_sliding_exact",
		Name:          "as is + sliding + exact",
		MaxPerProc:    0,
		SlidingWindow: true,
		ExactCrash:    true,
	},
}

func ShouldSkipCrash(title string) bool {
	t := strings.ToLower(title)
	return t == "" ||
		strings.Contains(t, "syzfail") ||
		strings.Contains(t, "syzfatal") ||
		strings.Contains(t, "lost connection") ||
		strings.Contains(t, "no output") ||
		strings.Contains(t, "max_lockdep_keys too low")
}

type BugEntry struct {
	ID        string
	Title     string
	AltTitles []string
	Log       []byte
}

func DiscoverBugs(workdir string, target *prog.Target) ([]*BugEntry, error) {
	crashesDir := filepath.Join(workdir, "crashes")
	entries, err := os.ReadDir(crashesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("crashes directory %q does not exist", crashesDir)
		}
		return nil, err
	}
	var bugs []*BugEntry
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		id := ent.Name()
		dir := filepath.Join(crashesDir, id)
		descBytes, err := os.ReadFile(filepath.Join(dir, "description"))
		if err != nil {
			continue
		}
		title := strings.TrimSpace(string(descBytes))
		if ShouldSkipCrash(title) {
			continue
		}
		log0, err := os.ReadFile(filepath.Join(dir, "log0"))
		if err != nil || len(log0) == 0 {
			continue
		}
		if !bytes.Contains(log0, []byte("executing program ")) {
			continue
		}
		bugs = append(bugs, &BugEntry{
			ID:    id,
			Title: title,
			Log:   log0,
		})
	}
	slices.SortFunc(bugs, func(a, b *BugEntry) int {
		if res := cmp.Compare(strings.ToLower(a.Title), strings.ToLower(b.Title)); res != 0 {
			return res
		}
		return cmp.Compare(a.ID, b.ID)
	})
	log.Logf(0, "repro-exp: discovered %d valid crashes in %s", len(bugs), crashesDir)
	return bugs, nil
}

func FilterLog(target *prog.Target, reporter *report.Reporter, crashLog []byte, maxPerProc int) []byte {
	if maxPerProc <= 0 || target == nil {
		return crashLog
	}
	entries := target.ParseLog(crashLog, prog.NonStrict)
	if len(entries) == 0 {
		return crashLog
	}
	crashStart := len(crashLog)
	if reporter != nil {
		if rep := reporter.Parse(crashLog); rep != nil && rep.StartPos >= 0 {
			crashStart = rep.StartPos
		}
	}
	var validEntries []*prog.LogEntry
	for _, ent := range entries {
		if ent.Start <= crashStart {
			validEntries = append(validEntries, ent)
		}
	}
	if len(validEntries) == 0 {
		return crashLog
	}
	procCount := make(map[int]int)
	var kept []*prog.LogEntry
	for _, ent := range slices.Backward(validEntries) {
		if procCount[ent.Proc] < maxPerProc {
			procCount[ent.Proc]++
			kept = append(kept, ent)
		}
	}
	slices.Reverse(kept)

	var buf bytes.Buffer
	for _, ent := range kept {
		pBytes := ent.P.Serialize()
		if len(pBytes) > 0 && pBytes[len(pBytes)-1] != '\n' {
			pBytes = append(pBytes, '\n')
		}
		fmt.Fprintf(&buf, "executing program %v:\n%s", ent.Proc, pBytes)
	}
	consoleStart := crashStart
	const consoleBanner = "kernel console output (not intermixed with test programs):\n\n"
	if pos := bytes.Index(crashLog, []byte(consoleBanner)); pos != -1 && pos < crashStart {
		consoleStart = pos
	}
	if consoleStart < len(crashLog) {
		buf.Write(crashLog[consoleStart:])
	}
	return buf.Bytes()
}

type ReproExpState struct {
	Bugs []*ReproExpBugState `json:"bugs"`
}

type ReproExpBugState struct {
	ID      string                    `json:"id"`
	Title   string                    `json:"title"`
	Results map[string]*ReproJobState `json:"results"`
}

type ReproJobState struct {
	ConfigKey    string        `json:"config_key"`
	Status       string        `json:"status"`
	CRepro       bool          `json:"c_repro,omitempty"`
	SyzRepro     bool          `json:"syz_repro,omitempty"`
	ReproTitle   string        `json:"repro_title,omitempty"`
	Duration     time.Duration `json:"duration,omitempty"`
	LogPath      string        `json:"log_path,omitempty"`
	TruncatedLog string        `json:"truncated_log,omitempty"`
	Error        string        `json:"error,omitempty"`
}

type ReproExpStatusSummary struct {
	LastUpdate   time.Time   `json:"last_update"`
	Running      bool        `json:"running"`
	TotalBugs    int         `json:"total_bugs"`
	DoneJobs     int         `json:"done_jobs"`
	RunningJobs  int         `json:"running_jobs"`
	PendingJobs  int         `json:"pending_jobs"`
	Columns      []string    `json:"columns"`
	SuccessRates []UIColStat `json:"success_rates"`
	Rows         []StatusRow `json:"rows"`
}

type StatusRow struct {
	ID      string            `json:"id"`
	Title   string            `json:"title"`
	Results map[string]string `json:"results"`
}

type UIReproExpTable struct {
	Columns []string
	Rows    []UIReproExpRow
	Stats   []UIColStat
	Running bool
}

type UIColStat struct {
	Text      string
	Breakdown string
}

type UIReproExpRow struct {
	ID    string
	Title string
	Cells []UIReproExpCell
}

type UIReproExpCell struct {
	Status       string
	LogPath      string
	TruncatedLog string
	Tooltip      string
	Style        template.CSS
}

type ReproRunnerFunc func(ctx context.Context, log []byte, cfg ReproConfig) (*repro.Result, *repro.Stats, error)

type ReproExp struct {
	cfg           *mgrconfig.Config
	features      flatrpc.Feature
	reporter      *report.Reporter
	pool          *vm.Dispatcher
	target        *prog.Target
	workdir       string
	sourceWorkdir string
	expDir        string
	stateFile     string
	statusFile    string
	dumpInterval  time.Duration

	runRepro ReproRunnerFunc

	mu          sync.Mutex
	state       *ReproExpState
	bugs        []*BugEntry
	runningJobs int
	started     bool

	statBugs     *stat.Val
	statJobsDone *stat.Val
	statRunning  *stat.Val
}

func NewReproExp(cfg *mgrconfig.Config, sourceWorkdir string, reporter *report.Reporter,
	pool *vm.Dispatcher) *ReproExp {
	if sourceWorkdir == "" {
		sourceWorkdir = cfg.Workdir
	}
	expDir := filepath.Join(cfg.Workdir, "repro-exp")
	exp := &ReproExp{
		cfg:           cfg,
		reporter:      reporter,
		pool:          pool,
		target:        cfg.Target,
		workdir:       cfg.Workdir,
		sourceWorkdir: sourceWorkdir,
		expDir:        expDir,
		stateFile:     filepath.Join(expDir, "state.json"),
		statusFile:    filepath.Join(expDir, "status.json"),
		dumpInterval:  time.Minute,
		state:         &ReproExpState{},
	}
	exp.runRepro = exp.defaultRunRepro
	exp.initStats()
	return exp
}

func (exp *ReproExp) initStats() {
	exp.statBugs = stat.New("repro_exp_bugs", "Total bugs to reproduce",
		stat.Console, stat.NoGraph, func() int {
			exp.mu.Lock()
			defer exp.mu.Unlock()
			return len(exp.state.Bugs)
		})
	exp.statJobsDone = stat.New("repro_exp_done", "Completed repro jobs",
		stat.Console, stat.NoGraph, func() int {
			exp.mu.Lock()
			defer exp.mu.Unlock()
			return exp.completedJobsLocked()
		})
	exp.statRunning = stat.New("repro_exp_running", "Running repro jobs",
		stat.Console, stat.NoGraph, func() int {
			exp.mu.Lock()
			defer exp.mu.Unlock()
			return exp.runningJobs
		})
}

func (exp *ReproExp) completedJobsLocked() int {
	done := 0
	for _, bug := range exp.state.Bugs {
		for _, res := range bug.Results {
			if isTerminalStatus(res.Status) {
				done++
			}
		}
	}
	return done
}

func isTerminalStatus(status string) bool {
	return status == ReproStatusCRepro || status == ReproStatusSyzRepro ||
		status == ReproStatusFailed || status == ReproStatusError
}

func (exp *ReproExp) Init() error {
	exp.mu.Lock()
	defer exp.mu.Unlock()

	bugs, err := DiscoverBugs(exp.sourceWorkdir, exp.target)
	if err != nil {
		return fmt.Errorf("failed to discover bugs: %w", err)
	}
	if exp.reporter != nil {
		for _, b := range bugs {
			if len(b.Log) > 0 {
				if rep := exp.reporter.Parse(b.Log); rep != nil {
					b.AltTitles = rep.AltTitles
				}
			}
		}
	}
	exp.bugs = bugs

	if err := exp.loadStateLocked(); err != nil {
		log.Errorf("repro-exp: failed to load state: %v", err)
	}

	existingBugs := make(map[string]*ReproExpBugState)
	for _, b := range exp.state.Bugs {
		existingBugs[b.ID] = b
	}

	var mergedBugs []*ReproExpBugState
	for _, b := range exp.bugs {
		bs := existingBugs[b.ID]
		if bs == nil {
			bs = &ReproExpBugState{
				ID:      b.ID,
				Title:   b.Title,
				Results: make(map[string]*ReproJobState),
			}
		} else {
			bs.Title = b.Title
			if bs.Results == nil {
				bs.Results = make(map[string]*ReproJobState)
			}
		}
		for _, cfg := range ReproConfigs {
			if _, ok := bs.Results[cfg.Key]; !ok {
				bs.Results[cfg.Key] = &ReproJobState{
					ConfigKey: cfg.Key,
					Status:    ReproStatusPending,
				}
			}
		}
		mergedBugs = append(mergedBugs, bs)
	}
	exp.state.Bugs = mergedBugs
	return exp.dumpStatusLocked()
}

func (exp *ReproExp) Start(ctx context.Context, features flatrpc.Feature) {
	exp.mu.Lock()
	if exp.started {
		exp.mu.Unlock()
		return
	}
	exp.started = true
	exp.features = features
	exp.mu.Unlock()

	go exp.Run(ctx)
}

func (exp *ReproExp) Run(ctx context.Context) {
	if err := exp.Init(); err != nil {
		log.Errorf("repro-exp: init failed: %v", err)
	}

	exp.mu.Lock()
	type pendingJob struct {
		bug    *BugEntry
		config ReproConfig
	}
	var pending []*pendingJob
	bugMap := make(map[string]*BugEntry)
	for _, b := range exp.bugs {
		bugMap[b.ID] = b
	}

	for _, bs := range exp.state.Bugs {
		bug := bugMap[bs.ID]
		if bug == nil {
			continue
		}
		for _, cfg := range ReproConfigs {
			res := bs.Results[cfg.Key]
			if res == nil || res.Status == ReproStatusPending {
				pending = append(pending, &pendingJob{
					bug:    bug,
					config: cfg,
				})
			}
		}
	}
	exp.mu.Unlock()

	vmCount := 1
	if exp.pool != nil {
		vmCount = max(1, exp.pool.Total())
		exp.pool.ReserveForRun(vmCount)
	}
	concurrency := max(1, int(float64(vmCount)/1.25))

	log.Logf(0, "repro-exp: starting %d pending jobs (%d VMs in pool, concurrency %d)",
		len(pending), vmCount, concurrency)

	dumpInterval := exp.dumpInterval
	if dumpInterval <= 0 {
		dumpInterval = time.Minute
	}
	statusTicker := time.NewTicker(dumpInterval)
	defer statusTicker.Stop()
	tickerStop := make(chan struct{})
	defer close(tickerStop)
	go func() {
		for {
			select {
			case <-tickerStop:
				return
			case <-ctx.Done():
				return
			case <-statusTicker.C:
				exp.mu.Lock()
				_ = exp.dumpStatusLocked()
				exp.mu.Unlock()
			}
		}
	}()

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

Loop:
	for _, pj := range pending {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			break Loop
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(job *pendingJob) {
			defer func() {
				<-sem
				wg.Done()
			}()
			exp.executeJob(ctx, job.bug, job.config)
		}(pj)
	}
	wg.Wait()
	exp.mu.Lock()
	_ = exp.dumpStatusLocked()
	exp.mu.Unlock()
	log.Logf(0, "repro-exp: all reproduction experiment jobs finished")
}

func (exp *ReproExp) executeJob(ctx context.Context, bug *BugEntry, cfg ReproConfig) {
	if ctx.Err() != nil {
		return
	}

	exp.mu.Lock()
	bs := exp.getBugStateLocked(bug.ID)
	if bs == nil {
		exp.mu.Unlock()
		return
	}
	js := bs.Results[cfg.Key]
	if js == nil {
		js = &ReproJobState{ConfigKey: cfg.Key}
		bs.Results[cfg.Key] = js
	}
	if isTerminalStatus(js.Status) {
		exp.mu.Unlock()
		return
	}
	js.Status = ReproStatusRunning
	exp.runningJobs++
	_ = exp.dumpStatusLocked()
	exp.mu.Unlock()

	defer func() {
		exp.mu.Lock()
		exp.runningJobs--
		_ = exp.dumpStatusLocked()
		exp.mu.Unlock()
	}()

	log.Logf(0, "repro-exp: running [%s] on %q", cfg.Name, bug.Title)
	filteredLog := FilterLog(exp.target, exp.reporter, bug.Log, cfg.MaxPerProc)

	// Save the preprocessed truncated input log in the job directory.
	jobDir := filepath.Join(exp.expDir, bug.ID, cfg.Key)
	osutil.MkdirAll(jobDir)
	truncatedPath := filepath.Join(jobDir, "truncated.log")
	if err := osutil.WriteFile(truncatedPath, filteredLog); err != nil {
		log.Errorf("repro-exp: failed to write truncated log %s: %v", truncatedPath, err)
	}
	relTruncatedPath := filepath.Join("repro-exp", bug.ID, cfg.Key, "truncated.log")

	exp.mu.Lock()
	js.TruncatedLog = relTruncatedPath
	exp.mu.Unlock()

	start := time.Now()
	res, stats, err := exp.runRepro(ctx, filteredLog, cfg)
	duration := time.Since(start)

	if errors.Is(err, context.Canceled) {
		exp.mu.Lock()
		js.Status = ReproStatusPending
		_ = exp.dumpStatusLocked()
		exp.mu.Unlock()
		return
	}

	status, cRepro, syzRepro, reproTitle := exp.evaluateResult(bug, res, err)

	var reproLog []byte
	if stats != nil {
		reproLog = stats.FullLog()
	}
	if err != nil {
		reproLog = append(reproLog, []byte(fmt.Sprintf("\nreproduction error: %v\n", err))...)
	}

	reproPath := filepath.Join(jobDir, "repro.log")
	if err := osutil.WriteFile(reproPath, reproLog); err != nil {
		log.Errorf("repro-exp: failed to write repro log %s: %v", reproPath, err)
	}
	relReproPath := filepath.Join("repro-exp", bug.ID, cfg.Key, "repro.log")

	exp.mu.Lock()
	js.Status = status
	js.CRepro = cRepro
	js.SyzRepro = syzRepro
	js.ReproTitle = reproTitle
	js.Duration = duration
	js.LogPath = relReproPath
	if err != nil {
		js.Error = err.Error()
	}
	_ = exp.dumpStatusLocked()
	exp.mu.Unlock()

	log.Logf(0, "repro-exp: [%s] on %q -> %s (%v)",
		cfg.Name, bug.Title, status, duration.Round(time.Second))
}

func (exp *ReproExp) evaluateResult(bug *BugEntry, res *repro.Result, err error) (
	status string, cRepro, syzRepro bool, reproTitle string) {
	if err != nil {
		return ReproStatusError, false, false, ""
	}
	if res == nil {
		return ReproStatusFailed, false, false, ""
	}
	if res.Report != nil {
		reproTitle = res.Report.Title
	}
	altTitles := bug.AltTitles
	if len(altTitles) == 0 && exp.reporter != nil && len(bug.Log) > 0 {
		if parsed := exp.reporter.Parse(bug.Log); parsed != nil {
			altTitles = parsed.AltTitles
		}
	}
	if res.Report == nil || !repro.TitlesIntersect(bug.Title, altTitles, res.Report.Title, res.Report.AltTitles) {
		return ReproStatusFailed, false, false, reproTitle
	}
	if res.CRepro {
		return ReproStatusCRepro, true, false, reproTitle
	}
	return ReproStatusSyzRepro, false, true, reproTitle
}

func (exp *ReproExp) getBugStateLocked(id string) *ReproExpBugState {
	for _, b := range exp.state.Bugs {
		if b.ID == id {
			return b
		}
	}
	return nil
}

func (exp *ReproExp) defaultRunRepro(ctx context.Context, crashLog []byte,
	cfg ReproConfig) (*repro.Result, *repro.Stats, error) {
	return repro.Run(ctx, crashLog, repro.Environment{
		Config:        exp.cfg,
		Features:      exp.features,
		Reporter:      exp.reporter,
		Pool:          exp.pool,
		SlidingWindow: cfg.SlidingWindow,
		ExactCrash:    cfg.ExactCrash,
	})
}

func (exp *ReproExp) loadStateLocked() error {
	osutil.MkdirAll(exp.expDir)
	data, err := os.ReadFile(exp.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			exp.state = &ReproExpState{}
			return nil
		}
		return err
	}
	state := &ReproExpState{}
	if err := json.Unmarshal(data, state); err != nil {
		log.Errorf("repro-exp: failed to parse state file: %v", err)
		exp.state = &ReproExpState{}
		return nil
	}
	for _, bug := range state.Bugs {
		for _, res := range bug.Results {
			if res.Status == ReproStatusRunning {
				res.Status = ReproStatusPending
			}
		}
	}
	exp.state = state
	return nil
}

func (exp *ReproExp) saveStateLocked() error {
	osutil.MkdirAll(exp.expDir)
	data, err := json.MarshalIndent(exp.state, "", "  ")
	if err != nil {
		return err
	}
	tmpFile := exp.stateFile + ".tmp"
	if err := osutil.WriteFile(tmpFile, data); err != nil {
		return err
	}
	return osutil.Rename(tmpFile, exp.stateFile)
}

func (exp *ReproExp) dumpStatusLocked() error {
	_ = exp.saveStateLocked()
	table := exp.uiLocked()
	totalJobs := len(exp.state.Bugs) * len(ReproConfigs)
	doneJobs := exp.completedJobsLocked()
	summary := &ReproExpStatusSummary{
		LastUpdate:   time.Now(),
		Running:      exp.runningJobs > 0,
		TotalBugs:    len(exp.state.Bugs),
		DoneJobs:     doneJobs,
		RunningJobs:  exp.runningJobs,
		PendingJobs:  max(0, totalJobs-doneJobs-exp.runningJobs),
		Columns:      table.Columns,
		SuccessRates: table.Stats,
	}
	for _, bug := range exp.state.Bugs {
		r := StatusRow{
			ID:      bug.ID,
			Title:   bug.Title,
			Results: make(map[string]string),
		}
		for _, cfg := range ReproConfigs {
			if res, ok := bug.Results[cfg.Key]; ok {
				r.Results[cfg.Key] = res.Status
			} else {
				r.Results[cfg.Key] = ReproStatusPending
			}
		}
		summary.Rows = append(summary.Rows, r)
	}
	osutil.MkdirAll(exp.expDir)
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	tmpFile := exp.statusFile + ".tmp"
	if err := osutil.WriteFile(tmpFile, data); err != nil {
		return err
	}
	return osutil.Rename(tmpFile, exp.statusFile)
}

func (exp *ReproExp) UI() *UIReproExpTable {
	exp.mu.Lock()
	defer exp.mu.Unlock()
	return exp.uiLocked()
}

func (exp *ReproExp) uiLocked() *UIReproExpTable {
	table := &UIReproExpTable{
		Columns: make([]string, len(ReproConfigs)),
		Stats:   make([]UIColStat, len(ReproConfigs)),
		Running: exp.runningJobs > 0,
	}
	for i, cfg := range ReproConfigs {
		table.Columns[i] = cfg.Name
	}

	successCount := make([]int, len(ReproConfigs))
	cReproCount := make([]int, len(ReproConfigs))
	syzReproCount := make([]int, len(ReproConfigs))
	totalBugs := len(exp.state.Bugs)

	for _, bug := range exp.state.Bugs {
		row := UIReproExpRow{
			ID:    bug.ID,
			Title: bug.Title,
			Cells: make([]UIReproExpCell, len(ReproConfigs)),
		}
		for i, cfg := range ReproConfigs {
			res := bug.Results[cfg.Key]
			cell := UIReproExpCell{
				Status: ReproStatusPending,
				Style:  template.CSS("color: #888;"),
			}
			if res != nil {
				cell.Status = res.Status
				cell.LogPath = res.LogPath
				cell.TruncatedLog = res.TruncatedLog
				if res.Duration > 0 {
					cell.Tooltip = fmt.Sprintf("duration: %v", res.Duration.Round(time.Second))
				}
				if res.Error != "" {
					if cell.Tooltip != "" {
						cell.Tooltip = fmt.Sprintf("%s | error: %s", cell.Tooltip, res.Error)
					} else {
						cell.Tooltip = fmt.Sprintf("error: %s", res.Error)
					}
				}

				switch res.Status {
				case ReproStatusCRepro:
					cell.Style = template.CSS("color: #2e7d32; font-weight: bold;")
					successCount[i]++
					cReproCount[i]++
				case ReproStatusSyzRepro:
					cell.Style = template.CSS("color: #388e3c; font-weight: bold;")
					successCount[i]++
					syzReproCount[i]++
				case ReproStatusFailed:
					cell.Style = template.CSS("color: #888;")
				case ReproStatusError:
					cell.Style = template.CSS("color: #d32f2f; font-weight: bold;")
				case ReproStatusRunning:
					cell.Style = template.CSS("color: #1976d2; font-weight: bold;")
				default:
					cell.Style = template.CSS("color: #888;")
				}
			}
			row.Cells[i] = cell
		}
		table.Rows = append(table.Rows, row)
	}

	for i := range ReproConfigs {
		if totalBugs == 0 {
			table.Stats[i] = UIColStat{
				Text: "0/0 (0.0%)",
			}
		} else {
			pct := float64(successCount[i]) * 100.0 / float64(totalBugs)
			var breakdown string
			if successCount[i] > 0 {
				breakdown = fmt.Sprintf("C: %d, syz: %d", cReproCount[i], syzReproCount[i])
			}
			table.Stats[i] = UIColStat{
				Text:      fmt.Sprintf("%d/%d (%.1f%%)", successCount[i], totalBugs, pct),
				Breakdown: breakdown,
			}
		}
	}
	return table
}
