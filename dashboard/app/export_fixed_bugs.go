// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/gcs"
	"golang.org/x/sync/errgroup"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// handleExportFixedBugs dumps all publicly visible fixed bugs of a namespace that had a reproducer
// (together with all their reproducer crashes and the crashes of their publicly visible duplicates)
// as a publicly readable .jsonl.gz file to GCS.
//
// It's meant to be run as a one-off and may take longer than the 10 minute request deadline
// of automatically scaled instances. So deploy it as a separate no-traffic version with basic
// scaling (24h deadline), see app.yaml, e.g.:
//
//	gcloud app deploy ./dashboard/app/app.yaml --project syzkaller --version=export --no-promote
//
// and then open:
//
//	https://export-dot-syzkaller.appspot.com/export_fixed_bugs?ns=upstream&bucket=BUCKET
//
// The endpoint is public, so the request only determines the bucket, but not the object name
// (it's timestamped and placed under exportFixedBugsDir), and only one export may run at a time.
func handleExportFixedBugs(w http.ResponseWriter, r *http.Request) {
	// Don't abort the export if the client disconnects (e.g. the browser tab gets closed).
	ctx := context.WithoutCancel(r.Context())
	ns := r.FormValue("ns")
	nsConfig := getConfig(ctx).Namespaces[ns]
	if nsConfig == nil || nsConfig.AccessLevel != AccessPublic {
		http.Error(w, "unknown or non-public namespace", http.StatusBadRequest)
		return
	}
	bucket := r.FormValue("bucket")
	if !gcsBucketRe.MatchString(bucket) {
		http.Error(w, "invalid bucket name", http.StatusBadRequest)
		return
	}
	if !exportFixedBugsRunning.CompareAndSwap(false, true) {
		http.Error(w, "another export is already running", http.StatusConflict)
		return
	}
	defer exportFixedBugsRunning.Store(false)
	path := fmt.Sprintf("%v/%v/%v-%v.jsonl.gz", bucket, exportFixedBugsDir, ns,
		timeNow(ctx).UTC().Format("20060102-150405"))
	log.Infof(ctx, "exporting %v fixed bugs to gs://%v", ns, path)
	stats, err := exportFixedBugsToGCS(ctx, ns, path)
	if err != nil {
		log.Errorf(ctx, "fixed bugs export failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "exported %v bugs with %v crashes to https://storage.googleapis.com/%v\n",
		stats.Bugs, stats.Crashes, path)
	fmt.Fprintf(w, "skipped (no repro crashes left): %v\n", stats.NoCrashes)
	fmt.Fprintf(w, "failed: %v\n", len(stats.Failed))
	for _, msg := range stats.Failed {
		fmt.Fprintf(w, "  %v\n", msg)
	}
}

const (
	exportFixedBugsDir = "syzbot-fixed-bugs"
	// Each worker keeps the crash texts of up to exportCrashChunk crashes in memory at a time,
	// plus the compressed output for the bug it's processing.
	exportFixedBugsWorkers = 16
	// The B8 instance has 3GB of memory, let GC work harder before we approach the limit.
	exportMemoryLimit = 2 << 30
)

var (
	exportCrashChunk       = 16
	exportFixedBugsRunning atomic.Bool
	// See https://cloud.google.com/storage/docs/buckets#naming.
	gcsBucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)
)

func exportFixedBugsToGCS(ctx context.Context, ns, path string) (*exportStats, error) {
	prevLimit := debug.SetMemoryLimit(exportMemoryLimit)
	defer debug.SetMemoryLimit(prevLimit)
	// Cancelling the context aborts the upload, so that a partial object is not committed on errors.
	gcsCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	client, err := gcs.NewClient(gcsCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()
	gcsWriter, err := client.FileWriter(path, "application/gzip", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS writer: %w", err)
	}
	stats, err := exportFixedBugs(ctx, ns, gcsWriter, exportFixedBugsWorkers)
	if err != nil {
		return nil, err
	}
	if err := gcsWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to finish GCS upload: %w", err)
	}
	if err := client.Publish(path); err != nil {
		return nil, fmt.Errorf("failed to publish the export: %w", err)
	}
	return stats, nil
}

type exportStats struct {
	Bugs      int
	Crashes   int
	NoCrashes int
	Failed    []string
}

// exportBug is one line of the output.
type exportBug struct {
	exportBugInfo
	Crashes []*exportCrash `json:"crashes"`
}

type exportBugInfo struct {
	ID             string           `json:"id"`
	Title          string           `json:"title"`
	FirstTime      time.Time        `json:"first_time"`
	LastTime       time.Time        `json:"last_time"`
	FixTime        time.Time        `json:"fix_time,omitzero"`
	ClosedTime     time.Time        `json:"closed_time,omitzero"`
	Labels         []exportLabel    `json:"labels,omitempty"`
	FixCommits     []exportCommit   `json:"fix_commits,omitempty"`
	CauseBisection *exportBisection `json:"cause_bisection,omitempty"`
	FixBisection   *exportBisection `json:"fix_bisection,omitempty"`
	Dups           []exportDupBug   `json:"dups,omitempty"`
}

type exportLabel struct {
	Label string `json:"label"`
	Value string `json:"value,omitempty"`
}

type exportCommit struct {
	Hash  string `json:"hash,omitempty"`
	Title string `json:"title"`
}

type exportBisection struct {
	AI           bool           `json:"ai"`
	Status       string         `json:"status"`
	KernelRepo   string         `json:"kernel_repo,omitempty"`
	KernelBranch string         `json:"kernel_branch,omitempty"`
	Commits      []exportCommit `json:"commits,omitempty"`
	// Flags are syz-ci bisection result flags (e.g. "[merge commit]").
	Flags string `json:"flags,omitempty"`
	// StillPresent is set if an AI fix bisection concluded that the bug was not fixed.
	StillPresent bool `json:"still_present,omitempty"`
}

type exportDupBug struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type exportCrash struct {
	// ID is the datastore ID of the crash (unique within BugID).
	ID int64 `json:"id"`
	// BugID is the bug the crash belongs to: either the exported bug or one of its dups.
	BugID           string    `json:"bug_id"`
	Time            time.Time `json:"time"`
	Title           string    `json:"title"`
	Manager         string    `json:"manager"`
	Report          string    `json:"report"`
	KernelRepo      string    `json:"kernel_repo"`
	KernelBranch    string    `json:"kernel_branch"`
	KernelCommit    string    `json:"kernel_commit"`
	KernelConfig    string    `json:"kernel_config"`
	SyzkallerCommit string    `json:"syzkaller_commit"`
	ReproOpts       string    `json:"repro_opts,omitempty"`
	SyzRepro        string    `json:"syz_repro,omitempty"`
	CRepro          string    `json:"c_repro,omitempty"`
	ReproIsRevoked  bool      `json:"repro_is_revoked,omitempty"`
}

// pendingCrash is a crash to be exported, whose texts are not loaded yet.
type pendingCrash struct {
	bug   *Bug
	key   *db.Key
	crash *Crash
	build *Build
}

// exportFixedBugs writes the gzip-compressed jsonl dump to w.
// Errors related to individual bugs are recorded in the stats, but they don't abort the export.
//
// To make use of multiple CPUs, each bug is compressed by its worker as a separate gzip member.
// A concatenation of gzip members is a valid gzip stream (decoders read it as a single file).
func exportFixedBugs(ctx context.Context, ns string, w io.Writer, workers int) (*exportStats, error) {
	var fixedBugs, dupBugs []*Bug
	g, _ := errgroup.WithContext(ctx)
	for status, list := range map[int]*[]*Bug{BugStatusFixed: &fixedBugs, BugStatusDup: &dupBugs} {
		g.Go(func() error {
			return foreachBug(ctx, func(query *db.Query) *db.Query {
				return query.Filter("Namespace=", ns).Filter("Status=", status)
			}, func(bug *Bug, _ *db.Key) error {
				*list = append(*list, bug)
				return nil
			})
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	dups := make(map[string][]*Bug)
	for _, bug := range dupBugs {
		dups[bug.DupOf] = append(dups[bug.DupOf], bug)
	}
	log.Infof(ctx, "export: loaded %v fixed and %v dup bugs", len(fixedBugs), len(dupBugs))

	var (
		mu        sync.Mutex
		stats     = &exportStats{}
		processed atomic.Int64
	)
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	for _, bug := range fixedBugs {
		if !publiclyVisible(ctx, bug) {
			continue
		}
		group := []*Bug{bug}
		for _, dup := range collectDups(ctx, bug, dups) {
			if publiclyVisible(ctx, dup) {
				group = append(group, dup)
			}
		}
		if !slices.ContainsFunc(group, func(b *Bug) bool { return b.HasSyzRepro || b.HasCRepro }) {
			continue
		}
		g.Go(func() error {
			if n := processed.Add(1); n%100 == 0 {
				log.Infof(ctx, "export: processed %v bugs", n)
			}
			if gCtx.Err() != nil {
				return gCtx.Err()
			}
			compressed, numCrashes, err := exportBugGroup(ctx, group)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				msg := fmt.Sprintf("%v: %v", bug.keyHash(ctx), err)
				log.Errorf(ctx, "export: %v", msg)
				stats.Failed = append(stats.Failed, msg)
				return nil
			}
			if numCrashes == 0 {
				stats.NoCrashes++
				return nil
			}
			stats.Bugs++
			stats.Crashes += numCrashes
			// Write errors are fatal: the output is broken anyway.
			_, err = w.Write(compressed)
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return stats, nil
}

// exportBugGroup returns the gzip-compressed JSON line for the bug and its duplicates
// (group[0] is the main bug) and the number of exported crashes.
// Panics are converted to errors, so that an unexpected entity state does not abort the whole export.
func exportBugGroup(ctx context.Context, group []*Bug) (compressed []byte, numCrashes int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
		}
	}()
	info, crashes, err := loadExportBug(ctx, group)
	if err != nil || len(crashes) == 0 {
		return nil, 0, err
	}
	compressed, err = compressExportBug(ctx, info, crashes)
	return compressed, len(crashes), err
}

// compressExportBug serializes the bug as a JSON line equivalent to exportBug.
// Crash texts (most notably, kernel configs) take most of the space, so they are loaded
// and serialized in chunks to limit memory consumption.
func compressExportBug(ctx context.Context, info *exportBugInfo, crashes []*pendingCrash) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	data, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	// Drop the closing brace to append the crashes field.
	gz.Write(data[:len(data)-1])
	gz.Write([]byte(`,"crashes":[`))
	for start := 0; start < len(crashes); start += exportCrashChunk {
		chunk := crashes[start:min(start+exportCrashChunk, len(crashes))]
		texts := newTextLoader()
		for _, pc := range chunk {
			texts.add(textCrashReport, pc.crash.Report)
			texts.add(textReproSyz, pc.crash.ReproSyz)
			texts.add(textReproC, pc.crash.ReproC)
			texts.add(textKernelConfig, pc.build.KernelConfig)
		}
		if err := texts.load(ctx); err != nil {
			return nil, err
		}
		for i, pc := range chunk {
			data, err := json.Marshal(makeExportCrash(ctx, pc, texts))
			if err != nil {
				return nil, err
			}
			if start+i != 0 {
				gz.Write([]byte(","))
			}
			gz.Write(data)
		}
	}
	gz.Write([]byte("]}\n"))
	// Writes to bytes.Buffer don't fail, so it's enough to check the result of Close.
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func makeExportCrash(ctx context.Context, pc *pendingCrash, texts *textLoader) *exportCrash {
	title := pc.crash.Title
	if title == "" {
		title = pc.bug.Title
	}
	return &exportCrash{
		ID:              pc.key.IntID(),
		BugID:           pc.bug.keyHash(ctx),
		Time:            pc.crash.Time,
		Title:           title,
		Manager:         pc.crash.Manager,
		Report:          texts.get(textCrashReport, pc.crash.Report),
		KernelRepo:      pc.build.KernelRepo,
		KernelBranch:    pc.build.KernelBranch,
		KernelCommit:    pc.build.KernelCommit,
		KernelConfig:    texts.get(textKernelConfig, pc.build.KernelConfig),
		SyzkallerCommit: pc.build.SyzkallerCommit,
		ReproOpts:       string(pc.crash.ReproOpts),
		SyzRepro:        texts.get(textReproSyz, pc.crash.ReproSyz),
		CRepro:          texts.get(textReproC, pc.crash.ReproC),
		ReproIsRevoked:  pc.crash.ReproIsRevoked,
	}
}

// publiclyVisible says if the bug is visible on the public dashboard.
func publiclyVisible(ctx context.Context, bug *Bug) bool {
	// sanitizeAccess modifies the bug (e.g. it resets DupOf), so give it a copy.
	tmp := *bug
	tmp.Reporting = slices.Clone(bug.Reporting)
	return AccessPublic >= tmp.sanitizeAccess(ctx, AccessPublic)
}

// collectDups returns all transitive duplicates of the bug.
func collectDups(ctx context.Context, bug *Bug, dups map[string][]*Bug) []*Bug {
	var ret []*Bug
	visited := map[string]bool{}
	queue := []string{bug.keyHash(ctx)}
	for len(queue) > 0 {
		hash := queue[0]
		queue = queue[1:]
		if visited[hash] {
			continue
		}
		visited[hash] = true
		for _, dup := range dups[hash] {
			ret = append(ret, dup)
			queue = append(queue, dup.keyHash(ctx))
		}
	}
	return ret
}

// loadExportBug loads everything except for the crash texts.
func loadExportBug(ctx context.Context, group []*Bug) (*exportBugInfo, []*pendingCrash, error) {
	bug := group[0]
	ret := &exportBugInfo{
		ID:         bug.keyHash(ctx),
		Title:      bug.displayTitle(),
		FirstTime:  bug.FirstTime,
		LastTime:   bug.LastTime,
		FixTime:    bug.FixTime,
		ClosedTime: bug.Closed,
	}
	for _, label := range bug.Labels {
		ret.Labels = append(ret.Labels, exportLabel{Label: string(label.Label), Value: label.Value})
	}
	for i, title := range bug.Commits {
		com := exportCommit{Title: title}
		if i < len(bug.CommitInfo) {
			com.Hash = bug.CommitInfo[i].Hash
		}
		ret.FixCommits = append(ret.FixCommits, com)
	}
	for _, dup := range group[1:] {
		ret.Dups = append(ret.Dups, exportDupBug{ID: dup.keyHash(ctx), Title: dup.displayTitle()})
	}
	// Datastore queries take most of the time, so run them in parallel.
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		ret.CauseBisection, err = makeExportBisection(ctx, bug, JobBisectCause, &bug.AIBisectCause, bug.BisectCause)
		return err
	})
	g.Go(func() error {
		var err error
		ret.FixBisection, err = makeExportBisection(ctx, bug, JobBisectFix, &bug.AIBisectFix, bug.BisectFix)
		return err
	})
	crashes := make([][]*pendingCrash, len(group))
	for i, b := range group {
		g.Go(func() error {
			var err error
			crashes[i], err = loadExportCrashes(ctx, b)
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}
	allCrashes := slices.Concat(crashes...)
	slices.SortStableFunc(allCrashes, func(a, b *pendingCrash) int {
		return a.crash.Time.Compare(b.crash.Time)
	})
	return ret, allCrashes, nil
}

// makeExportBisection mirrors the logic of the bug page: AI results take priority over syz-ci ones.
func makeExportBisection(ctx context.Context, bug *Bug, typ JobType, ai *BugAIBisect,
	status BisectStatus) (*exportBisection, error) {
	if ai.present() {
		ret := &exportBisection{
			AI:           true,
			Status:       ai.status(status).String(),
			KernelRepo:   ai.KernelRepo,
			StillPresent: ai.StillPresent,
		}
		for _, com := range ai.Commits {
			ret.Commits = append(ret.Commits, exportCommit{Hash: com.Hash, Title: com.Title})
		}
		return ret, nil
	}
	if status <= BisectPending {
		return nil, nil
	}
	jobs, err := queryBugJobs(ctx, bug, typ)
	if err != nil {
		return nil, err
	}
	best := jobs.bestBisection()
	if best == nil {
		return nil, nil
	}
	job := best.job
	ret := &exportBisection{
		Status:       status.String(),
		KernelRepo:   job.KernelRepo,
		KernelBranch: job.KernelBranch,
		Flags:        job.Flags.String(),
	}
	for _, com := range job.Commits {
		ret.Commits = append(ret.Commits, exportCommit{Hash: com.Hash, Title: com.Title})
	}
	return ret, nil
}

// loadExportCrashes loads the bug's crashes with reproducers and their builds.
func loadExportCrashes(ctx context.Context, bug *Bug) ([]*pendingCrash, error) {
	var all []*Crash
	keys, err := db.NewQuery("Crash").Ancestor(bug.key(ctx)).GetAll(ctx, &all)
	if err != nil {
		return nil, fmt.Errorf("failed to query crashes: %w", err)
	}
	var ret []*pendingCrash
	for i, crash := range all {
		if crash.ReproSyz != 0 || crash.ReproC != 0 {
			ret = append(ret, &pendingCrash{bug: bug, key: keys[i], crash: crash})
		}
	}
	if len(ret) == 0 {
		return nil, nil
	}
	var buildIDs []string
	for _, pc := range ret {
		if !slices.Contains(buildIDs, pc.crash.BuildID) {
			buildIDs = append(buildIDs, pc.crash.BuildID)
		}
	}
	var buildKeys []*db.Key
	for _, id := range buildIDs {
		buildKeys = append(buildKeys, buildKey(ctx, bug.Namespace, id))
	}
	builds := make([]*Build, len(buildKeys))
	if err := getMultiChunked(ctx, buildKeys, builds); err != nil {
		return nil, fmt.Errorf("failed to load builds: %w", err)
	}
	for _, pc := range ret {
		pc.build = builds[slices.Index(buildIDs, pc.crash.BuildID)]
	}
	return ret, nil
}

// textLoader fetches the Text entities in bulk.
type textLoader struct {
	ids    map[string][]int64
	loaded map[string]map[int64]string
}

func newTextLoader() *textLoader {
	return &textLoader{
		ids:    make(map[string][]int64),
		loaded: make(map[string]map[int64]string),
	}
}

func (tl *textLoader) add(tag string, id int64) {
	if id != 0 && !slices.Contains(tl.ids[tag], id) {
		tl.ids[tag] = append(tl.ids[tag], id)
	}
}

func (tl *textLoader) load(ctx context.Context) error {
	var keys []*db.Key
	for tag, ids := range tl.ids {
		for _, id := range ids {
			keys = append(keys, db.NewKey(ctx, tag, "", id, nil))
		}
	}
	texts := make([]*Text, len(keys))
	if err := getMultiChunked(ctx, keys, texts); err != nil {
		return fmt.Errorf("failed to load texts: %w", err)
	}
	for i, key := range keys {
		data, err := decompressText(texts[i])
		if err != nil {
			return fmt.Errorf("failed to decompress text %v: %w", key, err)
		}
		if tl.loaded[key.Kind()] == nil {
			tl.loaded[key.Kind()] = make(map[int64]string)
		}
		tl.loaded[key.Kind()][key.IntID()] = string(data)
	}
	return nil
}

func (tl *textLoader) get(tag string, id int64) string {
	return tl.loaded[tag][id]
}

func getMultiChunked[T any](ctx context.Context, keys []*db.Key, dst []*T) error {
	const chunk = 500
	for i := range dst {
		dst[i] = new(T)
	}
	for start := 0; start < len(keys); start += chunk {
		end := min(start+chunk, len(keys))
		if err := db.GetMulti(ctx, keys[start:end], dst[start:end]); err != nil {
			return err
		}
	}
	return nil
}
