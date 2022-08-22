// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagCommand    = flag.String("command", "", "")
	flagDashboard  = flag.String("dashboard", "", "dashboard address")
	flagAPIClient  = flag.String("client", "", "api client")
	flagAPIKey     = flag.String("key", "", "api key")
	flagCacheDir   = flag.String("cache_dir", "", "cache dir (optional)")
	flagKernelRepo = flag.String("kernel_repo", "", "the location of the kernel repo")
	flagLKML       = flag.String("lkml", "", "pre-parsed LKML data")
)

func queryFixStats(dash *dashapi.Dashboard) {
	log.Printf("querying reports..")
	reports, err := queryCachedReports(dash, func(rep *dashapi.BugReport) bool {
		return rep.Namespace == "upstream"
	})
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Printf("querying commits hashes..")
	list, err := queryFixCommits(reports)
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Printf("querying commits info..")
	err = queryCommitObjects(list)
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Printf("parsing LKML records..")
	rawEvents, err := parseLKML(*flagLKML)
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Printf("collecting stats..")
	eventGroups := groupLKML(rawEvents)
	bugReports := map[string]*fixCommitResult{}
	for _, item := range list {
		bugReports[item.bug.Title] = item
	}

	onlyWithRepro := func(i *statsInput) bool { return i.result.bug.ReproSyz != nil }
	//	onlyWithoutRepro := func(i *statsInput) bool { return i.result.bug.ReproSyz == nil }
	//onlyWarning := func(i *statsInput) bool { return strings.HasPrefix(i.result.bug.Title, "WARNING") }
	/*onlyCauseBisected := func(i *statsInput) bool {
		info := i.result.bug.BisectCause
		return info != nil && info.Commit != nil
	}*/
	hasPerfEvent := func(i *statsInput) bool {
		reproSyz := i.result.bug.ReproSyz
		if reproSyz == nil {
			return false
		}
		reproStr := string(reproSyz)
		return strings.Contains(reproStr, "perf_event_open")
	}

	hasStrace := func(i *statsInput) bool {
		return i.result.bug.LogHasStrace
	}

	// TODO: not all fixed bugs are currently marked as fixed (due to pending commits)
	stats := map[string]Stats{
		"Per hour": newPerHour(),
		//		"Per hour (warnings)": statsFilter(newPerHour(), onlyWarning),
		"Has repro": &PerRepro{},
		//	"Per type w/ repro":   statsFilter(newPerType(), onlyWithRepro),
		//	"Per type w/o repro":  statsFilter(newPerType(), onlyWithoutRepro),
		"Share of closed with repro": statsFilter(newClosedGraph(100), onlyWithRepro),
		//		"Share of closed (cause-bisected)": statsFilter(newClosedGraph(100), onlyWithRepro, onlyCauseBisected),
		"Per type": newPerType(),
		//		"Bisect stats":    statsFilter(&currBisectStats{}, onlyWithRepro),
		"perf_event_open": statsFilter(newSlidingShare(hasPerfEvent), onlyWithRepro),
		"strace":          statsFilter(newSlidingShare(hasStrace), onlyWithRepro),
	}
	startTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	endTime := time.Now() //.Add(-time.Hour * 24 * 120)
	filterTime := func(i *statsInput) bool {
		date := i.result.bug.CrashTime
		return date.After(startTime) && date.Before(endTime)
	}
	for title, group := range eventGroups {
		info := bugReports[title]
		if info == nil || group.firstReport.IsZero() {
			continue
		}
		for _, stat := range stats {
			filteredStats := statsFilter(stat, filterTime)
			filteredStats.Record(&statsInput{
				result: info,
				group:  group,
			})
		}
	}
	dumpStats(stats)

	onlyReported := func(i *statsInput) bool { return i.group != nil }
	/*	noNoReproBugs := func(i *statsInput) bool {
			title := i.result.bug.Title
			if strings.HasPrefix(title, "KCSAN") {
				return false
			}
			if strings.Contains(title, "boot error") {
				return false
			}
			if strings.Contains(title, "test error") {
				return false
			}
			return true
		}

		onlyInfo := func(i *statsInput) bool {
			title := i.result.bug.Title
			return strings.HasPrefix(title, "INFO")
		}
	*/
	bugStats := map[string]Stats{
		"Per year": newPerYear(),
		//		"Repro share":     statsFilter(newSlidingReproRate(), onlyReported),
		"Open bug repros": statsFilter(&currReproStats{}, filterTime, onlyReported),
		//		"INFO":            statsFilter(newSlidingShare(onlyInfo), onlyReported),
	}
	for _, info := range list {
		for _, stat := range bugStats {
			stat.Record(&statsInput{
				result: info,
				group:  eventGroups[info.bug.Title],
			})
		}
	}
	dumpStats(bugStats)
}

func dumpStats(stats map[string]Stats) {
	for title, stat := range stats {
		fmt.Printf("\n%s\n", title)
		result := stat.Collect()
		switch v := result.(type) {
		case [][]string:
			printTable(v)
		}
	}
}

func printTable(table [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	for _, row := range table {
		for _, val := range row {
			fmt.Fprintf(w, "%s\t", val)
		}
		fmt.Fprintf(w, "\n")
	}
	w.Flush()
}

func queryCommitObjects(list []*fixCommitResult) error {
	// TODO: make OS and repo type adjustable.
	repo, err := vcs.NewRepo(targets.Linux, "gce", *flagKernelRepo)
	if err != nil {
		return err
	}
	fetcher, ok := repo.(vcs.CommitFetcher)
	if !ok {
		return fmt.Errorf("cannot get commit fetcher")
	}
	tasks := make(chan *fixCommitResult)
	var wg sync.WaitGroup
	const threads = 16
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range tasks {
				if job.commitHash == "" {
					continue
				}
				job.commitObj, _ = fetcher.QueryCommit(job.commitHash)
			}
		}()
	}
	for _, job := range list {
		tasks <- job
	}
	close(tasks)
	wg.Wait()
	return nil
}

type fixCommitResult struct {
	bug        *dashapi.BugReport
	commitHash string
	commitObj  *vcs.Commit
}

func queryFixCommits(bugs map[string]*dashapi.BugReport) ([]*fixCommitResult, error) {
	if *flagKernelRepo == "" {
		return nil, fmt.Errorf("kernel repo is required")
	}
	if *flagCacheDir == "" {
		return nil, fmt.Errorf("cache dir is required")
	}
	commitCache, err := makeCommitSearchCache(*flagKernelRepo, *flagCacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create commit search cache: %s", err)
	}
	titleToJobs := map[string][]*fixCommitResult{}
	titlesToQuery := []string{}
	ret := []*fixCommitResult{}
	for _, bug := range bugs {
		result := &fixCommitResult{bug: bug}
		ret = append(ret, result)
		for _, title := range bug.FixCommitTitles {
			titleToJobs[title] = append(titleToJobs[title], result)
			titlesToQuery = append(titlesToQuery, title)
		}
	}
	hashes, err := commitCache.multiQuery(titlesToQuery)
	if err != nil {
		return nil, err
	}
	for title, hash := range hashes {
		for _, res := range titleToJobs[title] {
			res.commitHash = hash
		}
	}
	return ret, nil
}

func queryCachedReports(dash *dashapi.Dashboard, filter func(*dashapi.BugReport) bool) (map[string]*dashapi.BugReport, error) {
	if dash == nil {
		return nil, fmt.Errorf("dashboard is required")
	}
	cache, err := makeBugCache(*flagCacheDir, dash)
	if err != nil {
		return nil, err
	}
	list, err := cache.cachedIDs()
	if err != nil {
		return nil, err
	}
	return cache.queryMulti(list, filter)
}

func queryBugReports(dash *dashapi.Dashboard, filter func(*dashapi.BugReport) bool) (map[string]*dashapi.BugReport, error) {
	if dash == nil {
		return nil, fmt.Errorf("dashboard is required")
	}
	resp, err := dash.BugList()
	if err != nil {
		return nil, err
	}
	cache, err := makeBugCache(*flagCacheDir, dash)
	if err != nil {
		return nil, err
	}
	return cache.queryMulti(resp.List, filter)
}

func main() {
	flag.Parse()
	var dash *dashapi.Dashboard
	if *flagDashboard != "" {
		var err error
		dash, err = dashapi.New(*flagAPIClient, *flagDashboard, *flagAPIKey)
		if err != nil {
			log.Fatalf("dashapi creation failed: %v", err)
		}
	}
	switch *flagCommand {
	case "test-subsystems":
		querySubsystems(dash)
	case "fix-stats":
		queryFixStats(dash)
	default:
		log.Fatalf("unknown command")
	}
}
