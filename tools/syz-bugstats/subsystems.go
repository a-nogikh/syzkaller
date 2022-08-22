package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
)

type querySubsystemJob struct {
	bugReport  *dashapi.BugReport
	commitHash string
	results    map[string]*querySubsystemResult
}

type querySubsystemResult struct {
	lists     []string
	debugInfo string
}

func extractMailingLists(guiltyFile, patchFile string) ([]string, error) {
	args := []string{"--email", "--non", "--nom", "--nor", "--separator", ",,,"}
	if guiltyFile != "" {
		args = append(args, "-f", guiltyFile)
	} else if patchFile != "" {
		args = append(args, patchFile)
	}
	script := filepath.FromSlash("scripts/get_maintainer.pl")
	output, err := osutil.RunCmd(time.Minute, *flagKernelRepo, script, args...)
	if err != nil {
		return nil, err
	}
	entries := strings.Split(string(output), ",,,")
	ret := []string{}
	for _, entry := range entries {
		email := strings.Split(entry, " ")[0]
		ret = append(ret, email)
	}
	return ret, nil
}

func fetchCrashSubsystemForJob(job *querySubsystemJob, reporter *report.Reporter) {
	result := &querySubsystemResult{}
	job.results["report"] = result
	rep := reporter.Parse(job.bugReport.Log)
	if rep == nil {
		result.debugInfo = "log is empty"
		return
	}
	rep.Report = job.bugReport.Report
	reporter.Symbolize(rep)
	if rep.GuiltyFile == "" {
		result.debugInfo = "no guilty file"
		return
	}
	tmpList, err := extractMailingLists(rep.GuiltyFile, "")
	if err != nil {
		tmpList, err = extractMailingLists(filepath.Dir(rep.GuiltyFile), "")
		rep.GuiltyFile = rep.GuiltyFile + " (cut)"
		if err != nil {
			result.debugInfo = fmt.Sprintf("get_maintainer.pl error: %s", err)
			return
		}
	}
	result.lists = tmpList
	result.debugInfo = rep.GuiltyFile
	//	result.subsystem = strings.TrimSpace(fmt.Sprintf("%s", output))
}

func fetchCrashSubsystems(jobs []*querySubsystemJob) error {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Linux,
			TargetArch: targets.AMD64,
			SysTarget:  targets.Get(targets.Linux, targets.AMD64),
		},
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		return err
	}

	tasks := make(chan *querySubsystemJob)
	var wg sync.WaitGroup
	const threads = 48
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range tasks {
				fetchCrashSubsystemForJob(job, reporter)
			}
		}()
	}
	done := 0
	const reportingStep = 100
	for _, job := range jobs {
		tasks <- job
		done++
		if done%reportingStep == 0 {
			log.Printf("%d / %d\n", done, len(jobs))
		}
	}
	close(tasks)
	wg.Wait()
	return nil
}

func handlePatch(result *querySubsystemResult, patch []byte) error {
	patchName, err := osutil.WriteTempFile(patch)
	if err != nil {
		return err
	}
	defer os.Remove(patchName)
	result.lists, err = extractMailingLists("", patchName)
	if err != nil {
		result.debugInfo = fmt.Sprintf("get_maintainer.pl error: %s", err)
		return nil
	}
	return nil
}

func fetchSubsystemFromFix(job *querySubsystemJob) {
	if job.commitHash == "" {
		return
	}
	result := &querySubsystemResult{}
	job.results["fix"] = result
	args := []string{"diff-tree", "-p", job.commitHash}
	output, err := osutil.RunCmd(time.Minute, *flagKernelRepo, "git", args...)
	if err != nil {
		result.debugInfo = fmt.Sprintf("git diff-tree error: %s", err)
		return
	}
	handlePatch(result, output)
}

func fetchFixSubsystems(jobs []*querySubsystemJob) error {
	tasks := make(chan *querySubsystemJob)
	var wg sync.WaitGroup
	const threads = 32
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range tasks {
				fetchSubsystemFromFix(job)
			}
		}()
	}
	done := 0
	const reportingStep = 100
	for _, job := range jobs {
		tasks <- job
		done++
		if done%reportingStep == 0 {
			log.Printf("%d / %d\n", done, len(jobs))
		}
	}
	close(tasks)
	wg.Wait()
	return nil
}

func hasIntersection(report, fix []string) bool {
	reportHas := map[string]bool{}
	for _, email := range report {
		if email == "linux-kernel@vger.kernel.org" {
			continue
		}
		reportHas[email] = true
	}
	for _, email := range fix {
		if reportHas[email] {
			return true
		}
	}
	return false
}

func limitReports(reports0 map[string]*dashapi.BugReport) map[string]*dashapi.BugReport {
	reports := map[string]*dashapi.BugReport{}
	limit := 100
	for key, value := range reports0 {
		limit--
		if limit < 0 {
			break
		}
		reports[key] = value
	}
	return reports
}

func querySubsystems(dash *dashapi.Dashboard) {
	if *flagKernelRepo == "" {
		log.Fatalf("kernel repo is required")
	}
	log.Printf("querying bugs from the dashboard..")
	reports, err := queryCachedReports(dash, func(rep *dashapi.BugReport) bool {
		return rep.BugStatus == dashapi.BugStatusFixed && rep.Namespace == "upstream"
	})
	if err != nil {
		log.Fatalf("%s", err)
	}

	log.Printf("querying commits..")
	found, err := queryFixCommits(reports)
	if err != nil {
		log.Fatalf("%s", err)
	}
	jobs := []*querySubsystemJob{}
	for _, res := range found {
		job := &querySubsystemJob{
			bugReport:  res.bug,
			commitHash: res.commitHash,
			results:    map[string]*querySubsystemResult{},
		}
		jobs = append(jobs, job)
	}
	log.Printf("querying subsystems from reports..")
	err = fetchCrashSubsystems(jobs)
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Printf("queryinh subsystems from fixes..")
	err = fetchFixSubsystems(jobs)
	if err != nil {
		log.Fatalf("%s", err)
	}

	subsystems := func(list []string) string {
		return strings.Join(list, ",")
	}

	fmt.Printf("Results:\n")
	table := [][]string{[]string{"Title", "Report", "Debug", "Fix", "Debug", "Intersects", "Dashboard", "Commit"}}
	ok, total := 0, 0
	for _, job := range jobs {
		parts := []string{job.bugReport.Title}
		res := job.results["report"]
		reportLists, fixLists := []string{}, []string{}
		if res == nil {
			parts = append(parts, "???", "")
		} else {
			reportLists = res.lists
			parts = append(parts, subsystems(res.lists), res.debugInfo)
		}
		res = job.results["fix"]
		if res == nil {
			parts = append(parts, "???", "")
		} else {
			fixLists = res.lists
			parts = append(parts, subsystems(res.lists), res.debugInfo)
		}
		intersects := hasIntersection(reportLists, fixLists)
		if intersects {
			ok++
		}
		total++
		parts = append(parts, fmt.Sprintf("%v", intersects))
		parts = append(parts, job.bugReport.Link, job.commitHash)
		table = append(table, parts)
	}

	log.Printf("Total: %d, ok: %d, that's %.2f", total, ok, float64(ok)/float64(total)*100.0)

	f, err := os.Create("results3.csv")
	defer f.Close()

	if err != nil {
		log.Fatalln("failed to open file", err)
	}

	w := csv.NewWriter(f)
	err = w.WriteAll(table) // calls Flush internally
	if err != nil {
		log.Fatal(err)
	}
}
