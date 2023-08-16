// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/stats/syzbotstats"
	"github.com/google/syzkaller/pkg/tool"
)

var (
	flagAction      = flag.String("action", "", "")
	flagDiscussions = flag.String("discussions", "", "path to the folder with serialized discussions")
	flagSummary     = flag.String("summary", "", "a json file from /ns/bug-summary")
	flagSkipEmails  = flag.String("skip_emails", "", "a comma-separated list of emails to skip")
)

func main() {
	defer tool.Init()()
	if *flagDiscussions == "" {
		tool.Failf("`discussions `must be specified")
	}
	if *flagSummary == "" {
		tool.Failf("`summary` must be specified")
	}
	discussions, err := LoadDiscussions(*flagDiscussions)
	if err != nil {
		tool.Fail(err)
	}
	log.Printf("loaded %d discussions", len(discussions.List))

	summaries, err := loadSummaries(*flagSummary)
	if err != nil {
		tool.Fail(err)
	}
	log.Printf("loaded %d summaries", len(summaries))

	summaries = filterSummaries(summaries, time.Now())
	log.Printf("%d after filtering", len(summaries))
	for i := range summaries {
		postCalculateSummary(&summaries[i], discussions)
	}

	if len(os.Args) == 1 {
		tool.Failf("you must specify the action")
	}

	switch *flagAction {
	case "list-bugs":
		actionAllBugs(summaries, discussions)
	case "generate":
		actionGenerate(summaries, discussions)
	case "fix-buckets":
		actionFixBuckets(summaries)
	default:
		tool.Failf("unknown action")
	}
}

func actionFixBuckets(summaries []syzbotstats.BugStatSummary) {
	agePerMonth := map[time.Time]map[int]int{}
	fixPerMonth := map[time.Time]map[int]int{}
	// Calculate graps AS IF we were to take measurements at two points in history.
	// Always take last 2 years of reported bugs and fixes up to a point.
	points := []time.Time{
		time.Date(2022, 7, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2023, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	for _, t := range points {
		fixes := map[int]int{}
		const bugAge = time.Hour * 24 * 365 * 1
		for _, bug := range summaries {
			if bug.ResolvedTime.IsZero() ||
				bug.ResolvedTime.After(t) ||
				t.Sub(bug.ResolvedTime) > bugAge {
				continue
			}
			if bug.Status == syzbotstats.BugAutoInvalidated {
				continue
			}
			months := bug.ResolvedTime.Sub(bug.ReleasedTime).Hours() / 24.0 / 30
			fixes[int(months)]++
		}

		age := map[int]int{}
		for _, bug := range summaries {
			if !bug.ResolvedTime.IsZero() && bug.ResolvedTime.Before(t) {
				continue
			}
			diff := t.Sub(bug.ReleasedTime)
			months := diff.Hours() / 24.0 / 30
			for j := 0; j <= int(months); j++ {
				age[j]++
			}
		}

		agePerMonth[t] = age
		fixPerMonth[t] = fixes
	}

	table := [][]string{{"Months"}}
	for _, t := range points {
		table[0] = append(table[0], fmt.Sprintf("%d-%d", t.Year(), t.Month()))
	}

	for i := 0; i < 32; i++ {
		row := []string{
			fmt.Sprintf("%d", i+1),
		}
		for _, t := range points {
			row = append(row,
				fmt.Sprintf("%d/%d (%.3f%%)",
					fixPerMonth[t][i],
					agePerMonth[t][i],
					float64(fixPerMonth[t][i])/float64(agePerMonth[t][i])*100.0,
				))
		}
		table = append(table, row)
	}
	wTab := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
	for _, row := range table {
		for _, cell := range row {
			fmt.Fprintf(wTab, "%s\t", cell)
		}
		fmt.Fprintf(wTab, "\n")
	}
	wTab.Flush()
}

func loadSummaries(path string) ([]syzbotstats.BugStatSummary, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ret []syzbotstats.BugStatSummary
	err = json.Unmarshal(bytes, &ret)
	return ret, err
}

type Discussions struct {
	List  []*dashapi.Discussion
	PerID map[string][]*dashapi.Discussion
}

func LoadDiscussions(dir string) (*Discussions, error) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	ret := &Discussions{
		PerID: map[string][]*dashapi.Discussion{},
	}
	for _, item := range items {
		if item.IsDir() {
			continue
		}
		bytes, err := os.ReadFile(filepath.Join(dir, item.Name()))
		if err != nil {
			return nil, err
		}
		var item dashapi.Discussion
		if err := json.Unmarshal(bytes, &item); err != nil {
			return nil, err
		}
		ret.List = append(ret.List, &item)
		for _, bug := range item.BugIDs {
			ret.PerID[bug] = append(ret.PerID[bug], &item)
		}
	}
	return ret, nil
}

func (d *Discussions) ForBug(ids []string) []*dashapi.Discussion {
	m := map[*dashapi.Discussion]struct{}{}
	for _, id := range ids {
		for _, item := range d.PerID[id] {
			m[item] = struct{}{}
		}
	}
	var ret []*dashapi.Discussion
	for obj := range m {
		ret = append(ret, obj)
	}
	return ret
}
