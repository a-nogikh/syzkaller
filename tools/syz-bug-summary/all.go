// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/stats/syzbotstats"
)

func actionAllBugs(summaries []syzbotstats.BugStatSummary, discussions *Discussions) error {
	f, err := os.Create("bugs.csv")
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{
		"Title", "ReleasedTime", "FoundReproTime", "CauseBisectTime", "ResolvedTime",
		"Status", "Subsystem", "Type", "Strace", "HitsPerDay", "RemindersCount",
	}
	err = w.Write(header)
	if err != nil {
		return err
	}
	for _, item := range summaries {
		row := []string{
			item.Title,
			fmt.Sprintf("%v", timeOrEmpty(item.ReleasedTime)),
			fmt.Sprintf("%v", timeOrEmpty(item.ReproTime)),
			fmt.Sprintf("%v", timeOrEmpty(item.CauseBisectTime)),
			fmt.Sprintf("%v", timeOrEmpty(item.ResolvedTime)),
			fmt.Sprintf("%s", item.Status),
			oneSubsystem(item.Subsystems),
			fmt.Sprintf("%v", item.Type),
			fmt.Sprintf("%v", item.Strace),
			fmt.Sprintf("%v", item.HitsPerDay),
			fmt.Sprintf("%d", len(item.ReminderTimes)),
		}
		err := w.Write(row)
		if err != nil {
			return err
		}
	}
	return nil
}

func timeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Round(time.Second).String()
}
