// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzbotstats

import (
	"sort"
	"time"
)

type BugStatSummary struct {
	Title           string
	AltTitles       []string
	IDs             []string  // IDs used by syzbot for this bug.
	ReleasedTime    time.Time // When the bug was published.
	ReproTime       time.Time // When we found the reproducer.
	CauseBisectTime time.Time // When we found cause bisection.
	ResolvedTime    time.Time // When the bug was resolved.
	Status          BugStatus
	Subsystems      []string
	Strace          bool    // Whether we managed to reproduce under strace.
	HitsPerDay      float64 // Average number of bug hits per day.
	OnlyNext        bool

	// Post-calculated data.
	Type              string
	SubsystemReported bool
	ReminderTimes     []time.Time
}

type BugStatus string

const (
	BugFixed           BugStatus = "fixed"
	BugInvalidated     BugStatus = "invalidated"
	BugAutoInvalidated BugStatus = "auto-invalidated"
	BugDup             BugStatus = "dup"
	BugPending         BugStatus = "pending"
)

type BugState struct {
	Time        time.Time
	Repro       bool
	CauseBisect bool
	Reminders   int
	Duration    time.Duration

	Type       string
	Strace     bool
	Assets     bool
	HitsPerDay float64

	// Filled later.
	OnlyNext          bool
	Subsystems        []string
	SubsystemReported bool
	ReportedIn14      int
	ReportedIn60      int
	Resolved          bool
	Commented         bool
	Title             string
	EndStatus         BugStatus
}

func GetBugStates(summary BugStatSummary, now time.Time) []BugState {
	points := map[time.Time]bool{
		summary.ReleasedTime:    true,
		summary.ReproTime:       true,
		summary.CauseBisectTime: true,
	}
	for _, p := range summary.ReminderTimes {
		points[p] = true
	}

	var ret []BugState
	for t := range points {
		if t.IsZero() || t.Equal(summary.ResolvedTime) ||
			!summary.ResolvedTime.IsZero() && t.After(summary.ResolvedTime) {
			continue
		}
		hasRepro := !summary.ReproTime.IsZero() && (summary.ReproTime.Before(t) || summary.ReproTime.Equal(t))
		hasCauseBisect := !summary.CauseBisectTime.IsZero() && (summary.CauseBisectTime.Before(t) || summary.CauseBisectTime.Equal(t))
		reminders := 0
		for _, p := range summary.ReminderTimes {
			if !p.After(t) {
				reminders++
			}
		}
		ret = append(ret, BugState{
			Time:        t,
			Repro:       hasRepro,
			CauseBisect: hasCauseBisect,
			Reminders:   reminders,

			Type:       summary.Type,
			Strace:     summary.Strace && hasRepro,
			HitsPerDay: summary.HitsPerDay,
			Subsystems: summary.Subsystems,
		})
	}
	if len(ret) == 0 {
		return ret
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].Time.Before(ret[j].Time)
	})
	for i := range ret {
		end := now
		if i+1 < len(ret) {
			end = ret[i+1].Time
		} else if !summary.ResolvedTime.IsZero() {
			end = summary.ResolvedTime
		}
		ret[i].Duration = end.Sub(ret[i].Time)
	}
	return ret
}
