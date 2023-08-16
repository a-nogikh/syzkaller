// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/stats/syzbotstats"
	"github.com/google/syzkaller/pkg/tool"
)

func actionGenerate(summaries []syzbotstats.BugStatSummary, discussions *Discussions) {
	now := time.Now()
	var resolved, commented, activity []syzbotstats.BugState
	for _, s := range summaries {
		s.ReminderTimes = nil
		states := syzbotstats.GetBugStates(s, time.Now())
		for i := range states {
			state := &states[i]
			state.ReportedIn14 = countReported(state, summaries, time.Hour*24*14)
			state.ReportedIn60 = countReported(state, summaries, time.Hour*24*60)
			state.SubsystemReported = s.SubsystemReported
			state.Subsystems = s.Subsystems
			state.OnlyNext = s.OnlyNext
			state.Title = s.Title
			state.EndStatus = s.Status
		}
		for _, state := range states {
			// Only take a state if:
			// a) Nothing happened in [t;t+cutOff] and t+cutOff <= now.
			// b) Something happened in [t;min(t+cutOff,duration)].
			// Otherwise we can attribute nothing to the state.
			takeResolved, bugResolved := takeState(state, s.ResolvedTime, now)
			state.Resolved = bugResolved

			if bugResolved && s.Status == syzbotstats.BugAutoInvalidated {
				takeResolved = false
				state.Resolved = false
			}

			if takeResolved {
				resolved = append(resolved, state)
			}
			takeCommented, bugCommented := takeState(state,
				earliestComment(&s, state.Time, discussions),
				now)
			state.Commented = bugCommented
			if takeCommented {
				commented = append(commented, state)
			}
			if takeResolved || takeCommented {
				activity = append(activity, state)
			}
		}
	}
	err := writeResult(resolved, "resolved")
	if err != nil {
		tool.Fail(err)
	}
	err = writeResult(commented, "commented")
	if err != nil {
		tool.Fail(err)
	}
	err = writeResult(activity, "action")
	if err != nil {
		tool.Fail(err)
	}
}

func takeState(state syzbotstats.BugState, event, now time.Time) (bool, bool) {
	const cutOff = time.Hour * 24 * 30
	if !event.IsZero() &&
		event.After(state.Time) &&
		event.Sub(state.Time) <= cutOff &&
		event.Sub(state.Time) <= state.Duration {
		// Event happened during the state within cutOff.
		return true, true
	}
	if event.IsZero() && now.Sub(state.Time) >= cutOff {
		// Event did not happend and enough time has passed.
		return true, false
	}
	if !event.IsZero() && event.Sub(state.Time) > cutOff {
		// There's enough time until the event.
		return true, false
	}
	return false, false
}

func countReported(base *syzbotstats.BugState, list []syzbotstats.BugStatSummary, cutOff time.Duration) int {
	ret := 0
	for _, item := range list {
		if !stringListsIntersect(item.Subsystems, base.Subsystems) {
			continue
		}
		if item.ReleasedTime.After(base.Time) {
			continue
		}
		if base.Time.Sub(item.ReleasedTime) < cutOff {
			ret++
		}
	}
	return ret
}

func stringListsIntersect(a, b []string) bool {
	m := map[string]bool{}
	for _, strA := range a {
		m[strA] = true
	}
	for _, strB := range b {
		if m[strB] {
			return true
		}
	}
	return false
}

var typeMap = map[string]string{
	"warning in":                   "warning",
	"kernel bug in":                "bug",
	"kernel bug at":                "bug",
	"warning: odebug":              "bug",
	"warning: kmalloc":             "bug",
	"bug: corrupted list in":       "bug",
	"kcsan:":                       "kcsan",
	"kasan:":                       "kasan",
	"kmsan:":                       "kmsan",
	"possible deadlock":            "lockdep",
	"inconsistent lock state":      "lockdep",
	"warning: locking":             "lockdep",
	"warning: nested lock was not": "lockdep",
	"warning: back unlock":         "lockdep",
	"warning: bad unlock balance":  "lockdep",
	"warning: lock held when":      "lockdep",
	"general protection fault":     "gpf",
	"info: task hung":              "hung",
	"info: rcu":                    "hung",
	"memory leak":                  "leak",
	"ubsan:":                       "ubsan",
	"warning: refcount":            "refcount",
	"bug: unable to handle kernel paging request": "bad_paging",
	"bug: unable to handle kernel null":           "null_ptr",
	"info: task can't die":                        "cant_die",
	"bug: soft lockup":                            "soft_lockup",
	"info: trying to register non-static key in":  "non_static_key",
	"divide error in":                             "divide_error",
	"bug: sleeping function called":               "bad_sleep",
	"warning: suspicious rcu usage in":            "suspicious_rcu",
	"kernel panic: corrupted stack end in":        "corrupted_stack_end",
	"bug: stack guard page was hit in":            "stack_guard_page",
}

func setType(s *syzbotstats.BugStatSummary) {
	title := strings.ToLower(s.Title)
	for prefix, t := range typeMap {
		if strings.HasPrefix(title, prefix) {
			s.Type = t
			return
		}
	}
	s.Type = "unknown"
}

var hadSubsystem = regexp.MustCompile(`(?m)\[\w+\?\]`)

func postCalculateSummary(s *syzbotstats.BugStatSummary, d *Discussions) {
	setType(s)
	for _, d := range d.ForBug(s.IDs) {
		if d.Source != dashapi.DiscussionLore {
			continue
		}
		if d.Type == dashapi.DiscussionReport {
			s.SubsystemReported = s.SubsystemReported ||
				hadSubsystem.MatchString(d.Subject)
		}
		if d.Type == dashapi.DiscussionReminder {
			var first time.Time
			for _, m := range d.Messages {
				if first.IsZero() || first.After(m.Time) {
					first = m.Time
				}
			}
			if !first.IsZero() {
				s.ReminderTimes = append(s.ReminderTimes, first)
			}
		}
	}
	sort.Slice(s.ReminderTimes, func(i, j int) bool {
		return s.ReminderTimes[i].Before(s.ReminderTimes[j])
	})
	if len(s.ReminderTimes) > 1 {
		// Only leave the first.
		s.ReminderTimes = s.ReminderTimes[:1]
	}
}

func earliestComment(s *syzbotstats.BugStatSummary, after time.Time, d *Discussions) time.Time {
	var ret time.Time
	for _, d := range d.ForBug(s.IDs) {
		if d.Source != dashapi.DiscussionLore {
			continue
		}
		for _, m := range d.Messages {
			// Not informative for statistics.
			if strings.Contains(*flagSkipEmails, m.Email) {
				continue
			}
			if !m.External {
				continue
			}
			if m.Time.Before(after) {
				continue
			}
			if ret.IsZero() || ret.After(m.Time) {
				ret = m.Time
			}
		}
	}
	return ret
}

func writeResult(list []syzbotstats.BugState, t string) error {
	log.Printf("writing %s %d result entries", t, len(list))
	f, err := os.Create(fmt.Sprintf("output_%s.csv", t))
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{
		"Time", "Skip_Title", "Skip_Verdict",
		"Month", "Hour", "WeekDay",
		"Repro", "CauseBisect", "Type", "Strace",
		"Hits", "ReportedIn14Days", "ReportedIn60Days",
		"Subsystem", "OnlyNext", "Reminders",
	}
	if t == "resolved" {
		header = append(header, "Resolved")
	} else if t == "commented" {
		header = append(header, "Commented")
	} else if t == "action" {
		header = append(header, "ActedUpon")
	} else {
		panic(t)
	}
	err = w.Write(header)
	if err != nil {
		return err
	}
	for _, item := range list {
		tt := item.Time.UTC()
		row := []string{
			fmt.Sprintf("%v", tt.String()),
			fmt.Sprintf("%v", item.Title),
			fmt.Sprintf("%v", item.EndStatus),
			fmt.Sprintf("%d", tt.Month()),
			fmt.Sprintf("%v", tt.Hour()),
			fmt.Sprintf("%d", tt.Weekday()),
			fmt.Sprintf("%v", item.Repro),
			fmt.Sprintf("%v", item.CauseBisect),
			item.Type,
			fmt.Sprintf("%v", item.Strace),
			fmt.Sprintf("%f", item.HitsPerDay),
			fmt.Sprintf("%d", item.ReportedIn14),
			fmt.Sprintf("%d", item.ReportedIn60),
			oneSubsystem(item.Subsystems),
			fmt.Sprintf("%v", item.OnlyNext),
			fmt.Sprintf("%d", item.Reminders),
		}
		if t == "resolved" {
			row = append(row, fmt.Sprintf("%v", item.Resolved))
		} else if t == "commented" {
			row = append(row, fmt.Sprintf("%v", item.Commented))
		} else if t == "action" {
			row = append(row, fmt.Sprintf("%v", item.Resolved || item.Commented))
		} else {
			panic(t)
		}
		err := w.Write(row)
		if err != nil {
			return err
		}
	}
	return nil
}

func oneSubsystem(subsystems []string) string {
	if len(subsystems) > 0 {
		sort.Strings(subsystems)
		return subsystems[0]
	}
	return ""
}

func filterSummaries(in []syzbotstats.BugStatSummary, now time.Time) []syzbotstats.BugStatSummary {
	const tooFresh = time.Hour * 24 * 14
	var ret []syzbotstats.BugStatSummary
	for _, s := range in {
		if s.ReleasedTime.Year() < 2020 || now.Sub(s.ReleasedTime) < tooFresh {
			continue
		}
		if !s.ResolvedTime.IsZero() && s.ResolvedTime.Before(s.ReleasedTime) {
			continue
		}
		if s.ResolvedTime.IsZero() && s.Status != syzbotstats.BugPending {
			continue
		}
		if strings.Contains(s.Title, "boot error") ||
			strings.Contains(s.Title, "build error") ||
			strings.Contains(s.Title, "test error") ||
			strings.Contains(s.Title, "syzkaller") ||
			strings.Contains(s.Title, "runtime error") ||
			strings.Contains(s.Title, "fatal error:") ||
			strings.Contains(s.Title, "SYZFAIL") ||
			strings.HasPrefix(s.Title, "panic: ") ||
			strings.Contains(s.Title, "fbcon: Driver 'vkmsdrmfb' missed to adjust virtual screen size (") {
			continue
		}
		if s.Status == syzbotstats.BugDup {
			continue
		}
		ret = append(ret, s)
	}
	return ret
}
