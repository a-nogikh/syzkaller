// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/net/context"
	appengine "google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
)

type stats interface {
	Record(input *bugInput)
	Collect() interface{}
}

// statsFilterStruct allows to embed input filtering to stats collection.
type statsFilterStruct struct {
	nested stats
	filter statsFilter
}

type statsFilter func(input *bugInput) bool

func combineFilters(filters ...statsFilter) statsFilter {
	return func(input *bugInput) bool {
		for _, filter := range filters {
			if !filter(input) {
				return false
			}
		}
		return true
	}
}

func newStatsFilter(nested stats, filters ...statsFilter) stats {
	return &statsFilterStruct{nested: nested, filter: combineFilters(filters...)}
}

func (sf *statsFilterStruct) Record(input *bugInput) {
	if sf.filter(input) {
		sf.nested.Record(input)
	}
}

func (sf *statsFilterStruct) Collect() interface{} {
	return sf.nested.Collect()
}

// bugInput structure contains the information for collecting all bug-related statistics.
type bugInput struct {
	bug           *Bug
	bugReporting  *BugReporting
	reportedCrash *Crash
	build         *Build
	discussions   []*Discussion
}

func (bi *bugInput) foundAt() time.Time {
	return bi.bug.FirstTime
}

func (bi *bugInput) reportedAt() time.Time {
	if bi.bugReporting == nil {
		return time.Time{}
	}
	return bi.bugReporting.Reported
}

func (bi *bugInput) fixedAt() time.Time {
	closeTime := time.Time{}
	if bi.bug.Status == BugStatusFixed {
		closeTime = bi.bug.Closed
	}
	for _, commit := range bi.bug.CommitInfo {
		if closeTime.IsZero() || closeTime.After(commit.Date) {
			closeTime = commit.Date
		}
	}
	return closeTime
}

type statsBugState int

const (
	stateOpen statsBugState = iota
	stateDecisionMade
	stateAutoInvalidated
)

func (bi *bugInput) stateAt(date time.Time) statsBugState {
	bug := bi.bug
	closeTime := bug.Closed
	closeStatus := stateDecisionMade
	if at := bi.fixedAt(); !at.IsZero() {
		closeTime = at
	} else if bug.Status == BugStatusInvalid {
		if bi.bugReporting.Auto {
			closeStatus = stateAutoInvalidated
		}
	}
	if closeTime.IsZero() || date.Before(closeTime) {
		return stateOpen
	}
	return closeStatus
}

func (bi *bugInput) commentedBy(date time.Time) bool {
	for _, d := range bi.discussions {
		for _, m := range d.Messages {
			if m.External && m.Time.Before(date) {
				return true
			}
		}
	}
	return false
}

// Some common bug input filters.

func bugsNoEarlier(since time.Time) statsFilter {
	return func(input *bugInput) bool {
		return input.reportedAt().After(since)
	}
}

func bugsNoLater(now time.Time, days int) statsFilter {
	return func(input *bugInput) bool {
		return now.Sub(input.foundAt()) > time.Hour*24*time.Duration(days)
	}
}

func bugsInReportingStage(name string) statsFilter {
	return func(input *bugInput) bool {
		return input.bugReporting.Name == name
	}
}

func bugsReachedReportingStage(name string) statsFilter {
	return func(input *bugInput) bool {
		for _, rep := range input.bug.Reporting {
			if rep.Name == name {
				return !rep.Reported.IsZero()
			}
		}
		return false
	}
}

func bugsHaveRepro(now time.Time, days int) statsFilter {
	return func(input *bugInput) bool {
		return input.reportedCrash != nil &&
			now.Sub(input.reportedCrash.Time) > time.Hour*24*time.Duration(days) &&
			(input.reportedCrash.ReproSyz != 0 || input.reportedCrash.ReproC != 0)
	}
}

func excludeBadSubsystems(input *bugInput) bool {
	for _, label := range input.bug.Labels {
		if label.Value == "reiserfs" || label.Value == "jfs" || label.Value == "ntfs" || label.Value == "hfs" {
			return false
		}
	}
	return true
}

// allBugInputs queries the raw data about all bugs from a namespace.
func allBugInputs(c context.Context, ns string) ([]*bugInput, error) {
	filter := func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns)
	}
	inputs := []*bugInput{}
	bugs, bugKeys, err := loadAllBugs(c, filter)
	if err != nil {
		return nil, err
	}

	crashKeys := []*db.Key{}
	crashToInput := map[*db.Key]*bugInput{}
	for i, bug := range bugs {
		bugReporting := lastReportedReporting(bug)
		input := &bugInput{
			bug:          bug,
			bugReporting: bugReporting,
		}
		if bugReporting.CrashID != 0 {
			crashKey := db.NewKey(c, "Crash", "", bugReporting.CrashID, bugKeys[i])
			crashKeys = append(crashKeys, crashKey)
			crashToInput[crashKey] = input
		}
		inputs = append(inputs, input)
	}
	// Fetch crashes.
	buildKeys := []*db.Key{}
	buildToInput := map[*db.Key]*bugInput{}
	if len(crashKeys) > 0 {
		crashes := make([]*Crash, len(crashKeys))
		if pos, err := getAllMulti(c, crashKeys, func(i, j int) interface{} {
			return crashes[i:j]
		}); err != nil {
			if pos >= 0 {
				bug := crashToInput[crashKeys[pos]].bug
				return nil, fmt.Errorf("could not extract a crash for %q", bug.displayTitle())
			}
			return nil, fmt.Errorf("failed to fetch crashes: %w", err)
		}
		for i, crash := range crashes {
			if crash == nil {
				continue
			}
			input := crashToInput[crashKeys[i]]
			input.reportedCrash = crash

			buildKey := buildKey(c, ns, crash.BuildID)
			buildKeys = append(buildKeys, buildKey)
			buildToInput[buildKey] = input
		}
	}
	// Fetch builds.
	if len(buildKeys) > 0 {
		builds := make([]*Build, len(buildKeys))
		if _, err := getAllMulti(c, buildKeys, func(i, j int) interface{} {
			return builds[i:j]
		}); err != nil {
			return nil, fmt.Errorf("failed to fetch builds: %w", err)
		}
		for i, build := range builds {
			if build != nil {
				buildToInput[buildKeys[i]].build = build
			}
		}
	}
	// Fetch discussions.
	bugToInput := map[string]*bugInput{}
	for _, info := range inputs {
		bugToInput[info.bug.key(c).StringID()] = info
	}
	err = foreachDiscussion(c, func(d *Discussion, key *db.Key) error {
		if len(d.BugKeys) > 1 {
			return nil
		}
		for _, bugKey := range d.BugKeys {
			bi := bugToInput[bugKey]
			if bi == nil {
				continue
			}
			bi.discussions = append(bugToInput[bugKey].discussions, d)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discussions: %w", err)
	}
	return inputs, nil
}

func getAllMulti(c context.Context, key []*db.Key, getDst func(from, to int) interface{}) (int, error) {
	// Circumventing the datastore multi query limitation.
	const step = 1000
	for from := 0; from < len(key); from += step {
		to := from + step
		if to > len(key) {
			to = len(key)
		}
		err := db.GetMulti(c, key[from:to], getDst(from, to))
		if err == nil {
			continue
		}
		errors, ok := err.(appengine.MultiError)
		if ok {
			for pos, err := range errors {
				if err != nil {
					return from + pos, err
				}
			}
		}
		return -1, err
	}
	return 0, nil
}

type statsCounter struct {
	total int
	match int
}

func (sc *statsCounter) Record(match bool) {
	sc.total++
	if match {
		sc.match++
	}
}

func (sc statsCounter) String() string {
	percent := 0.0
	if sc.total != 0 {
		percent = float64(sc.match) / float64(sc.total) * 100.0
	}
	return fmt.Sprintf("%.2f%% (%d/%d)", percent, sc.match, sc.total)
}

// reactionFactor represents the generic stats collector that measures the effect
// of a single variable on the how it affected the chances of the bug status
// becoming statusDecisionMade in `days` days after reporting.
type reactionFactor struct {
	resolved   reactionSubFactor
	commented  reactionSubFactor
	days       int
	factorName string
	factor     statsFilter
}

func newReactionFactor(days int, name string, factor statsFilter) *reactionFactor {
	return &reactionFactor{
		days:       days,
		factorName: name,
		factor:     factor,
	}
}

func (rf *reactionFactor) Record(input *bugInput) {
	reported := input.reportedAt()
	if input.reportedCrash != nil {
		reported = input.reportedCrash.Time
	}
	byTime := reported.Add(time.Hour * time.Duration(24*rf.days))
	factor := rf.factor(input)
	rf.resolved.record(factor, input.stateAt(byTime) == stateDecisionMade)
	rf.commented.record(factor, input.commentedBy(byTime))
}

func (rf *reactionFactor) Collect() interface{} {
	return [][]string{
		{"", rf.factorName, "No " + rf.factorName, "All"},
		{
			fmt.Sprintf("Resolved in %d days", rf.days),
			rf.resolved.yes.String(),
			rf.resolved.no.String(),
			rf.resolved.all.String(),
		},
		{
			fmt.Sprintf("Commented in %d days", rf.days),
			rf.commented.yes.String(),
			rf.commented.no.String(),
			rf.commented.all.String(),
		},
	}
}

type reactionSubFactor struct {
	all statsCounter
	yes statsCounter
	no  statsCounter
}

func (f *reactionSubFactor) record(factor, result bool) {
	f.all.Record(result)
	if factor {
		f.yes.Record(result)
	} else {
		f.no.Record(result)
	}
}

// Some common factors affecting the attention to the bug.

func newStraceEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Strace", func(bi *bugInput) bool {
		if bi.reportedCrash == nil {
			return false
		}
		return dashapi.CrashFlags(bi.reportedCrash.Flags)&dashapi.CrashUnderStrace > 0
	})
}

func newReproEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Repro", func(bi *bugInput) bool {
		return bi.bug.ReproLevel > 0
	})
}

func newAssetEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Build Assets", func(bi *bugInput) bool {
		if bi.build == nil {
			return false
		}
		return len(bi.build.Assets) > 0
	})
}

func newBisectCauseEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Successful Cause Bisection", func(bi *bugInput) bool {
		return bi.bug.BisectCause == BisectYes
	})
}

func bugHadSubsystem(bi *bugInput) bool {
	for _, info := range bi.discussions {
		if info.Source != string(dashapi.DiscussionLore) {
			continue
		}
		if info.Type != string(dashapi.DiscussionReport) {
			continue
		}
		if strings.Contains(info.Subject, "?]") {
			return true
		}
	}
	return false
}

func newSubsystemEffect(days int) *reactionFactor {
	return newReactionFactor(days, "Subsystem", bugHadSubsystem)
}

func foreachDiscussion(c context.Context, fn func(discussion *Discussion, key *db.Key) error) error {
	const batchSize = 2000
	var cursor *db.Cursor
	for {
		query := db.NewQuery("Discussion").Limit(batchSize)
		if cursor != nil {
			query = query.Start(*cursor)
		}
		iter := query.Run(c)
		for i := 0; ; i++ {
			obj := new(Discussion)
			key, err := iter.Next(obj)
			if err == db.Done {
				if i < batchSize {
					return nil
				}
				break
			}
			if err != nil {
				return fmt.Errorf("failed to fetch discussions: %v", err)
			}
			if err := fn(obj, key); err != nil {
				return err
			}
		}
		cur, err := iter.Cursor()
		if err != nil {
			return fmt.Errorf("cursor failed while fetching discussions: %v", err)
		}
		cursor = &cur
	}
}

type bucketFactor struct {
	resolved map[string]*statsCounter
	days     int
	classify bugToBuckets
}

type bugToBuckets func(*bugInput) []string

func newBucketFactor(days int, f bugToBuckets) *bucketFactor {
	return &bucketFactor{
		days:     days,
		classify: f,
		resolved: map[string]*statsCounter{},
	}
}

func newSingleBucketFactor(days int, f func(*bugInput) string) *bucketFactor {
	return newBucketFactor(days, func(bi *bugInput) []string {
		if ret := f(bi); ret != "" {
			return []string{ret}
		}
		return nil
	})
}

func (bf *bucketFactor) Record(input *bugInput) {
	reported := input.reportedAt()
	if input.reportedCrash != nil {
		reported = input.reportedCrash.Time
	}
	byTime := reported.Add(time.Hour * time.Duration(24*bf.days))
	decisionMade := input.stateAt(byTime) == stateDecisionMade
	for _, name := range bf.classify(input) {
		stat := bf.resolved[name]
		if stat == nil {
			stat = &statsCounter{}
			bf.resolved[name] = stat
		}
		stat.Record(decisionMade)
	}
}

func (bf *bucketFactor) Collect() interface{} {
	ret := [][]string{
		{
			"Kind",
			fmt.Sprintf("Resolved in %d days", bf.days),
		},
	}
	var names []string
	for key := range bf.resolved {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		ret = append(ret, []string{
			key,
			bf.resolved[key].String(),
		})
	}
	return ret
}

var typeRe = regexp.MustCompile(`(?m)^(\w+)`)

func newTypeEffect(days int) *bucketFactor {
	return newSingleBucketFactor(days, func(bi *bugInput) string {
		return typeRe.FindString(bi.bug.Title)
	})
}

func newCrashCountEffect(days int) *bucketFactor {
	return newSingleBucketFactor(days, func(bi *bugInput) string {
		count := bi.bug.NumCrashes
		if count < 5 {
			return "< 5"
		} else if count < 10 {
			return "< 10"
		} else if count < 20 {
			return "< 20"
		}
		return ">= 20"
	})
}

func newSubsystemBucketEffect(days int) *bucketFactor {
	return newBucketFactor(days, func(bi *bugInput) []string {
		var ret []string
		for _, label := range bi.bug.Labels {
			if label.Label == SubsystemLabel {
				ret = append(ret, label.Value)
			}
		}
		return ret
	})
}
