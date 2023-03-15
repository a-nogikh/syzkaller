// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/hash"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

const maxListQueriesPerPoll = 5

// reportingPollBugs is called by backends to get bug lists that need to be reported.
func reportingPollBugLists(c context.Context, typ string) []*dashapi.BugListReport {
	state, err := loadReportingState(c)
	if err != nil {
		log.Errorf(c, "%v", err)
		return nil
	}
	registry, err := makeSubsystemRegistry(c)
	if err != nil {
		log.Errorf(c, "failed to load subsystems: %v", err)
		return nil
	}
	updateLimit := maxListQueriesPerPoll
	ret := []*dashapi.BugListReport{}
	for ns, nsConfig := range config.Namespaces {
		rConfig := nsConfig.Subsystems.Reminder
		if rConfig == nil {
			continue
		}
		reporting := nsConfig.ReportingByName(rConfig.SourceStage)
		stateEntry := state.getEntry(timeNow(c), ns, reporting.Name)
		// The DB might well contain info about stale entities, but by querying the latest
		// list of subsystems from the configuration, we make sure we only consider what's
		// currently relevant.
		rawSubsystems := nsConfig.Subsystems.Service.List()
		// Sort to keep output stable.
		sort.Slice(rawSubsystems, func(i, j int) bool {
			return rawSubsystems[i].Name < rawSubsystems[j].Name
		})
		for _, entry := range rawSubsystems {
			if stateEntry.Sent >= reporting.DailyLimit {
				// No point in further examination -- we've already exceeded the
				// daily limit.
				break
			}
			subsystem := registry.get(ns, entry.Name)
			if timeNow(c).After(subsystem.ListsQueried.Add(subsystemListQueryPeriod)) &&
				updateLimit > 0 {
				updateLimit--
				item, err := querySubsystemReminder(c, subsystem, reporting, rConfig)
				if err != nil {
					log.Errorf(c, "failed to query bug lists: %v", err)
					return nil
				}
				err = registry.appendReminder(c, subsystem, item)
				if err != nil {
					log.Errorf(c, "failed to save subsystem: %v", err)
					return nil
				}
			}
			// Load the subsystem again -- it might have been changed above.
			report, err := reportingBugListReport(c, registry.get(ns, entry.Name), typ)
			if err != nil {
				log.Errorf(c, "failed to make bug list report: %v", err)
				return nil
			}
			if report != nil {
				stateEntry.Sent++
				ret = append(ret, report)
			}
		}
	}
	return ret
}

func reportingBugListCommand(c context.Context, cmd *dashapi.BugListUpdate) (string, error) {
	reply := ""
	tx := func(c context.Context) error {
		subsystem, reminder, stage, err := findBugListByID(c, cmd.ID)
		if err != nil {
			return err
		}
		if subsystem == nil {
			return fmt.Errorf("the bug list was not found")
		}
		if stage.ExtID == "" {
			stage.ExtID = cmd.ExtID
		}
		if stage.Link == "" {
			stage.Link = cmd.Link
		}
		// It might e.g. happen that we skipped a stage in reportingBugListReport.
		// Make sure all skipped stages have non-nil Closed.
		for i := range reminder.Stages {
			item := &reminder.Stages[i]
			if item == stage {
				break
			}
			item.Closed = timeNow(c)
		}
		switch cmd.Command {
		case dashapi.BugListSentCmd:
			// TODO: check quotas.
			if !stage.Reported.IsZero() {
				return fmt.Errorf("the reporting stage was already reported")
			}
			stage.Reported = timeNow(c)
		case dashapi.BugListUpstreamCmd:
			if !stage.Moderation {
				reply = `The report cannot be sent further upstream.
It's already at the last reporting stage.`
				return nil
			}
			if !stage.Closed.IsZero() {
				reply = `The bug list was already upstreamed.
Please visit the new discussion thread.`
				return nil
			}
			stage.Closed = timeNow(c)
		}
		_, err = db.Put(c, subsystemKey(c, subsystem), subsystem)
		if err != nil {
			return fmt.Errorf("failed to save the object: %w", err)
		}
		return nil
	}
	return reply, db.RunInTransaction(c, tx, nil)
}

func findBugListByID(c context.Context, ID string) (*Subsystem, *SubsystemReminder, *SubsystemReminderStage, error) {
	var subsystems []*Subsystem
	_, err := db.NewQuery("Subsystem").
		Filter("BugLists.Stages.ID=", ID).
		Limit(1).
		GetAll(c, &subsystems)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to query subsystems: %w", err)
	}
	if len(subsystems) == 0 {
		return nil, nil, nil, nil
	}
	reminder, stage := subsystems[0].findStage(ID)
	if stage == nil {
		// This should never happen (provided that all the code is correct).
		return nil, nil, nil, fmt.Errorf("bug list is found, but the stage is missing")
	}
	return subsystems[0], reminder, stage, nil
}

const (
	subsystemListQueryPeriod = 30 * 24 * time.Hour
	subsystemPickBugsCount   = 10
)

// querySubsystemReminder queries the open bugs and constucts a SubsystemReminder object.
func querySubsystemReminder(c context.Context, subsystem *Subsystem, reporting *Reporting,
	reminderConfig *BugListReporting) (*SubsystemReminder, error) {
	allBugs, allBugKeys, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", subsystem.Namespace).
			Filter("Status=", BugStatusOpen).
			Filter("Tags.Subsystems.Name=", subsystem.Name)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query bugs for subsystem: %w", err)
	}
	var keys []*db.Key
	var bugs []*Bug
	for i, bug := range allBugs {
		if len(bug.Commits) != 0 {
			// This bug is no longer really open.
			continue
		}
		const tooNewPeriod = 14 * 24 * time.Hour
		if bug.FirstTime.After(timeNow(c).Add(-tooNewPeriod)) {
			// Don't take bugs which are too new -- they're still fresh in memory.
			continue
		}
		currReporting, _, _, _, err := currentReporting(c, bug)
		if err != nil {
			return nil, fmt.Errorf("failed to query current reporting: %w", err)
		}
		if reporting.Name != currReporting.Name {
			// The big is not at the expected reporting stage.
			continue
		}
		bugs = append(bugs, allBugs[i])
		keys = append(keys, allBugKeys[i])
	}
	// Let's reduce noise and don't remind about just one bug.
	if len(keys) < 2 {
		return nil, nil
	}
	// For now let's just pick the most frequent bugs.
	// TODO: implement other bug sorting algorithms.
	sort.Stable(&bugSorter{
		bugs: bugs,
		keys: keys,
		less: func(a, b *Bug) bool {
			return a.NumCrashes > b.NumCrashes
		},
	})
	return makeSubsystemReminder(c, reminderConfig, dashapi.BugListMostFrequent, keys), nil
}

// makeSubsystemReminder creates a new SubsystemReminder object.
func makeSubsystemReminder(c context.Context, config *BugListReporting,
	listType dashapi.BugListType, keys []*db.Key) *SubsystemReminder {
	ret := &SubsystemReminder{
		Created: timeNow(c),
		Type:    string(listType),
		Total:   len(keys),
	}
	if len(keys) > subsystemPickBugsCount {
		keys = keys[:subsystemPickBugsCount]
	}
	for _, key := range keys {
		ret.BugKeys = append(ret.BugKeys, key.Encode())
	}
	baseID := hash.String([]byte(fmt.Sprintf("%v-%v-%v", timeNow(c), listType, ret.BugKeys)))
	if config.ModerationConfig != nil {
		ret.Stages = append(ret.Stages, SubsystemReminderStage{
			ID:         bugListReportingHash(baseID, "moderation"),
			Moderation: true,
		})
	}
	ret.Stages = append(ret.Stages, SubsystemReminderStage{
		ID: bugListReportingHash(baseID, "public"),
	})

	return ret
}

const bugListHashPrefix = "list"

func bugListReportingHash(base, name string) string {
	return bugListHashPrefix + bugReportingHash(base, name)
}

func isBugListHash(hash string) bool {
	return strings.HasPrefix(hash, bugListHashPrefix)
}

type bugSorter struct {
	bugs []*Bug
	keys []*db.Key
	less func(a, b *Bug) bool
}

func (sorter *bugSorter) Len() int { return len(sorter.bugs) }
func (sorter *bugSorter) Less(i, j int) bool {
	return sorter.less(sorter.bugs[i], sorter.bugs[j])
}
func (sorter *bugSorter) Swap(i, j int) {
	sorter.bugs[i], sorter.bugs[j] = sorter.bugs[j], sorter.bugs[i]
	sorter.keys[i], sorter.keys[j] = sorter.keys[j], sorter.keys[i]
}

func reportingBugListReport(c context.Context, subsystem *Subsystem,
	targetReportingType string) (*dashapi.BugListReport, error) {
	if len(subsystem.BugLists) == 0 {
		return nil, nil
	}
	last := subsystem.BugLists[len(subsystem.BugLists)-1]
	for _, stage := range last.Stages {
		if !stage.Closed.IsZero() {
			continue
		}
		repType := bugListReportingType(subsystem.Namespace, &stage)
		if repType == nil {
			// It might happen if e.g. Moderation was set to nil.
			// Just skip the stage then.
			continue
		}
		if !stage.Reported.IsZero() || repType.Type() != targetReportingType {
			break
		}
		ret := &dashapi.BugListReport{
			ID:    stage.ID,
			Total: last.Total,
			Link: fmt.Sprintf("%v/%s/s/%s", appURL(c),
				subsystem.Namespace, subsystem.Name),
			Subsystem:   subsystem.Name,
			ListType:    dashapi.BugListType(last.Type),
			Maintainers: subsystemMaintainers(c, subsystem.Namespace, subsystem.Name),
			Moderation:  stage.Moderation,
		}
		bugKeys, err := last.getBugKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to get bug keys: %w", err)
		}
		bugs := make([]*Bug, len(bugKeys))
		err = db.GetMulti(c, bugKeys, bugs)
		if err != nil {
			return nil, fmt.Errorf("failed to get bugs: %w", err)
		}
		for _, bug := range bugs {
			ret.Bugs = append(ret.Bugs, dashapi.BugListItem{
				Title:      bug.displayTitle(),
				Link:       fmt.Sprintf("%v/bug?id=%v", appURL(c), bug.keyHash()),
				ReproLevel: bug.ReproLevel,
				Hits:       bug.NumCrashes,
			})
		}
		return ret, nil
	}
	return nil, nil
}

func bugListReportingType(ns string, stage *SubsystemReminderStage) ReportingType {
	cfg := config.Namespaces[ns].Subsystems.Reminder
	if stage.Moderation {
		return cfg.ModerationConfig
	}
	return cfg.Config
}

func makeSubsystem(ns, name string) *Subsystem {
	return &Subsystem{
		Namespace: ns,
		Name:      name,
	}
}

func subsystemKey(c context.Context, s *Subsystem) *db.Key {
	return db.NewKey(c, "Subsystem", fmt.Sprintf("%v-%v", s.Namespace, s.Name), 0, nil)
}

type subsystemsRegistry struct {
	entities map[string]map[string]*Subsystem
}

func makeSubsystemRegistry(c context.Context) (*subsystemsRegistry, error) {
	var subsystems []*Subsystem
	if _, err := db.NewQuery("Subsystem").GetAll(c, &subsystems); err != nil {
		return nil, err
	}
	ret := &subsystemsRegistry{
		entities: map[string]map[string]*Subsystem{},
	}
	for _, item := range subsystems {
		ret.save(item)
	}
	return ret, nil
}

func (sr *subsystemsRegistry) get(ns, name string) *Subsystem {
	ret := sr.entities[ns][name]
	if ret == nil {
		ret = makeSubsystem(ns, name)
	}
	return ret
}

func (sr *subsystemsRegistry) save(item *Subsystem) {
	if sr.entities[item.Namespace] == nil {
		sr.entities[item.Namespace] = map[string]*Subsystem{}
	}
	sr.entities[item.Namespace][item.Name] = item
}

func (sr *subsystemsRegistry) appendReminder(c context.Context, s *Subsystem,
	item *SubsystemReminder) error {
	key := subsystemKey(c, s)
	return db.RunInTransaction(c, func(c context.Context) error {
		dbSubsystem := new(Subsystem)
		err := db.Get(c, key, dbSubsystem)
		if err == db.ErrNoSuchEntity {
			dbSubsystem = s
		} else if err != nil {
			return fmt.Errorf("failed to get Subsystem '%v': %w", key, err)
		}
		dbSubsystem.ListsQueried = timeNow(c)
		if item != nil {
			dbSubsystem.BugLists = append(dbSubsystem.BugLists, *item)
		}
		if _, err := db.Put(c, key, dbSubsystem); err != nil {
			return fmt.Errorf("failed to save Subsystem: %w", err)
		}
		sr.save(dbSubsystem)
		return nil
	}, nil)
}
