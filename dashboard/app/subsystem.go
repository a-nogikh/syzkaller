// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/subsystem"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// reassignBugSubsystems is expected to be periodically called to refresh old automatic
// subsystem assignments.
func reassignBugSubsystems(c context.Context, ns string, count int) error {
	service := getSubsystemService(c, ns)
	if service == nil {
		return nil
	}
	bugs, keys, err := bugsToUpdateSubsystems(c, ns, count)
	if err != nil {
		return err
	}
	log.Infof(c, "updating subsystems for %d bugs in %#v", len(keys), ns)
	now := timeNow(c)
	for i, bugKey := range keys {
		list, err := inferSubsystems(c, bugs[i], bugKey)
		if err != nil {
			return fmt.Errorf("failed to infer subsystems: %w", err)
		}
		tx := func(c context.Context) error {
			bug := new(Bug)
			if err := db.Get(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to get bug: %v", err)
			}
			bug.SetSubsystems(list, now)
			if _, err = db.Put(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to put bug: %v", err)
			}
			return nil
		}
		if err := db.RunInTransaction(c, tx, &db.TransactionOptions{Attempts: 10}); err != nil {
			return err
		}
	}
	return nil
}

func bugsToUpdateSubsystems(c context.Context, ns string, count int) ([]*Bug, []*db.Key, error) {
	now := timeNow(c)
	// Give priority to open bugs.
	var openBugs []*Bug
	openKeys, err := db.NewQuery("Bug").
		Filter("Namespace=", ns).
		Filter("Status=", BugStatusOpen).
		Filter("SubsystemsTime<", now.Add(-openBugsUpdateTime)).
		Limit(count).
		GetAll(c, &openBugs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query open bugs: %v", err)
	}
	var closedBugs []*Bug
	var closedKeys []*db.Key
	if len(openKeys) < count {
		closedKeys, err = db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("Status=", BugStatusFixed).
			Filter("SubsystemsTime<", now.Add(-fixedBugsUpdateTime)).
			Limit(count-len(openKeys)).
			GetAll(c, &closedBugs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query fixed bugs: %v", err)
		}
	}
	return append(openBugs, closedBugs...), append(openKeys, closedKeys...), nil
}

const (
	// We load the top crashesForInference crashes to determine the bug subsystem(s).
	crashesForInference = 5
	// How often we update open bugs.
	openBugsUpdateTime = time.Hour * 24 * 30
	// How often we update fixed bugs.
	fixedBugsUpdateTime = time.Hour * 24 * 30 * 6
)

// inferSubsystems determines the best yet possible estimate of the bug's subsystems.
func inferSubsystems(c context.Context, bug *Bug, bugKey *db.Key) ([]*subsystem.Subsystem, error) {
	service := getSubsystemService(c, bug.Namespace)
	if service == nil {
		// There's nothing we can do.
		return nil, nil
	}
	dbCrashes, dbCrashKeys, err := queryCrashesForBug(c, bugKey, crashesForInference)
	if err != nil {
		return nil, err
	}
	crashes := []*subsystem.Crash{}
	for i, dbCrash := range dbCrashes {
		crash := &subsystem.Crash{}
		if len(dbCrash.ReportElements.GuiltyFiles) > 0 {
			// For now we anyway only store one.
			crash.GuiltyPath = dbCrash.ReportElements.GuiltyFiles[0]
		}
		if dbCrash.ReproSyz != 0 {
			crash.SyzRepro, _, err = getText(c, textReproSyz, dbCrash.ReproSyz)
			if err != nil {
				return nil, fmt.Errorf("failed to load syz repro for %s: %w",
					dbCrashKeys[i], err)
			}
		}
		crashes = append(crashes, crash)
	}
	return service.Extract(crashes), nil
}

// subsystemMaintainers queries the list of emails to send the bug to.
func subsystemMaintainers(c context.Context, ns, subsystemName string) []string {
	service := getSubsystemService(c, ns)
	if service == nil {
		return nil
	}
	item := service.ByName(subsystemName)
	if item == nil {
		return nil
	}
	return item.Emails()
}

var subsystemsListKey = "custom list of kernel subsystems"

type customSubsystemList struct {
	ns   string
	list []*subsystem.Subsystem
}

func contextWithSubsystems(c context.Context, custom *customSubsystemList) context.Context {
	return context.WithValue(c, &subsystemsListKey, custom)
}

func getSubsystemService(c context.Context, ns string) *subsystem.Service {
	// This is needed to emulate changes to the subsystem list over time during testing.
	if val, ok := c.Value(&subsystemsListKey).(*customSubsystemList); ok && val.ns == ns {
		return subsystem.MustMakeService(val.list)
	}
	return config.Namespaces[ns].SubsystemService
}
