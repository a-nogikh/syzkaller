// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/appengine/v2/memcache"
)

type Cached struct {
	Open       int
	Fixed      int
	Invalid    int
	Subsystems map[string]SubsystemStats
}

type SubsystemStats struct {
	Open    int
	Fixed   int
	Invalid int
}

func CacheGet(c context.Context, r *http.Request, ns string) (*Cached, error) {
	accessLevel := accessLevel(c, r)
	v := new(Cached)
	_, err := memcache.Gob.Get(c, cacheKey(ns, accessLevel), v)
	if err != nil && err != memcache.ErrCacheMiss {
		return nil, err
	}
	if err == nil {
		return v, nil
	}
	bugs, _, err := loadNamespaceBugs(c, ns)
	if err != nil {
		return nil, err
	}
	return buildAndStoreCached(c, bugs, ns, accessLevel)
}

// cacheUpdate updates memcache every hour (called by cron.yaml).
// Cache update is slow and we don't want to slow down user requests.
func cacheUpdate(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	for ns := range config.Namespaces {
		bugs, _, err := loadNamespaceBugs(c, ns)
		if err != nil {
			log.Errorf(c, "failed load ns=%v bugs: %v", ns, err)
			continue
		}
		for _, accessLevel := range []AccessLevel{AccessPublic, AccessUser, AccessAdmin} {
			_, err := buildAndStoreCached(c, bugs, ns, accessLevel)
			if err != nil {
				log.Errorf(c, "failed to build cached for ns=%v access=%v: %v", ns, accessLevel, err)
				continue
			}
		}
	}
}

type cacheBugStatus int

const (
	cacheBugOpen cacheBugStatus = iota
	cacheBugFixed
	cacheBugInvalid
	cacheBugSkip
)

func buildAndStoreCached(c context.Context, bugs []*Bug, ns string, accessLevel AccessLevel) (*Cached, error) {
	v := &Cached{
		Subsystems: make(map[string]SubsystemStats),
	}
	for _, bug := range bugs {
		if bug.Status == BugStatusOpen && accessLevel < bug.sanitizeAccess(accessLevel) {
			continue
		}
		bugStatus := getBugStatus(bug)
		switch bugStatus {
		case cacheBugOpen:
			v.Open++
		case cacheBugFixed:
			v.Fixed++
		case cacheBugInvalid:
			v.Invalid++
		}
		for _, subsystem := range bug.Tags.Subsystems {
			stats := v.Subsystems[subsystem.Name]
			switch bugStatus {
			case cacheBugOpen:
				stats.Open++
			case cacheBugFixed:
				stats.Fixed++
			case cacheBugInvalid:
				stats.Invalid++
			}
			v.Subsystems[subsystem.Name] = stats
		}
	}
	item := &memcache.Item{
		Key:        cacheKey(ns, accessLevel),
		Object:     v,
		Expiration: 4 * time.Hour, // supposed to be updated by cron every hour
	}
	if err := memcache.Gob.Set(c, item); err != nil {
		return nil, err
	}
	return v, nil
}

func getBugStatus(bug *Bug) cacheBugStatus {
	switch bug.Status {
	case BugStatusOpen:
		if len(bug.Commits) == 0 {
			return cacheBugOpen
		} else {
			return cacheBugFixed
		}
	case BugStatusFixed:
		return cacheBugFixed
	case BugStatusInvalid:
		return cacheBugInvalid
	}
	return cacheBugSkip
}

func cacheKey(ns string, accessLevel AccessLevel) string {
	return fmt.Sprintf("%v-%v", ns, accessLevel)
}
