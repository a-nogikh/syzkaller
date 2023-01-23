// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/subsystem/match"
)

func ListFromRepo(repo string) ([]*entity.Subsystem, error) {
	return listFromRepoInner(repo, linuxSubsystemRules)
}

// listFromRepoInner allows for better testing.
func listFromRepoInner(repo string, rules []linuxSubsystemRule) ([]*entity.Subsystem, error) {
	records, err := getMaintainers(repo)
	if err != nil {
		return nil, err
	}
	ctx := &linuxCtx{
		repo:       repo,
		rawRecords: records,
	}
	err = ctx.applyCustomRules(rules)
	if err != nil {
		return nil, err
	}
	ctx.groupByList()
	subsystems, err := ctx.getSubsystems()
	if err != nil {
		return nil, err
	}
	return subsystems, nil
}

type linuxCtx struct {
	repo       string
	subsystems []*subsystemCandidate
	rawRecords []*maintainersRecord
}

type subsystemCandidate struct {
	rule        *linuxSubsystemRule
	records     []*maintainersRecord
	commonEmail string
}

func (ctx *linuxCtx) applyCustomRules(rules []linuxSubsystemRule) error {
	matcher := match.MakePathMatcher()
	for _, record := range ctx.rawRecords {
		matcher.Register(record, record.ToPathRule())
	}
	cover, err := match.BuildPathCover(ctx.repo, matcher.Match)
	if err != nil {
		return err
	}
	cachedCover := match.MakePathCoverCache(cover)
	excludeRecords := make(map[*maintainersRecord]struct{})
	for i := range rules {
		rule := rules[i] // we want a copy to extract a pointer
		matching := querySubtrees(cachedCover, rule.matchPaths)
		nonMatching := querySubtrees(cachedCover, rule.noMatchPaths)
		candidate := &subsystemCandidate{rule: &rule}
		ctx.subsystems = append(ctx.subsystems, candidate)
		for raw := range matching {
			if _, ok := nonMatching[raw]; ok {
				continue
			}
			record := raw.(*maintainersRecord)
			candidate.records = append(candidate.records, record)
			if !rule.keepRecords {
				excludeRecords[record] = struct{}{}
			}
		}
	}
	ctx.removeRecords(excludeRecords)
	return nil
}

func querySubtrees(cover *match.PathCoverCache, entries []string) map[interface{}]struct{} {
	ret := make(map[interface{}]struct{})
	for _, entry := range entries {
		for key := range cover.QuerySubtree(entry) {
			ret[key] = struct{}{}
		}
	}
	return ret
}

func (ctx *linuxCtx) ignoreLists() map[string]bool {
	// Some mailing lists are less important for clusterization, because they always
	// coincide with some other mailing list.
	// If the lists fully overlap, we just pick the alphabetically first one.
	cm := match.MakeCoincidenceMatrix()
	for _, record := range ctx.rawRecords {
		items := []interface{}{}
		for _, email := range record.lists {
			items = append(items, email)
		}
		cm.Record(items...)
	}

	// .. and, as usual, nothing works exactly as intended. There are several super
	// generic mailing lists, which enclose just too many others.
	canOverlap := map[string]bool{
		"linux-kernel@vger.kernel.org":   true,
		"linux-media@vger.kernel.org":    true,
		"netdev@vger.kernel.org":         true,
		"linux-wireless@vger.kernel.org": true,
	}

	ignore := map[string]bool{}
	cm.NonEmptyPairs(func(anyA, anyB interface{}, count int) {
		a, b := anyA.(string), anyB.(string)

		// If M[A][B] == M[A][A], then A always coincides with B.
		// If, at the same time, M[A][B] == M[B][B], then we
		// eliminate A and keep B if A > B.
		if count == cm.Count(a) {
			if count == cm.Count(b) &&
				strings.ToLower(a) < strings.ToLower(b) {
				return
			}
			if canOverlap[b] {
				return
			}
			ignore[a] = true
		}
	})
	return ignore
}

func (ctx *linuxCtx) groupByList() {
	perList := make(map[string][]*maintainersRecord)
	exclude := make(map[*maintainersRecord]struct{})
	for _, record := range ctx.rawRecords {
		for _, list := range record.lists {
			perList[list] = append(perList[list], record)
		}
		if len(record.lists) > 0 {
			exclude[record] = struct{}{}
		}
	}
	ignore := ctx.ignoreLists()
	for email, list := range perList {
		if ignore[email] {
			continue
		}
		ctx.subsystems = append(ctx.subsystems, &subsystemCandidate{
			commonEmail: email,
			records:     list,
		})
	}
	// Remove the records that have been merged into at least one group.
	ctx.removeRecords(exclude)
}

func (ctx *linuxCtx) getSubsystems() ([]*entity.Subsystem, error) {
	ret := []*entity.Subsystem{}
	setNames := []*setNameRequest{}
	for _, raw := range ctx.subsystems {
		s := &entity.Subsystem{}
		if raw.rule != nil {
			s.Name = raw.rule.name
			s.Syscalls = raw.rule.syscalls
		}
		raw.mergeRawRecords(s)
		// Skip empty subsystems.
		if len(s.Syscalls)+len(s.PathRules) == 0 {
			continue
		}
		ret = append(ret, s)
		// Generate a name request.
		setNames = append(setNames, &setNameRequest{
			subsystem:      s,
			referenceEmail: raw.commonEmail,
		})
	}
	err := setSubsystemNames(setNames)
	if err != nil {
		return nil, fmt.Errorf("failed to set names: %w", err)
	}
	cover, err := ctx.subsystemsCover(ret)
	if err != nil {
		return nil, err
	}
	err = SetParents(cover, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (ctx *linuxCtx) subsystemsCover(subsystems []*entity.Subsystem) (*match.PathCover, error) {
	matcher := match.MakePathMatcher()
	for _, s := range subsystems {
		err := matcher.Register(s, s.PathRules...)
		if err != nil {
			return nil, err
		}
	}
	return match.BuildPathCover(ctx.repo, matcher.Match)
}

func (ctx *linuxCtx) removeRecords(exclude map[*maintainersRecord]struct{}) {
	newRecords := []*maintainersRecord{}
	for _, record := range ctx.rawRecords {
		if _, ok := exclude[record]; ok {
			continue
		}
		newRecords = append(newRecords, record)
	}
	ctx.rawRecords = newRecords
}

func (candidate *subsystemCandidate) mergeRawRecords(subsystem *entity.Subsystem) {
	unique := func(list []string) []string {
		m := make(map[string]struct{})
		for _, s := range list {
			m[s] = struct{}{}
		}
		ret := []string{}
		for s := range m {
			ret = append(ret, s)
		}
		return ret
	}
	var lists, maintainers []string
	for _, record := range candidate.records {
		rule := record.ToPathRule()
		if !rule.IsEmpty() {
			subsystem.PathRules = append(subsystem.PathRules, rule)
		}
		lists = append(lists, record.lists...)
		maintainers = append(maintainers, record.maintainers...)
	}
	if candidate.commonEmail != "" {
		// For list-grouped subsystems, we risk merging just too many lists.
		// Keep the list short in this case.
		subsystem.Lists = []string{candidate.commonEmail}
	} else if candidate.rule != nil && len(candidate.rule.lists) > 0 {
		// If the rule already has the mailing lists, use them.
		subsystem.Lists = candidate.rule.lists
	} else if len(lists) > 0 {
		// It's expected that we mostly merge subsystems that share mailing lists,
		// so we don't worry about merging the lists.
		subsystem.Lists = unique(lists)
	}
	// But there's a ristk that we collect too many unrelated maintainers, so
	// let's only merge them if there are no lists.
	if len(subsystem.Lists) == 0 {
		subsystem.Maintainers = unique(maintainers)
	}
}

func getMaintainers(repo string) ([]*maintainersRecord, error) {
	f, err := os.Open(filepath.Join(repo, "MAINTAINERS"))
	if err != nil {
		return nil, fmt.Errorf("failed to open the MAINTAINERS file: %w", err)
	}
	defer f.Close()
	return parseLinuxMaintainers(f)
}
