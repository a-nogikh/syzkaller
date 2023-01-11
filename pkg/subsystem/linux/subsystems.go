// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"
	"os"
	"path/filepath"

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
		matching := cachedCover.QuerySubtree(rule.matchPath)
		nonMatching := make(map[interface{}]struct{})
		if rule.noMatchPath != "" {
			nonMatching = cachedCover.QuerySubtree(rule.noMatchPath)
		}
		candidate := &subsystemCandidate{rule: &rule}
		ctx.subsystems = append(ctx.subsystems, candidate)
		for raw := range matching {
			if _, ok := nonMatching[raw]; ok {
				continue
			}
			record := raw.(*maintainersRecord)
			candidate.records = append(candidate.records, record)
			excludeRecords[record] = struct{}{}
		}
	}
	ctx.removeRecords(excludeRecords)
	return nil
}

func (ctx *linuxCtx) groupByList() {
	// TODO: some groups may 100% overlap. Remove such duplicates.
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
	for email, list := range perList {
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
	for _, raw := range ctx.subsystems {
		s := &entity.Subsystem{}
		if raw.rule != nil {
			s.Name = raw.rule.name
			s.Syscalls = raw.rule.syscalls
		}
		mergeRawRecords(s, raw.records)
		ret = append(ret, s)
	}
	return ret, nil
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

func mergeRawRecords(subsystem *entity.Subsystem, records []*maintainersRecord) {
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
	for _, record := range records {
		rule := record.ToPathRule()
		if !rule.IsEmpty() {
			subsystem.PathRules = append(subsystem.PathRules, rule)
		}
		lists = append(lists, record.lists...)
		maintainers = append(maintainers, record.maintainers...)
	}
	// It's expected that we mostly merge subsystems that share mailing lists,
	// so we don't worry about merging the lists.
	if len(lists) > 0 {
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
