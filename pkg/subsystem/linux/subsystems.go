// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/subsystem/match"
)

func ListFromRepo(repo string) ([]*entity.Subsystem, error) {
	return listFromRepoInner(repo, linuxSubsystemRules)
}

// listFromRepoInner allows for better testing.
func listFromRepoInner(repo string, rules *customRules) ([]*entity.Subsystem, error) {
	records, err := getMaintainers(repo)
	if err != nil {
		return nil, err
	}
	removeMatchingPatterns(records, dropPatterns)
	ctx := &linuxCtx{
		repo:       repo,
		rawRecords: records,
		extraRules: rules,
	}
	ctx.groupByList()
	list, err := ctx.getSubsystems()
	if err != nil {
		return nil, err
	}
	// Sort subsystems by name to keep output consistent.
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	// Sort path rules to keep output consistent.
	for _, entity := range list {
		sort.Slice(entity.PathRules, func(i, j int) bool {
			a, b := entity.PathRules[i], entity.PathRules[j]
			if a.IncludeRegexp != b.IncludeRegexp {
				return a.IncludeRegexp < b.IncludeRegexp
			}
			return a.ExcludeRegexp < b.ExcludeRegexp
		})
	}
	return list, nil
}

type linuxCtx struct {
	repo       string
	rawRecords []*maintainersRecord
	extraRules *customRules
}

type subsystemCandidate struct {
	records     []*maintainersRecord
	commonEmail string
}

var (
	// Some of the patterns are not really needed for bug subsystem inteference and
	// only complicate the manual review of the rules.
	dropPatterns = regexp.MustCompile(`^(Documentation|scripts|samples|tools)|Makefile`)
)

func (ctx *linuxCtx) groupByList() []*subsystemCandidate {
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
	ret := []*subsystemCandidate{}
	for email, list := range perList {
		ret = append(ret, &subsystemCandidate{
			commonEmail: email,
			records:     list,
		})
	}
	return ret
}

func (ctx *linuxCtx) getSubsystems() ([]*entity.Subsystem, error) {
	ret := []*entity.Subsystem{}
	setNames := []*setNameRequest{}
	for _, raw := range ctx.groupByList() {
		s := &entity.Subsystem{}
		raw.mergeRawRecords(s)
		ret = append(ret, s)
		// Generate a name request.
		setNames = append(setNames, &setNameRequest{
			subsystem:      s,
			referenceEmail: raw.commonEmail,
		})
	}
	if err := setSubsystemNames(setNames); err != nil {
		return nil, fmt.Errorf("failed to set names: %w", err)
	}
	ctx.applyExtraRules(ret)
	if err := anyEmptyNames(ret); err != nil {
		return nil, err
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

func (ctx *linuxCtx) applyExtraRules(list []*entity.Subsystem) {
	if ctx.extraRules == nil {
		return
	}
	for _, entry := range list {
		entry.Syscalls = ctx.extraRules.subsystemCalls[entry.Name]
	}
}

func anyEmptyNames(list []*entity.Subsystem) error {
	for _, entry := range list {
		if entry.Name == "" {
			return fmt.Errorf("unable to find name for: %#v", entry)
		}
	}
	return nil
}

func (ctx *linuxCtx) subsystemsCover(subsystems []*entity.Subsystem) (*match.PathCover, error) {
	matcher := match.MakePathMatcher()
	for _, s := range subsystems {
		err := matcher.Register(s, s.PathRules...)
		if err != nil {
			return nil, err
		}
	}
	return match.BuildPathCover(ctx.repo, matcher.Match, dropPatterns)
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
		sort.Strings(ret)
		return ret
	}
	var maintainers []string
	for _, record := range candidate.records {
		rule := record.ToPathRule()
		if !rule.IsEmpty() {
			subsystem.PathRules = append(subsystem.PathRules, rule)
		}
		maintainers = append(maintainers, record.maintainers...)
	}
	if candidate.commonEmail != "" {
		// For list-grouped subsystems, we risk merging just too many lists.
		// Keep the list short in this case.
		subsystem.Lists = []string{candidate.commonEmail}
	}
	// There's a risk that we collect too many unrelated maintainers, so
	// let's only merge them if there are no lists.
	if len(candidate.records) <= 1 {
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
