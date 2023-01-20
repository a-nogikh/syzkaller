// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"fmt"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/subsystem/linux"
	"github.com/google/syzkaller/pkg/subsystem/match"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func ListFromOS(OS, repo string) ([]*entity.Subsystem, error) {
	if OS == targets.Linux {
		return linux.ListFromRepo(repo)
	}
	return nil, fmt.Errorf("unknown OS")
}

func MakeSubsystemExtractor(list []*entity.Subsystem) (*SubsystemExtractor, error) {
	ret := &SubsystemExtractor{
		matcher: match.MakePathMatcher(),
		perCall: make(map[string][]*entity.Subsystem),
	}
	for _, subsystem := range list {
		err := ret.matcher.Register(subsystem, subsystem.PathRules...)
		if err != nil {
			return nil, err
		}
		for _, call := range subsystem.Syscalls {
			ret.perCall[call] = append(ret.perCall[call], subsystem)
		}
	}
	return ret, nil
}

type SubsystemExtractor struct {
	matcher *match.PathMatcher
	perCall map[string][]*entity.Subsystem
}

func (se *SubsystemExtractor) FromPath(path string) []*entity.Subsystem {
	ret := []*entity.Subsystem{}
	for _, raw := range se.matcher.Match(path) {
		ret = append(ret, raw.(*entity.Subsystem))
	}
	return ret
}

func (se *SubsystemExtractor) FromProg(progBytes []byte) []*entity.Subsystem {
	calls := make(map[*entity.Subsystem]struct{})
	progCalls, _, _ := prog.CallSet(progBytes)
	for call := range progCalls {
		for _, subsystem := range se.perCall[call] {
			calls[subsystem] = struct{}{}
		}
	}
	list := []*entity.Subsystem{}
	for key := range calls {
		list = append(list, key)
	}
	return list
}
