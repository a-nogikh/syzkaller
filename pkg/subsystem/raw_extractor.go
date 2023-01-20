// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/subsystem/match"
	"github.com/google/syzkaller/prog"
)

// RawExtractor performs low-level subsystem matching (directly by a path or a syscall).
type RawExtractor struct {
	matcher *match.PathMatcher
	perCall map[string][]*entity.Subsystem
}

func MakeRawExtractor(list []*entity.Subsystem) (*RawExtractor, error) {
	ret := &RawExtractor{
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

func (e *RawExtractor) FromPath(path string) []*entity.Subsystem {
	ret := []*entity.Subsystem{}
	for _, raw := range e.matcher.Match(path) {
		ret = append(ret, raw.(*entity.Subsystem))
	}
	return ret
}

func (e *RawExtractor) FromProg(progBytes []byte) []*entity.Subsystem {
	calls := make(map[*entity.Subsystem]struct{})
	progCalls, _, _ := prog.CallSet(progBytes)
	for call := range progCalls {
		for _, subsystem := range e.perCall[call] {
			calls[subsystem] = struct{}{}
		}
	}
	list := []*entity.Subsystem{}
	for key := range calls {
		list = append(list, key)
	}
	return list
}
