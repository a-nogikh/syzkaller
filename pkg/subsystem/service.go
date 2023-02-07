// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"fmt"

	"github.com/google/syzkaller/pkg/subsystem/entity"
)

type Service struct {
	*Extractor
	perName map[string]*entity.Subsystem
}

func MakeService(list []*entity.Subsystem) (*Service, error) {
	extractor, err := MakeExtractor(list)
	if err != nil {
		return nil, err
	}
	perName := map[string]*entity.Subsystem{}
	for _, item := range list {
		if item.Name == "" {
			return nil, fmt.Errorf("input contains a subsystem without a name")
		}
		if perName[item.Name] != nil {
			return nil, fmt.Errorf("collision on %#v name", item.Name)
		}
		perName[item.Name] = item
	}

	return &Service{
		Extractor: extractor,
		perName:   perName,
	}, nil
}

func (s *Service) ByName(name string) *entity.Subsystem {
	return s.perName[name]
}
