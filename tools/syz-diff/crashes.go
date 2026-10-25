// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/osutil"
)

// baseCrashes persists the titles of the crashes observed on a base kernel build,
// so that the subsequent runs against the same base kernel don't waste time reproducing them.
type baseCrashes struct {
	file   string
	mu     sync.Mutex
	titles map[string]bool
}

func loadBaseCrashes(file string) (*baseCrashes, error) {
	ret := &baseCrashes{
		file:   file,
		titles: map[string]bool{},
	}
	if !osutil.IsExist(file) {
		return ret, nil
	}
	titles, err := osutil.ReadJSON[[]string](file)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v: %w", file, err)
	}
	for _, title := range titles {
		ret.titles[title] = true
	}
	return ret, nil
}

func (bc *baseCrashes) Has(title string) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.titles[title]
}

func (bc *baseCrashes) Add(title string) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	if bc.titles[title] {
		return nil
	}
	bc.titles[title] = true
	return osutil.WriteJSON(bc.file, slices.Sorted(maps.Keys(bc.titles)))
}
