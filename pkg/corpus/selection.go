// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"
	"sort"
	"sync"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type progSelector struct {
	mu        sync.RWMutex
	perSignal map[uint64][]seedInfo
	counts    map[uint64]int
	pcList    []uint64
	progs     []*prog.Prog
}

type seedInfo struct {
	weight int64
	p      *prog.Prog
}

func newProgSelector() *progSelector {
	return &progSelector{
		perSignal: map[uint64][]seedInfo{},
		counts:    map[uint64]int{},
	}
}

func (ps *progSelector) ChooseProgram(r *rand.Rand) *prog.Prog {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if len(ps.progs) == 0 {
		return nil
	}

	totalCount := len(ps.pcList)
	attempts := min(totalCount, 3)

	var pc uint64
	for i := 0; i < attempts; i++ {
		candidate := ps.pcList[r.Intn(totalCount)]
		if pc == 0 || ps.counts[candidate] < ps.counts[pc] {
			pc = candidate
		}
	}
	list := ps.perSignal[pc]

	var total int64
	for _, info := range list {
		total += info.weight
	}

	randVal := r.Int63n(total)
	var running int64
	for _, info := range list {
		running += info.weight
		if running >= randVal {
			return info.p
		}
	}
	panic("it should not happen")
}

func (ps *progSelector) Programs() []*prog.Prog {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.progs
}

const maxPerPC = 16

func (ps *progSelector) saveProgram(p *prog.Prog, signal signal.Signal) {
	ints := signal.ToRaw()
	weight := int64(len(signal))

	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.progs = append(ps.progs, p)

	for _, pc := range ints {
		if ps.counts[pc] == 0 {
			ps.pcList = append(ps.pcList, pc)
		}
		ps.counts[pc] = ps.counts[pc] + 1

		prev := ps.perSignal[pc]
		if prev == nil {
			prev = make([]seedInfo, 0, maxPerPC+1)
		}
		prev = append(prev, seedInfo{
			weight: weight,
			p:      p,
		})
		if len(prev) > maxPerPC {
			sort.Slice(prev, func(i, j int) bool {
				return prev[i].weight > prev[j].weight
			})
			prev = prev[:maxPerPC]
		}
		ps.perSignal[pc] = prev
	}
}

func (ps *progSelector) replace(other *progSelector) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.perSignal = other.perSignal
	ps.counts = other.counts
	ps.pcList = other.pcList
	ps.progs = other.progs
}
