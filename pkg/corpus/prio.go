// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"
	"sync"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type ProgramsList struct {
	mu       sync.RWMutex
	progs    []*prog.Prog
	sumPrios int64
	signals  [][]uint64
}

func (pl *ProgramsList) ChooseProgram(r *rand.Rand) (*prog.Prog, []uint64) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	if len(pl.progs) == 0 {
		return nil, nil
	}
	idx := r.Intn(len(pl.progs))
	return pl.progs[idx], pl.signals[idx]
}

func (pl *ProgramsList) Programs() []*prog.Prog {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	return pl.progs
}

func (pl *ProgramsList) saveProgram(p *prog.Prog, signal signal.Signal) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	prio := int64(len(signal))
	if prio == 0 {
		prio = 1
	}
	pl.sumPrios += prio
	pl.progs = append(pl.progs, p)
	pl.signals = append(pl.signals, signal.ToRaw())
}

func (pl *ProgramsList) replace(other *ProgramsList) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	pl.sumPrios = other.sumPrios
	pl.signals = other.signals
	pl.progs = other.progs
}
