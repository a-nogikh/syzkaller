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

type ProgramsList struct {
	mu       sync.RWMutex
	allProgs []*prog.Prog
	progs    []*prog.Prog
	sumPrios int64
	accPrios []int64
}

func (pl *ProgramsList) ChooseProgram(r *rand.Rand) *prog.Prog {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	if len(pl.allProgs) == 0 {
		return nil
	}
	if r.Intn(5) == 0 || len(pl.progs) == 0 {
		return pl.allProgs[r.Intn(len(pl.allProgs))]
	}
	randVal := r.Int63n(pl.sumPrios + 1)
	idx := sort.Search(len(pl.accPrios), func(i int) bool {
		return pl.accPrios[i] >= randVal
	})
	return pl.progs[idx]
}

func (pl *ProgramsList) Programs() []*prog.Prog {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	return pl.allProgs
}

func (pl *ProgramsList) saveProgram(p *prog.Prog, signal signal.Signal, fuzz bool) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	pl.allProgs = append(pl.allProgs, p)
	if !fuzz {
		return
	}
	prio := int64(len(signal))
	if prio == 0 {
		prio = 1
	}
	pl.sumPrios += prio
	pl.accPrios = append(pl.accPrios, pl.sumPrios)
	pl.progs = append(pl.progs, p)
}

func (pl *ProgramsList) replace(other *ProgramsList) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	pl.sumPrios = other.sumPrios
	pl.accPrios = other.accPrios
	pl.progs = other.progs
	pl.allProgs = other.allProgs
}
