// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/prog"
)

type choiceTableProxy struct {
	impl      atomic.Value
	mu        sync.Mutex
	lastProgs int
}

func (ct *choiceTableProxy) tryUpdate(target *prog.Target, corpus *Corpus,
	enabledCalls map[*prog.Syscall]bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	progsCount := len(corpus.Programs())
	// There were no deep ideas nor any calculations behind
	// these figures.
	regenerateEveryProgs := 500
	if progsCount <= 10 {
		regenerateEveryProgs = 5
	} else if progsCount < 100 {
		regenerateEveryProgs = 33
	} else if progsCount < 1000 {
		regenerateEveryProgs = 250
	}
	if ct.impl.Load() != nil &&
		progsCount < ct.lastProgs+regenerateEveryProgs {
		return
	}
	ct.impl.Store(
		target.BuildChoiceTable(corpus.Programs(), enabledCalls),
	)
	ct.lastProgs = progsCount
}

func (ct *choiceTableProxy) Enabled(call int) bool {
	return ct.impl.Load().(prog.ChoiceTable).Enabled(call)
}

func (ct *choiceTableProxy) Generatable(call int) bool {
	return ct.impl.Load().(prog.ChoiceTable).Generatable(call)
}

func (ct *choiceTableProxy) Choose(r *rand.Rand, bias int) int {
	return ct.impl.Load().(prog.ChoiceTable).Choose(r, bias)
}
