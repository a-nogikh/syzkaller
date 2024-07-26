// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/stat"
)

type ReproResult struct {
	Crash  *Crash // the original crash
	Repro  *repro.Result
	Strace *repro.StraceResult
	Stats  *repro.Stats
	Err    error
}

type Crash struct {
	InstanceIndex int
	FromHub       bool // this crash was created based on a repro from syz-hub
	FromDashboard bool // .. or from dashboard
	Manual        bool
	*report.Report
}

func (c *Crash) FullTitle() string {
	if c.Report.Title != "" {
		return c.Report.Title
	}
	// Just use some unique, but stable titles.
	if c.FromDashboard {
		return fmt.Sprintf("dashboard crash %p", c)
	} else if c.FromHub {
		return fmt.Sprintf("crash from hub %p", c)
	}
	panic("the crash is expected to have a report")
}

type ReproManagerView interface {
	RunRepro(crash *Crash) *ReproResult // TODO: consider moving runRepro() to repro.go.
	NeedRepro(crash *Crash) bool
	ResizeReproPool(size int)
}

type ReproManager struct {
	Done chan *ReproResult

	statNumReproducing *stat.Val
	statPending        *stat.Val

	onlyOnce  bool
	mgr       ReproManagerView
	parallel  chan struct{}
	pingQueue chan struct{}
	reproVMs  int

	mu          sync.Mutex
	queue       []*Crash
	reproducing map[string]bool
	attempted   map[string]bool
}

func NewReproManager(mgr ReproManagerView, reproVMs int, onlyOnce bool) *ReproManager {
	ret := &ReproManager{
		Done: make(chan *ReproResult, 10),

		mgr:         mgr,
		onlyOnce:    onlyOnce,
		parallel:    make(chan struct{}, reproVMs),
		reproVMs:    reproVMs,
		reproducing: map[string]bool{},
		pingQueue:   make(chan struct{}, 1),
		attempted:   map[string]bool{},
	}
	ret.statNumReproducing = stat.New("reproducing", "Number of crashes being reproduced",
		stat.Console, stat.NoGraph, func() int {
			ret.mu.Lock()
			defer ret.mu.Unlock()
			return len(ret.reproducing)
		})
	ret.statPending = stat.New("pending", "Number of pending repro tasks",
		stat.Console, stat.NoGraph, func() int {
			ret.mu.Lock()
			defer ret.mu.Unlock()
			return len(ret.queue)
		})
	return ret
}

// startReproduction() is assumed to be called only once.
// The agument is the maximum number of VMs dedicated to the bug reproduction.
func (m *ReproManager) StartReproduction() {
	count := 0
	for ; m.calculateReproVMs(count+1) <= m.reproVMs; count++ {
		m.parallel <- struct{}{}
	}
	log.Logf(0, "starting bug reproductions (max %d VMs, %d repros)", m.reproVMs, count)
}

func (m *ReproManager) calculateReproVMs(repros int) int {
	// Let's allocate 1.33 VMs per a reproducer thread.
	if m.reproVMs == 1 && repros == 1 {
		// With one exception -- if we have only one VM, let's still do one repro.
		return 1
	}
	return (repros*4 + 2) / 3
}

func (m *ReproManager) CanReproMore() bool {
	return len(m.parallel) != 0
}

func (m *ReproManager) Reproducing() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.reproducing)
}

// Empty returns true if there are neither running nor planned bug reproductions.
func (m *ReproManager) Empty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reproducing) == 0 && len(m.queue) == 0
}

func (m *ReproManager) Enqueue(crash *Crash) {
	m.mu.Lock()
	defer m.mu.Unlock()

	title := crash.FullTitle()
	if m.onlyOnce && m.attempted[title] {
		// Try to reproduce each bug at most 1 time in this mode.
		// Since we don't upload bugs/repros to dashboard, it likely won't have
		// the reproducer even if we succeeded last time, and will repeatedly
		// say it needs a repro.
		return
	}
	log.Logf(1, "scheduled a reproduction of '%v'", title)
	m.attempted[title] = true
	m.queue = append(m.queue, crash)

	// Ping the loop.
	select {
	case m.pingQueue <- struct{}{}:
	default:
	}
}

func (m *ReproManager) popCrash() *Crash {
	m.mu.Lock()
	defer m.mu.Unlock()

	// TODO: move it to Crash.PrioLess() bool. Make Crash an interface.
	newBetter := func(base, new *Crash) bool {
		// First, serve manual requests.
		if new.Manual != base.Manual {
			return new.Manual
		}
		// Then, deprioritize hub reproducers.
		if new.FromHub != base.FromHub {
			return !new.FromHub
		}
		return false
	}

	idx := -1
	for i, crash := range m.queue {
		if m.reproducing[crash.FullTitle()] {
			continue
		}
		if idx == -1 || newBetter(m.queue[idx], m.queue[i]) {
			idx = i
		}
	}
	if idx == -1 {
		return nil
	}
	crash := m.queue[idx]
	m.queue = slices.Delete(m.queue, idx, idx+1)
	return crash
}

func (m *ReproManager) Loop(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		crash := m.popCrash()
		for crash == nil {
			select {
			case <-m.pingQueue:
				crash = m.popCrash()
			case <-ctx.Done():
				return
			}
			if crash == nil || !m.mgr.NeedRepro(crash) {
				continue
			}
		}

		// Now wait until we can schedule another runner.
		select {
		case <-m.parallel:
		case <-ctx.Done():
			return
		}

		m.mu.Lock()
		m.reproducing[crash.FullTitle()] = true
		m.adjustPoolSizeLocked()
		m.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()

			m.handle(crash)

			m.mu.Lock()
			delete(m.reproducing, crash.FullTitle())
			m.adjustPoolSizeLocked()
			m.mu.Unlock()

			m.parallel <- struct{}{}
			m.pingQueue <- struct{}{}
		}()
	}
}

func (m *ReproManager) handle(crash *Crash) {
	log.Logf(0, "start reproducing '%v'", crash.FullTitle())

	res := m.mgr.RunRepro(crash)

	crepro := false
	title := ""
	if res.Repro != nil {
		crepro = res.Repro.CRepro
		title = res.Repro.Report.Title
	}
	log.Logf(0, "repro finished '%v', repro=%v crepro=%v desc='%v' hub=%v from_dashboard=%v",
		crash.FullTitle(), res.Repro != nil, crepro, title, crash.FromHub, crash.FromDashboard,
	)
	m.Done <- res
}

func (m *ReproManager) adjustPoolSizeLocked() {
	// Avoid the +-1 jitter by considering the repro queue size as well.

	// We process same-titled crashes sequentially, so only count unique ones.
	uniqueTitles := maps.Clone(m.reproducing)
	for _, crash := range m.queue {
		uniqueTitles[crash.FullTitle()] = true
	}

	needRepros := len(uniqueTitles)
	VMs := min(m.reproVMs, m.calculateReproVMs(needRepros))
	m.mgr.ResizeReproPool(VMs)
}
