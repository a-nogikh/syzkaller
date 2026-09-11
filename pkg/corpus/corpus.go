// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package corpus manages syzkaller test program corpora, signal tracking, and corpus minimization.
package corpus

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// Corpus object represents a set of syzkaller-found programs that
// cover the kernel up to the currently reached frontiers.
type Corpus struct {
	ctx      context.Context
	mu       sync.RWMutex
	progsMap map[string]*Item
	signal   signal.Signal // total signal of all items
	cover    cover.Cover   // total coverage of all items
	updates  chan<- NewItemEvent

	*ProgramsList
	StatProgs  *stat.Val
	StatSignal *stat.Val
	StatCover  *stat.Val

	focusAreas []*focusAreaState
}

type focusAreaState struct {
	FocusArea
	*ProgramsList
}

type FocusArea struct {
	Name      string // can be empty
	CoverPCs  map[uint64]struct{}
	IgnorePCs map[uint64]struct{}
	Weight    float64
	Dynamic   bool
}

func (fa *FocusArea) inAreaPCs(cover []uint64) int {
	var count int
	for _, pc := range cover {
		if len(fa.CoverPCs) > 0 {
			if _, ok := fa.CoverPCs[pc]; !ok {
				continue
			}
		}
		if len(fa.IgnorePCs) > 0 {
			if _, ok := fa.IgnorePCs[pc]; ok {
				continue
			}
		}
		count++
	}
	return count
}

// progPrio returns the priority of the program within the area.
// For statically configured areas it's simply the number of PCs that fall into the area.
// Dynamic (compensatory) areas instead weigh programs by the density of the matched PCs
// (count * count / total). Otherwise a bloated program that touches lots of hot code would
// still outrank a small program that predominantly covers the underrepresented PCs.
func (fa *FocusArea) progPrio(item *Item) int {
	if len(fa.CoverPCs) == 0 && len(fa.IgnorePCs) == 0 {
		// An area without filters accepts every program, so there is nothing to weigh them
		// by -- mirror the main corpus list, which such an area effectively stands in for.
		// Weighing by the coverage instead would favor programs with lots of setup calls:
		// their extra boilerplate coverage is not what they were added to the corpus for.
		return len(item.Signal)
	}
	cover := item.areaCover()
	count := fa.inAreaPCs(cover)
	if !fa.Dynamic || count == 0 {
		return count
	}
	// Never return 0 for programs that do cover the area, it would exclude them altogether.
	return max(1, count*count/len(cover))
}

func NewCorpus(ctx context.Context) *Corpus {
	return NewMonitoredCorpus(ctx, nil)
}

func NewMonitoredCorpus(ctx context.Context, updates chan<- NewItemEvent) *Corpus {
	return NewFocusedCorpus(ctx, updates, nil)
}

func NewFocusedCorpus(ctx context.Context, updates chan<- NewItemEvent, areas []FocusArea) *Corpus {
	corpus := &Corpus{
		ctx:          ctx,
		progsMap:     make(map[string]*Item),
		updates:      updates,
		ProgramsList: &ProgramsList{},
	}
	corpus.StatProgs = stat.New("corpus", "Number of test programs in the corpus", stat.Console,
		stat.Link("/corpus"), stat.Graph("corpus"), stat.LenOf(&corpus.progsMap, &corpus.mu))
	corpus.StatSignal = stat.New("signal", "Fuzzing signal in the corpus",
		stat.LenOf(&corpus.signal, &corpus.mu))
	corpus.StatCover = stat.New("coverage", "Source coverage in the corpus", stat.Console,
		stat.Link("/cover"), stat.Prometheus("syz_corpus_cover"), stat.LenOf(&corpus.cover, &corpus.mu))
	for _, area := range areas {
		obj := &ProgramsList{}
		if len(areas) > 1 && area.Name != "" && len(area.CoverPCs) > 0 {
			// Only show extra statistics if there's more than one area.
			stat.New("corpus ["+area.Name+"]",
				fmt.Sprintf("Corpus programs of the focus area %q", area.Name),
				stat.Console, stat.Graph("corpus"),
				stat.LenOf(&obj.progs, &corpus.mu))
		}
		corpus.focusAreas = append(corpus.focusAreas, &focusAreaState{
			FocusArea:    area,
			ProgramsList: obj,
		})
	}
	return corpus
}

// ItemUpdate represents an update to a corpus item.
// A single program may be relevant for multiple syscalls, resulting in multiple
// ItemUpdate entities.
type ItemUpdate struct {
	Call     int
	RawCover []uint64
}

// Item objects are to be treated as immutable, otherwise it's just
// too hard to synchonize accesses to them across the whole project.
// When Corpus updates one of its items, it saves a copy of it.
type Item struct {
	Sig       string
	Call      int
	Prog      *prog.Prog
	HasAny    bool // whether the prog contains squashed arguments
	Signal    signal.Signal
	Cover     []uint64
	FullCover []uint64
	Updates   []ItemUpdate

	areas map[*focusAreaState]struct{}
}

func (item Item) StringCall() string {
	return item.Prog.CallName(item.Call)
}

// areaCover returns the coverage used to match the item against focus areas.
// FullCover spans all program calls, while Cover only covers the call the program
// was saved for. Old corpus items may have no FullCover, fall back to Cover for them.
func (item Item) areaCover() []uint64 {
	if len(item.FullCover) != 0 {
		return item.FullCover
	}
	return item.Cover
}

type NewInput struct {
	Prog      *prog.Prog
	Call      int
	Signal    signal.Signal
	Cover     []uint64
	RawCover  []uint64
	FullCover []uint64
}

type NewItemEvent struct {
	Sig      string
	Exists   bool
	ProgData []byte
	NewCover []uint64
}

func (corpus *Corpus) Save(inp NewInput) {
	progData := inp.Prog.Serialize()
	sig := hash.String(progData)

	corpus.mu.Lock()
	defer corpus.mu.Unlock()

	update := ItemUpdate{
		Call:     inp.Call,
		RawCover: inp.RawCover,
	}
	exists := false
	if old, ok := corpus.progsMap[sig]; ok {
		exists = true
		newSignal := old.Signal.Copy()
		newSignal.Merge(inp.Signal)
		var newCover cover.Cover
		newCover.Merge(old.Cover)
		newCover.Merge(inp.Cover)
		var newFullCover cover.Cover
		newFullCover.Merge(old.FullCover)
		newFullCover.Merge(inp.FullCover)
		newItem := &Item{
			Sig:       sig,
			Prog:      old.Prog,
			Call:      old.Call,
			HasAny:    old.HasAny,
			Signal:    newSignal,
			Cover:     newCover.Serialize(),
			FullCover: newFullCover.Serialize(),
			Updates:   slices.Clone(old.Updates),
			areas:     maps.Clone(old.areas),
		}
		const maxUpdates = 32
		if len(newItem.Updates) < maxUpdates {
			newItem.Updates = append(newItem.Updates, update)
		}
		corpus.progsMap[sig] = newItem
		corpus.applyFocusAreas(newItem)
	} else {
		fullCover := inp.FullCover
		if len(fullCover) == 0 {
			fullCover = inp.Cover
		}
		item := &Item{
			Sig:       sig,
			Call:      inp.Call,
			Prog:      inp.Prog,
			HasAny:    inp.Prog.ContainsAny(),
			Signal:    inp.Signal,
			Cover:     inp.Cover,
			FullCover: fullCover,
			Updates:   []ItemUpdate{update},
		}
		corpus.progsMap[sig] = item
		corpus.applyFocusAreas(item)
		corpus.saveProgram(inp.Prog, len(inp.Signal))
	}
	corpus.signal.Merge(inp.Signal)
	newCover := corpus.cover.MergeDiff(inp.Cover)
	if corpus.updates != nil {
		select {
		case <-corpus.ctx.Done():
		case corpus.updates <- NewItemEvent{
			Sig:      sig,
			Exists:   exists,
			ProgData: progData,
			NewCover: newCover,
		}:
		}
	}
}

func (corpus *Corpus) applyFocusAreas(item *Item) {
	for _, area := range corpus.focusAreas {
		if _, ok := item.areas[area]; ok {
			continue
		}
		prio := area.progPrio(item)
		if prio == 0 {
			continue
		}
		area.saveProgram(item.Prog, prio)
		if item.areas == nil {
			item.areas = make(map[*focusAreaState]struct{})
		}
		item.areas[area] = struct{}{}
	}
}

func (corpus *Corpus) BaseFocusAreas() []FocusArea {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	var ret []FocusArea
	for _, state := range corpus.focusAreas {
		if !state.Dynamic {
			ret = append(ret, state.FocusArea)
		}
	}
	return ret
}

type areaMember struct {
	item *Item
	prio int
}

func (corpus *Corpus) SetCompensatoryAreas(areas []FocusArea) {
	// Matching every corpus program against the new areas is expensive (it's linear in the
	// total corpus coverage), so do it under a read lock and only grab the write lock
	// afterwards to swap the prepared areas in.
	corpus.mu.RLock()
	items := make([]*Item, 0, len(corpus.progsMap))
	for _, item := range corpus.progsMap {
		items = append(items, item)
	}
	corpus.mu.RUnlock()

	states := make([]*focusAreaState, 0, len(areas))
	members := make([][]areaMember, 0, len(areas))
	for _, area := range areas {
		area.Dynamic = true
		state := &focusAreaState{
			FocusArea:    area,
			ProgramsList: &ProgramsList{},
		}
		var matched []areaMember
		for _, item := range items {
			if prio := state.progPrio(item); prio > 0 {
				matched = append(matched, areaMember{item, prio})
			}
		}
		if len(matched) > 0 {
			states = append(states, state)
			members = append(members, matched)
		}
	}

	corpus.mu.Lock()
	defer corpus.mu.Unlock()
	for _, item := range corpus.progsMap {
		maps.DeleteFunc(item.areas, func(area *focusAreaState, _ struct{}) bool {
			return area.Dynamic
		})
	}
	corpus.focusAreas = slices.DeleteFunc(corpus.focusAreas, func(state *focusAreaState) bool {
		return state.Dynamic
	})
	for i, state := range states {
		for _, member := range members[i] {
			// The item could have been replaced or dropped while we were not holding the lock.
			if corpus.progsMap[member.item.Sig] != member.item {
				continue
			}
			state.saveProgram(member.item.Prog, member.prio)
			if member.item.areas == nil {
				member.item.areas = make(map[*focusAreaState]struct{})
			}
			member.item.areas[state] = struct{}{}
		}
		if len(state.progs) > 0 {
			corpus.focusAreas = append(corpus.focusAreas, state)
		}
	}
}

func (corpus *Corpus) Signal() signal.Signal {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.signal.Copy()
}

func (corpus *Corpus) Items() []*Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	ret := make([]*Item, 0, len(corpus.progsMap))
	for _, item := range corpus.progsMap {
		ret = append(ret, item)
	}
	return ret
}

func (corpus *Corpus) Item(sig string) *Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progsMap[sig]
}

type CallCov struct {
	Count int
	Cover cover.Cover
}

func (corpus *Corpus) CallCover() map[string]*CallCov {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	calls := make(map[string]*CallCov)
	for _, inp := range corpus.progsMap {
		call := inp.StringCall()
		if calls[call] == nil {
			calls[call] = new(CallCov)
		}
		cc := calls[call]
		cc.Count++
		cc.Cover.Merge(inp.Cover)
	}
	return calls
}

func (corpus *Corpus) ProgsPerArea() map[string]int {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	ret := map[string]int{}
	for _, item := range corpus.focusAreas {
		ret[item.Name] = len(item.progs)
	}
	return ret
}

type FocusAreaInfo struct {
	Name      string
	Weight    float64
	Dynamic   bool
	Progs     int
	CoverPCs  int
	IgnorePCs int
}

func (corpus *Corpus) FocusAreaInfo() []FocusAreaInfo {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	var ret []FocusAreaInfo
	for _, state := range corpus.focusAreas {
		ret = append(ret, FocusAreaInfo{
			Name:      state.Name,
			Weight:    state.Weight,
			Dynamic:   state.Dynamic,
			Progs:     len(state.progs),
			CoverPCs:  len(state.CoverPCs),
			IgnorePCs: len(state.IgnorePCs),
		})
	}
	return ret
}

func (corpus *Corpus) Cover() []uint64 {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.cover.Serialize()
}

func (corpus *Corpus) CoverLen() int {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return len(corpus.cover)
}
