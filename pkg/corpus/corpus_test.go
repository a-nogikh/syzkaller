// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorpusOperation(t *testing.T) {
	// Basic corpus functionality.
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	ch := make(chan NewItemEvent)
	corpus := NewMonitoredCorpus(context.Background(), ch)

	// First program is saved.
	rs := rand.NewSource(0)
	inp1 := generateInput(target, rs, 5)
	go corpus.Save(inp1)
	event := <-ch
	progData := inp1.Prog.Serialize()
	assert.Equal(t, progData, event.ProgData)
	assert.Equal(t, false, event.Exists)

	// Second program is saved for every its call.
	inp2 := generateInput(target, rs, 5)
	progData = inp2.Prog.Serialize()
	for i := range len(inp2.Prog.Calls) {
		inp2.Call = i
		go corpus.Save(inp2)
		event := <-ch
		assert.Equal(t, progData, event.ProgData)
		assert.Equal(t, i != 0, event.Exists)
	}

	// Verify that we can query corpus items.
	items := corpus.Items()
	assert.Len(t, items, 2)
	for _, item := range items {
		assert.Equal(t, item, corpus.Item(item.Sig))
	}

	// Verify the total signal.
	assert.Equal(t, 5, corpus.StatSignal.Val())
	assert.Equal(t, 2, corpus.StatProgs.Val())

	corpus.Minimize(true)
}

func TestCorpusCoverage(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	ch := make(chan NewItemEvent)
	corpus := NewMonitoredCorpus(context.Background(), ch)
	rs := rand.NewSource(0)

	inp := generateInput(target, rs, 5)
	inp.Cover = []uint64{10, 11}
	go corpus.Save(inp)
	event := <-ch
	assert.Equal(t, []uint64{10, 11}, event.NewCover)

	inp.Call = 1
	inp.Cover = []uint64{11, 12}
	go corpus.Save(inp)
	event = <-ch
	assert.Equal(t, []uint64{12}, event.NewCover)

	// Check the total corpus size.
	assert.Equal(t, corpus.StatCover.Val(), 3)
}

func TestCorpusSaveConcurrency(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())

	const (
		routines = 10
		iters    = 100
	)

	for range routines {
		go func() {
			rs := rand.NewSource(0)
			r := rand.New(rs)
			for it := range iters {
				inp := generateInput(target, rs, it)
				corpus.Save(inp)
				corpus.ChooseProgram(r).Clone()
			}
		}()
	}
}

func generateInput(target *prog.Target, rs rand.Source, sizeSig int) NewInput {
	return generateRangedInput(target, rs, 1, sizeSig)
}

func generateRangedInput(target *prog.Target, rs rand.Source, sigFrom, sigTo int) NewInput {
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["test$manual"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p := target.Generate(rs, 5, ct)
	var raw []uint64
	for i := sigFrom; i <= sigTo; i++ {
		raw = append(raw, uint64(i))
	}
	return NewInput{
		Prog:   p,
		Call:   int(rs.Int63() % int64(len(p.Calls))),
		Signal: signal.FromRaw(raw, 0),
		Cover:  raw,
	}
}

func getTarget(t *testing.T, os, arch string) *prog.Target {
	t.Parallel()
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestFocusedCorpusMinimization(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)

	area1 := FocusArea{
		Name:     "area1",
		CoverPCs: map[uint64]struct{}{10: {}},
		Weight:   1.0,
	}
	area2 := FocusArea{
		Name:     "area2",
		CoverPCs: map[uint64]struct{}{20: {}},
		Weight:   1.0,
	}

	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{area1, area2})

	// Save two inputs with same coverage and signal, but different program content.
	inp1 := generateRangedInput(target, rs, 1, 1)
	inp1.Cover = []uint64{10, 20}
	corpus.Save(inp1)

	inp2 := generateRangedInput(target, rs, 1, 1)
	inp2.Cover = []uint64{10, 20}
	corpus.Save(inp2)

	// Verify both areas have both programs.
	assert.Len(t, corpus.focusAreas[0].progs, 2)
	assert.Len(t, corpus.focusAreas[1].progs, 2)

	getStatVal := func(name string) int {
		for _, ui := range stat.Collect(stat.All) {
			if ui.Name == name {
				return ui.V
			}
		}
		t.Fatalf("stat %q not found", name)
		return 0
	}

	// Verify stats before minimization.
	assert.Equal(t, 2, getStatVal("corpus [area1]"))
	assert.Equal(t, 2, getStatVal("corpus [area2]"))

	// Minimize the corpus. One program should be discarded.
	corpus.Minimize(true)

	// Verify both areas now have only 1 program.
	assert.Len(t, corpus.focusAreas[0].progs, 1)
	assert.Len(t, corpus.focusAreas[1].progs, 1)

	// Verify stats after minimization (should update to 1, not be stuck at 2).
	assert.Equal(t, 1, getStatVal("corpus [area1]"))
	assert.Equal(t, 1, getStatVal("corpus [area2]"))
}

func TestFocusedCorpusReSave(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)

	area := FocusArea{
		Name:     "area1",
		CoverPCs: map[uint64]struct{}{10: {}},
		Weight:   1.0,
	}
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{area})

	inp := generateRangedInput(target, rs, 1, 1)
	inp.Cover = []uint64{10}
	corpus.Save(inp)
	assert.Len(t, corpus.focusAreas[0].progs, 1)

	// Re-save the same input with additional coverage that includes the focus area PC again.
	inp.Cover = []uint64{10, 20}
	corpus.Save(inp)

	// Verify that the program is not double-counted in the focus area.
	assert.Len(t, corpus.focusAreas[0].progs, 1)
}

// Regression test for #7852: ensure saving an input with partially overlapping
// coverage does not mutate item.Cover in-place, preserving full coverage in CallCover.
func TestCallCoverPreserved(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())
	rs := rand.NewSource(0)

	inp1 := generateInput(target, rs, 1)
	inp1.Cover = []uint64{10, 20}
	corpus.Save(inp1)

	// Save an input with partially overlapping coverage (PC 10 exists, 30 is new).
	// Call = -1 isolates it under prog.ExtraCallName.
	inp2 := generateInput(target, rs, 2)
	inp2.Call = -1
	inp2.Cover = []uint64{10, 30}
	corpus.Save(inp2)

	// In-place mutation would overwrite PC 10 with 30, leaving only [30].
	callCover := corpus.CallCover()
	require.Equal(t, cover.FromRaw([]uint64{10, 30}), callCover[prog.ExtraCallName].Cover)
}

func TestFullCoverSaved(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())
	rs := rand.NewSource(0)

	inp := generateInput(target, rs, 1)
	inp.Cover = []uint64{10}
	inp.FullCover = []uint64{10, 20, 30}
	corpus.Save(inp)

	items := corpus.Items()
	require.Len(t, items, 1)
	require.Equal(t, []uint64{10}, items[0].Cover)
	require.Equal(t, cover.FromRaw([]uint64{10, 20, 30}), cover.FromRaw(items[0].FullCover))

	// Re-save with additional full coverage.
	inp.FullCover = []uint64{30, 40}
	corpus.Save(inp)

	items = corpus.Items()
	require.Len(t, items, 1)
	require.Equal(t, cover.FromRaw([]uint64{10, 20, 30, 40}), cover.FromRaw(items[0].FullCover))
}

func TestFocusAreaIgnorePCs(t *testing.T) {
	// Focus area with only IgnorePCs (catch-all except ignored).
	faIgnore := FocusArea{
		Name:      "test_ignore",
		IgnorePCs: map[uint64]struct{}{10: {}, 20: {}},
		Weight:    1.0,
	}
	require.Equal(t, 0, faIgnore.inAreaPCs([]uint64{10, 20}))
	require.Equal(t, 1, faIgnore.inAreaPCs([]uint64{10, 20, 30}))
	require.Equal(t, 2, faIgnore.inAreaPCs([]uint64{30, 40}))

	// Focus area with both CoverPCs and IgnorePCs.
	faBoth := FocusArea{
		Name:      "test_both",
		CoverPCs:  map[uint64]struct{}{10: {}, 20: {}, 30: {}},
		IgnorePCs: map[uint64]struct{}{10: {}},
		Weight:    1.0,
	}
	// 10 is ignored, 40 is not in CoverPCs -> only 20 and 30 count.
	require.Equal(t, 2, faBoth.inAreaPCs([]uint64{10, 20, 30, 40}))
}

func TestFocusAreaProgPrio(t *testing.T) {
	hot := map[uint64]struct{}{}
	for pc := range uint64(100) {
		hot[pc] = struct{}{}
	}
	// Item builds a corpus item covering PCs [from, to) and carrying sigLen signal elements.
	item := func(from, to uint64, sigLen int) *Item {
		var cover []uint64
		for pc := from; pc < to; pc++ {
			cover = append(cover, pc)
		}
		raw := make([]uint64, sigLen)
		for i := range raw {
			raw[i] = uint64(i)
		}
		return &Item{FullCover: cover, Signal: signal.FromRaw(raw, 0)}
	}

	// A statically configured area weighs programs by the plain number of in-area PCs.
	static := FocusArea{Name: "static", IgnorePCs: hot}
	require.Equal(t, 100, static.progPrio(item(0, 200, 7)))
	require.Equal(t, 20, static.progPrio(item(100, 120, 7)))

	// A dynamic area weighs them by the density of the in-area PCs, so a program that
	// mostly covers hot code loses to a smaller, but much more focused one.
	dynamic := FocusArea{Name: "dynamic", IgnorePCs: hot, Dynamic: true}
	// 200 PCs, 100 of them cold -> 100*100/200.
	require.Equal(t, 50, dynamic.progPrio(item(0, 200, 7)))
	// 20 PCs, all of them cold -> 20*20/20.
	require.Equal(t, 20, dynamic.progPrio(item(100, 120, 7)))
	// 1000 PCs, 900 of them cold, still wins on the sheer amount of cold coverage.
	require.Equal(t, 810, dynamic.progPrio(item(0, 1000, 7)))
	// Programs that cover no cold PCs at all are excluded.
	require.Equal(t, 0, dynamic.progPrio(item(0, 100, 7)))
	// A program with a tiny cold share must not be rounded down to 0 (it would be excluded).
	require.Equal(t, 1, dynamic.progPrio(item(0, 101, 7)))

	// An area without any filters accepts everything, so it must reproduce the weighting
	// of the main corpus list (the signal length) rather than count coverage.
	unfiltered := FocusArea{Name: "baseline", Dynamic: true}
	require.Equal(t, 7, unfiltered.progPrio(item(0, 200, 7)))
	require.Equal(t, 7, unfiltered.progPrio(item(0, 5000, 7)))
	require.Equal(t, 3, unfiltered.progPrio(item(0, 200, 3)))
}

func TestDynamicCompensatoryAreas(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())
	rs := rand.NewSource(0)

	// inp1 touches only hot PCs [10, 20].
	inp1 := generateRangedInput(target, rs, 1, 1)
	inp1.Cover = []uint64{10}
	inp1.FullCover = []uint64{10, 20}
	corpus.Save(inp1)

	// inp2 touches hot PCs [10, 20] and cold PC 30.
	inp2 := generateRangedInput(target, rs, 2, 2)
	inp2.Cover = []uint64{10}
	inp2.FullCover = []uint64{10, 20, 30}
	corpus.Save(inp2)

	// inp3 touches only cold PC 40.
	inp3 := generateRangedInput(target, rs, 3, 3)
	inp3.Cover = []uint64{40}
	inp3.FullCover = []uint64{40}
	corpus.Save(inp3)

	// Add compensatory area that ignores hot PCs [10, 20].
	corpus.SetCompensatoryAreas([]FocusArea{
		{
			Name:      "compensatory",
			IgnorePCs: map[uint64]struct{}{10: {}, 20: {}},
			Weight:    1.0,
		},
	})

	// inp1 should not be in the compensatory area, while inp2 and inp3 should.
	require.Len(t, corpus.focusAreas, 1)
	require.Len(t, corpus.focusAreas[0].progs, 2)
	require.Empty(t, corpus.BaseFocusAreas())

	// Minimization preserves compensatory area programs.
	corpus.Minimize(true)
	require.Len(t, corpus.focusAreas, 1)
	require.Len(t, corpus.focusAreas[0].progs, 2)

	// Clearing / removing compensatory areas.
	corpus.SetCompensatoryAreas(nil)
	require.Empty(t, corpus.focusAreas)

	// If a compensatory area has no eligible programs, it is omitted.
	corpus.SetCompensatoryAreas([]FocusArea{
		{
			Name:      "compensatory_empty",
			IgnorePCs: map[uint64]struct{}{10: {}, 20: {}, 30: {}, 40: {}},
			Weight:    1.0,
		},
	})
	require.Empty(t, corpus.focusAreas)

	// Configured focus area with reduced positive filter.
	corpusWithBase := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:     "subsystem",
			CoverPCs: map[uint64]struct{}{10: {}, 20: {}, 30: {}},
			Weight:   2.0,
		},
	})
	corpusWithBase.Save(inp1)
	corpusWithBase.Save(inp2)
	require.Len(t, corpusWithBase.focusAreas[0].progs, 2)

	// Add compensatory area with reduced positive filter (cold PC 30 only).
	corpusWithBase.SetCompensatoryAreas([]FocusArea{
		{
			Name:     "subsystem [compensatory]",
			CoverPCs: map[uint64]struct{}{30: {}},
			Weight:   2.0,
		},
	})
	// Only inp2 covers cold PC 30; inp1 only covered hot PCs 10 and 20.
	require.Len(t, corpusWithBase.focusAreas, 2)
	require.Len(t, corpusWithBase.focusAreas[1].progs, 1)
}
