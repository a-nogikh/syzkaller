// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
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

func compileTestTarget(t *testing.T, desc string, consts map[string]uint64) *prog.Target {
	t.Helper()
	eh := func(pos ast.Pos, msg string) {
		t.Fatalf("compile error at %v: %s", pos, msg)
	}
	parsed := ast.Parse([]byte(desc), "test.txt", eh)
	require.NotNil(t, parsed)
	base, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	comp := compiler.Compile(parsed, consts, targets.Get(targets.TestOS, targets.TestArch64), eh)
	require.NotNil(t, comp)
	return prog.NewTarget(base, comp.TargetDesc(consts))
}

func TestCorpusMigrate(t *testing.T) {
	t.Parallel()
	oldTarget := compileTestTarget(t, `
s_data {
	x	int32
	y	int32
}

foo$untouched(a int32, b ptr[in, s_data])
foo$refined(a int32)
foo$disabled(a int32)
foo$deleted(a int32)
`, map[string]uint64{
		"SYS_foo": 1,
	})

	// newTarget keeps foo$untouched, refines foo$refined with an extra argument,
	// marks foo$disabled as [disabled], adds foo$new_variant, and removes foo$deleted.
	newTarget := compileTestTarget(t, `
s_data {
	x	int32
	y	int32
}

foo$new_variant(a int32)
foo$untouched(a int32, b ptr[in, s_data])
foo$refined(a int32, b int32)
foo$disabled(a int32) (disabled)
`, map[string]uint64{
		"SYS_foo": 1,
	})

	area1 := FocusArea{
		Name:     "migrate_area1",
		CoverPCs: map[uint64]struct{}{10: {}},
		Weight:   1.0,
	}
	area2 := FocusArea{
		Name:     "migrate_area2",
		CoverPCs: map[uint64]struct{}{20: {}},
		Weight:   1.0,
	}
	updates := make(chan NewItemEvent, 10)
	corpus := NewFocusedCorpus(context.Background(), updates, []FocusArea{area1, area2})

	progs := []struct {
		text  string
		call  int
		sig   []uint64
		cover []uint64
	}{
		{
			text:  "foo$untouched(0x1, &(0x7f0000000000)={0x2, 0x3})\n",
			call:  0,
			sig:   []uint64{100, 101},
			cover: []uint64{10, 20},
		},
		{
			// Adapted by NonStrict deserialization to foo$refined(0x5, 0x0).
			text:  "foo$refined(0x5)\n",
			call:  0,
			sig:   []uint64{102},
			cover: []uint64{20},
		},
		{
			// Dropped because foo$disabled has the [disabled] attribute in newTarget.
			text:  "foo$disabled(0x1)\n",
			call:  0,
			sig:   []uint64{199},
			cover: []uint64{20},
		},
		{
			// Dropped because foo$deleted no longer exists in newTarget.
			text:  "foo$deleted(0x1)\n",
			call:  0,
			sig:   []uint64{200},
			cover: []uint64{20},
		},
		{
			// Dropped because one of the calls (foo$deleted) is stripped by NonStrict,
			// changing len(newProg.Calls).
			text:  "foo$deleted(0x1)\nfoo$untouched(0x1, &(0x7f0000000000)={0x2, 0x3})\n",
			call:  1,
			sig:   []uint64{201},
			cover: []uint64{10},
		},
	}
	for _, tc := range progs {
		p, err := oldTarget.Deserialize([]byte(tc.text), prog.Strict)
		require.NoError(t, err, "failed to deserialize %s", tc.text)
		corpus.Save(NewInput{
			Prog:   p,
			Call:   tc.call,
			Signal: signal.FromRaw(tc.sig, 0),
			Cover:  tc.cover,
		})
		<-updates
	}

	migrated := corpus.Migrate(context.Background(), newTarget)

	// Migrate should not re-emit NewItemEvents for migrated items, but should keep updates channel active.
	require.Empty(t, updates)

	items := migrated.Items()
	require.Len(t, items, 2)
	var gotProgs []string
	for _, item := range items {
		require.Same(t, newTarget, item.Prog.Target)
		gotProgs = append(gotProgs, string(item.Prog.Serialize()))
	}
	require.ElementsMatch(t, []string{
		"foo$untouched(0x1, &(0x7f0000000000)={0x2, 0x3})\n",
		"foo$refined(0x5, 0x0)\n",
	}, gotProgs)
	require.Equal(t, 3, migrated.StatSignal.Val())
	require.Equal(t, 2, migrated.StatProgs.Val())
	require.Equal(t, map[string]int{"migrate_area1": 1, "migrate_area2": 2}, migrated.ProgsPerArea())
}

