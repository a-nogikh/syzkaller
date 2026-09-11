// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestChooseProgram(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())

	const (
		maxIters   = 1000
		sizeCorpus = 1000
		eps        = 0.01
	)

	priorities := make(map[*prog.Prog]int64)
	for i := range sizeCorpus {
		sizeSig := i + 1
		if sizeSig%250 == 0 {
			sizeSig = 0
		}
		inp := generateInput(target, rs, sizeSig)
		corpus.Save(inp)
		priorities[inp.Prog] = int64(len(inp.Signal))
	}
	counters := make(map[*prog.Prog]int)
	for range maxIters {
		counters[corpus.chooseProgram(r)]++
	}
	for p, prio := range priorities {
		prob := float64(prio) / float64(corpus.sumPrios)
		diff := math.Abs(prob*maxIters - float64(counters[p]))
		if diff > eps*maxIters {
			t.Fatalf("the difference (%f) is higher than %f%%", diff, eps*100)
		}
	}
}

func TestFocusAreas(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			CoverPCs: map[uint64]struct{}{
				0: {},
				1: {},
				2: {},
			},
			Weight: 10,
		},
		{
			CoverPCs: map[uint64]struct{}{
				2: {},
				3: {},
			},
			Weight: 30,
		},
		{
			CoverPCs: map[uint64]struct{}{
				4: {},
				5: {},
			},
			Weight: 60,
		},
	})

	rs := rand.NewSource(0)

	fillGroup := func(from, to, count int) map[*prog.Prog]bool {
		ret := map[*prog.Prog]bool{}
		for i := range count {
			a := from + i%(to-from+1)
			b := a + i%(to-a+1)
			inp := generateRangedInput(target, rs, a, b)
			ret[inp.Prog] = true
			corpus.Save(inp)
		}
		return ret
	}

	first := fillGroup(0, 1, 10)
	second := fillGroup(2, 3, 10)
	third := fillGroup(4, 5, 10)

	rnd := rand.New(rs)
	different := map[*prog.Prog]bool{}
	firstCount, secondCount, thirdCount := 0, 0, 0
	const TOTAL = 10000
	for range TOTAL {
		p := corpus.ChooseProgram(rnd)
		different[p] = true

		if first[p] {
			firstCount++
		} else if second[p] {
			secondCount++
		} else if third[p] {
			thirdCount++
		}
	}

	assert.Greater(t, len(different), 25)
	// These must be proportional to the focus area weight distribution.
	assert.InDelta(t, firstCount, TOTAL*0.1, TOTAL/25)
	assert.InDelta(t, secondCount, TOTAL*0.3, TOTAL/25)
	assert.InDelta(t, thirdCount, TOTAL*0.6, TOTAL/25)
}

func TestFocusAreaInAreaWeighting(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:     "patch",
			CoverPCs: map[uint64]struct{}{10: {}, 11: {}},
			Weight:   1.0,
		},
	})

	// inp1 has 100 global signal entries, but only 1 PC in the focus area.
	inp1 := generateRangedInput(target, rs, 1, 100)
	inp1.Cover = []uint64{10}

	// inp2 has only 2 global signal entries, but both of its PCs are in the focus area.
	inp2 := generateRangedInput(target, rs, 101, 102)
	inp2.Cover = []uint64{10, 11}

	corpus.Save(inp1)
	corpus.Save(inp2)

	verifySampling := func(stage string) {
		counts := make(map[*prog.Prog]int)
		const iters = 10000
		for range iters {
			counts[corpus.ChooseProgram(rnd)]++
		}
		// inp2 has 2 focus PCs, inp1 has 1 focus PC.
		// inp2 should be chosen ~2/3 (66.7%) of the time, inp1 ~1/3 (33.3%).
		// Under the old bug (len(signal)), inp1 would be chosen ~98% of the time.
		assert.InDelta(t, 2.0/3.0, float64(counts[inp2.Prog])/iters, 0.05, stage)
		assert.InDelta(t, 1.0/3.0, float64(counts[inp1.Prog])/iters, 0.05, stage)
	}

	verifySampling("before minimization")
	corpus.Minimize(true)
	verifySampling("after minimization")
}

func TestCompensatoryAreaSelection(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	// Base focus area "subsystem" covering PCs [1, 2, 3, 4] with weight 1.0.
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:     "subsystem",
			CoverPCs: map[uint64]struct{}{1: {}, 2: {}, 3: {}, 4: {}},
			Weight:   1.0,
		},
	})

	// inpHot touches hot PCs [1, 2].
	inpHot := generateRangedInput(target, rs, 1, 50)
	inpHot.Cover = []uint64{1, 2}
	inpHot.FullCover = []uint64{1, 2}

	// inpCold touches cold PCs [3, 4].
	inpCold := generateRangedInput(target, rs, 51, 55)
	inpCold.Cover = []uint64{3, 4}
	inpCold.FullCover = []uint64{3, 4}

	corpus.Save(inpHot)
	corpus.Save(inpCold)

	// In the base focus area, both inpHot (2 PCs) and inpCold (2 PCs) have equal prio (2).
	// So each is chosen ~50% of the time.
	counts := make(map[*prog.Prog]int)
	const iters = 10000
	for range iters {
		counts[corpus.ChooseProgram(rnd)]++
	}
	assert.InDelta(t, 0.5, float64(counts[inpHot.Prog])/iters, 0.05)
	assert.InDelta(t, 0.5, float64(counts[inpCold.Prog])/iters, 0.05)

	// Add dynamic compensatory area reduced to cold PCs [3, 4] with weight 1.0.
	// Base area has weight 1.0, compensatory area has weight 1.0.
	// Base area (50% of selections): inpHot ~25%, inpCold ~25%.
	// Compensatory area (50% of selections): inpCold gets 100% of 50% = 50%.
	// Overall: inpCold gets ~75%, inpHot gets ~25%.
	corpus.SetCompensatoryAreas([]FocusArea{
		{
			Name:     "subsystem [compensatory]",
			CoverPCs: map[uint64]struct{}{3: {}, 4: {}},
			Weight:   1.0,
		},
	})

	counts = make(map[*prog.Prog]int)
	for range iters {
		counts[corpus.ChooseProgram(rnd)]++
	}
	assert.InDelta(t, 0.75, float64(counts[inpCold.Prog])/iters, 0.05)
	assert.InDelta(t, 0.25, float64(counts[inpHot.Prog])/iters, 0.05)

	// Deleting compensatory area restores 50/50 distribution.
	corpus.SetCompensatoryAreas(nil)
	counts = make(map[*prog.Prog]int)
	for range iters {
		counts[corpus.ChooseProgram(rnd)]++
	}
	assert.InDelta(t, 0.5, float64(counts[inpHot.Prog])/iters, 0.05)
	assert.InDelta(t, 0.5, float64(counts[inpCold.Prog])/iters, 0.05)
}

func TestCompensatoryAreaSelectionDefaultMode(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	// In default mode, no focus areas are configured initially.
	corpus := NewCorpus(context.Background())

	inpHot := generateRangedInput(target, rs, 1, 5)
	inpHot.Cover = []uint64{1, 2}
	inpHot.FullCover = []uint64{1, 2}

	inpCold := generateRangedInput(target, rs, 6, 10)
	inpCold.Cover = []uint64{3, 4}
	inpCold.FullCover = []uint64{3, 4}

	corpus.Save(inpHot)
	corpus.Save(inpCold)

	const iters = 10000
	counts := make(map[*prog.Prog]int)
	for range iters {
		counts[corpus.ChooseProgram(rnd)]++
	}
	assert.InDelta(t, 0.5, float64(counts[inpHot.Prog])/iters, 0.05)
	assert.InDelta(t, 0.5, float64(counts[inpCold.Prog])/iters, 0.05)

	// In default mode, both "baseline" (Weight 1.0) and "compensatory" (Weight 1.0) are added.
	corpus.SetCompensatoryAreas([]FocusArea{
		{
			Name:    "baseline",
			Weight:  1.0,
			Dynamic: true,
		},
		{
			Name:      "compensatory",
			IgnorePCs: map[uint64]struct{}{1: {}, 2: {}},
			Weight:    1.0,
			Dynamic:   true,
		},
	})

	counts = make(map[*prog.Prog]int)
	for range iters {
		counts[corpus.ChooseProgram(rnd)]++
	}
	// inpCold gets 50% from compensatory + 25% from baseline = ~75%.
	// inpHot gets 0% from compensatory + 25% from baseline = ~25%.
	assert.InDelta(t, 0.75, float64(counts[inpCold.Prog])/iters, 0.05)
	assert.InDelta(t, 0.25, float64(counts[inpHot.Prog])/iters, 0.05)

	// Clearing compensatory areas restores default corpus selection.
	corpus.SetCompensatoryAreas(nil)
	counts = make(map[*prog.Prog]int)
	for range iters {
		counts[corpus.ChooseProgram(rnd)]++
	}
	assert.InDelta(t, 0.5, float64(counts[inpHot.Prog])/iters, 0.05)
	assert.InDelta(t, 0.5, float64(counts[inpCold.Prog])/iters, 0.05)
}
