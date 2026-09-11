// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestPCSampler(t *testing.T) {
	now := time.Now()
	sampler := newPCSampler(now)

	sampler.collect(&flatrpc.ProgInfo{
		Calls: []*flatrpc.CallInfo{
			{Cover: []uint64{10, 20}},
			{Cover: []uint64{20, 30}},
		},
		Extra: &flatrpc.CallInfo{Cover: []uint64{40}},
	})

	// The window is not complete yet, so nothing is returned and nothing is reset.
	_, _, execs, elapsed, ok := sampler.trySnapshotAndReset(now.Add(time.Second), 1, time.Minute)
	require.False(t, ok)
	require.Equal(t, 1, execs)
	require.Equal(t, time.Second, elapsed)

	// Too few executions.
	_, _, _, _, ok = sampler.trySnapshotAndReset(now.Add(10*time.Minute), 10, time.Minute)
	require.False(t, ok)

	// Both conditions are satisfied.
	hits, totalHits, execCount, _, ok := sampler.trySnapshotAndReset(now.Add(10*time.Minute), 1, time.Minute)
	require.True(t, ok)
	require.Equal(t, 1, execCount)
	require.Equal(t, 5, totalHits)
	require.Equal(t, 1, hits[10])
	require.Equal(t, 2, hits[20])
	require.Equal(t, 1, hits[30])
	require.Equal(t, 1, hits[40])

	// The sampler must have started a new window.
	hitsAfter, totalAfter, execAfter, _, ok := sampler.trySnapshotAndReset(now.Add(20*time.Minute), 0, 0)
	require.True(t, ok)
	require.Equal(t, 0, totalAfter)
	require.Equal(t, 0, execAfter)
	require.Empty(t, hitsAfter)
}

func TestCalculateCompensatoryAreasDefault(t *testing.T) {
	// Sampled PC hits: PC 10 has 80 hits (80%), PC 20 has 10 hits (10%), PC 30 has 10 hits (10%).
	hits := map[uint64]int{
		10: 80,
		20: 10,
		30: 10,
	}

	comp := calculateCompensatoryAreas(nil, hits, 50, 0.80, nil)
	require.Len(t, comp, 2)
	require.Equal(t, "baseline", comp[0].Name)
	require.Equal(t, 1.0, comp[0].Weight)
	require.True(t, comp[0].Dynamic)
	require.Empty(t, comp[0].CoverPCs)
	require.Empty(t, comp[0].IgnorePCs)

	require.Equal(t, "compensatory", comp[1].Name)
	require.Equal(t, 1.0, comp[1].Weight)
	require.True(t, comp[1].Dynamic)
	require.Empty(t, comp[1].CoverPCs)
	// PC 10 constitutes 80% of total hits, so it should be the only ignored PC.
	require.Equal(t, map[uint64]struct{}{10: {}}, comp[1].IgnorePCs)
}

func TestCalculateCompensatoryAreasMultipleAreas(t *testing.T) {
	baseAreas := []corpus.FocusArea{
		{
			Name:     "net",
			CoverPCs: map[uint64]struct{}{1: {}, 2: {}, 3: {}},
			Weight:   10.0,
		},
		{
			Name:     "fs",
			CoverPCs: map[uint64]struct{}{4: {}, 5: {}},
			Weight:   5.0,
		},
	}

	hits := map[uint64]int{
		// Net PCs: PC 1 has 90 hits, PC 2 has 10 hits (total 100 hits).
		1: 90,
		2: 10,
		// Fs PCs: PC 4 has 10 hits, PC 5 has 10 hits (total 20 hits, below minSamples 50).
		4: 10,
		5: 10,
	}

	comp := calculateCompensatoryAreas(baseAreas, hits, 50, 0.85, nil)
	require.Len(t, comp, 1)
	require.Equal(t, "net [compensatory]", comp[0].Name)
	require.Equal(t, 10.0, comp[0].Weight)
	require.True(t, comp[0].Dynamic)
	// Positive filter reduced to cold PCs (2 and 3), hot PC (1) excluded.
	require.Equal(t, map[uint64]struct{}{2: {}, 3: {}}, comp[0].CoverPCs)
	require.Empty(t, comp[0].IgnorePCs)
}

func TestCalculateCompensatoryAreasThresholds(t *testing.T) {
	// Empty hits.
	require.Nil(t, calculateCompensatoryAreas(nil, nil, 50, 0.85, nil))
	require.Nil(t, calculateCompensatoryAreas(nil, map[uint64]int{}, 50, 0.85, nil))

	// Total samples below minSamples.
	hitsLow := map[uint64]int{10: 20, 20: 10}
	require.Nil(t, calculateCompensatoryAreas(nil, hitsLow, 50, 0.85, nil))

	// All PCs end up hot in global area (no remaining PCs to focus on).
	hitsEqual := map[uint64]int{10: 50, 20: 50}
	require.Nil(t, calculateCompensatoryAreas(nil, hitsEqual, 50, 0.85, nil))

	// All PCs end up hot in configured area (colderPCs empty).
	base := []corpus.FocusArea{{Name: "test", CoverPCs: map[uint64]struct{}{10: {}, 20: {}}, Weight: 1.0}}
	require.Nil(t, calculateCompensatoryAreas(base, hitsEqual, 50, 0.85, nil))
}

func TestEndToEndCompensatoryReevaluation(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	ctx := t.Context()
	c := corpus.NewCorpus(ctx)

	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:             c,
		Coverage:           true,
		CompReevalInterval: -1, // disable background timer
	}, rand.New(rand.NewSource(0)), target)

	// Save two inputs:
	// inpHot touches only hot PCs [10, 20].
	inpHot := corpus.NewInput{
		Prog:      target.Generate(rand.New(rand.NewSource(1)), 3, target.DefaultChoiceTable()),
		Call:      0,
		Signal:    signal.FromRaw([]uint64{10, 20}, 0),
		Cover:     []uint64{10, 20},
		FullCover: []uint64{10, 20},
	}
	c.Save(inpHot)

	// inpCold touches hot PCs [10, 20] and cold PC 30.
	inpCold := corpus.NewInput{
		Prog:      target.Generate(rand.New(rand.NewSource(2)), 3, target.DefaultChoiceTable()),
		Call:      0,
		Signal:    signal.FromRaw([]uint64{10, 20, 30}, 0),
		Cover:     []uint64{30},
		FullCover: []uint64{10, 20, 30},
	}
	c.Save(inpCold)

	// Simulate sampled executions with 85% attention on PC 10 and 20.
	fuzzer.sampler.collect(&flatrpc.ProgInfo{
		Calls: []*flatrpc.CallInfo{
			{Cover: makeRepeatedPCs(10, 45)},
			{Cover: makeRepeatedPCs(20, 40)},
			{Cover: makeRepeatedPCs(30, 15)},
		},
	})

	// Reevaluate with minExecs=1, minDuration=0, minAreaHits=10, and cutoff=0.85.
	fuzzer.ReevaluateCompensatoryAreasWithParams(1, 0, 10, 0.85)

	// In default mode, baseline area contains both inputs, while compensatory area contains only inpCold.
	areas := c.ProgsPerArea()
	require.Equal(t, 2, areas["baseline"])
	require.Equal(t, 1, areas["compensatory"])

	// Reevaluate with minExecs=0 (no new samples): dynamic areas should be removed.
	fuzzer.ReevaluateCompensatoryAreasWithParams(0, 0, 10, 0.85)
	areasAfter := c.ProgsPerArea()
	require.Equal(t, 0, areasAfter["baseline"])
	require.Equal(t, 0, areasAfter["compensatory"])
}

func makeRepeatedPCs(pc uint64, count int) []uint64 {
	pcs := make([]uint64, count)
	for i := range pcs {
		pcs[i] = pc
	}
	return pcs
}

func TestSamplingFlags(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	ctx := t.Context()
	c := corpus.NewCorpus(ctx)

	fuzzer := NewFuzzer(ctx, &Config{
		Corpus:             c,
		Coverage:           true,
		Collide:            true,
		CompReevalInterval: -1,
	}, rand.New(rand.NewSource(0)), target)

	sampledCount := 0
	collideCount := 0
	const iters = 10000
	for range iters {
		req := fuzzer.genFuzz()
		if req.Stat == fuzzer.statExecCollide {
			collideCount++
			require.Zero(t, req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover,
				"collide request must not have ExecFlagCollectCover")
		} else if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover != 0 {
			sampledCount++
		}
	}

	require.Greater(t, collideCount, 0)
	expectedSampled := float64(iters-collideCount) * 0.05
	require.InDelta(t, expectedSampled, sampledCount, 100)

	// Verification that ExecFlagCollectComps requests are never sampled into pcSampler.
	compsReq := &queue.Request{
		ExecOpts: flatrpc.ExecOpts{
			ExecFlags: flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectComps,
		},
	}
	fuzzer.processResult(compsReq, &queue.Result{
		Status: queue.Success,
		Info: &flatrpc.ProgInfo{
			Calls: []*flatrpc.CallInfo{
				{Cover: []uint64{999}},
			},
		},
	}, 0, 0)
	_, totalHits, _, _, ok := fuzzer.sampler.trySnapshotAndReset(time.Now(), 0, 0)
	require.True(t, ok)
	require.Equal(t, 0, totalHits, "comparison requests must never be collected into pcSampler")
}
