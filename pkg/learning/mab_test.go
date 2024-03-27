// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestMAB(t *testing.T) {
	t.Run("exp3", func(t *testing.T) {
		testMAB(t, &EXP3[int]{
			ExplorationRate: 0.1,
		})
	})
	t.Run("expected", func(t *testing.T) {
		testMAB(t, &ExpectedMAB[int]{
			LearningRate:    0.05,
			ExplorationRate: 0.05,
		})
	})
}

func testMAB(t *testing.T, bandit MAB[int]) {
	r := rand.New(testutil.RandSource(t))

	// Expected rewards.
	// We don't want to emulate normal distribution, but we want
	// their averages to be different.
	arms := []float64{0.2, 0.7, 0.5, 0.1}
	for i := range arms {
		bandit.AddArm(i)
	}

	const steps = 15000
	counts := runMAB(r, bandit, arms, steps)
	t.Logf("initially: %v", counts)

	// Ensure that we've found the best arm.
	assert.Greater(t, counts[1], steps/2)

	// Now add one more arm.
	arms = append(arms, 0.9)
	bandit.AddArm(len(arms) - 1)

	// And re-run the experiment.
	counts = runMAB(r, bandit, arms, steps)
	t.Logf("after one new arm: %v", counts)
	assert.Greater(t, counts[len(counts)-1], steps/2)

	// Now remove some arms and add another one.
	arms = append(arms, 0.6)
	bandit.Rebuild([]int{0, 2, 5})

	counts = runMAB(r, bandit, arms, steps)
	t.Logf("after rebuild: %v", counts)
	assert.Greater(t, counts[len(counts)-1], steps/2)
}

func TestManyArms(t *testing.T) {
	r := rand.New(testutil.RandSource(t))
	bandit := &ExpectedMAB[int]{
		LearningRate:    0.05,
		ExplorationRate: 0.05,
	}
	arms := make([]float64, 1000)
	for i := 0; i < len(arms); i += 25 {
		arms[i] = 1.0
	}
	for i := range arms {
		bandit.AddArm(i)
	}
	const steps = 25000
	counts := runMAB(r, bandit, arms, steps)
	sum := 0
	for i := 0; i < len(arms); i += 25 {
		sum += counts[i]
	}
	assert.Greater(t, sum, steps/2)
}

func TestSmallDiff(t *testing.T) {
	r := rand.New(testutil.RandSource(t))
	bandit := &PlainMAB[int]{
		LearningRate:    0.02,
		ExplorationRate: 0.02,
	}
	arms := []float64{0.6, 0.7}
	for i := range arms {
		bandit.AddArm(i)
	}
	const steps = 20000
	counts := runMAB(r, bandit, arms, steps)
	t.Logf("%+v", counts)
}

func TestNonStationaryMAB(t *testing.T) {
	t.Run("exp3", func(t *testing.T) {
		testNonStationaryMAB(t, &EXP3[int]{
			ExplorationRate: 0.1,
		})
	})
	t.Run("expected", func(t *testing.T) {
		testNonStationaryMAB(t, &ExpectedMAB[int]{
			LearningRate:    0.025,
			ExplorationRate: 0.05,
		})
	})
}

func testNonStationaryMAB(t *testing.T, bandit MAB[int]) {
	r := rand.New(testutil.RandSource(t))

	arms := []float64{0.2, 0.7, 0.5, 0.1}
	for i := range arms {
		bandit.AddArm(i)
	}

	const steps = 20000
	counts := runMAB(r, bandit, arms, steps)
	t.Logf("initially: %v", counts)

	// Ensure that we've found the best arm.
	assert.Greater(t, counts[1], steps/2)

	// Now change the best arm's avg reward.
	arms[3] = 0.9
	counts = runMAB(r, bandit, arms, steps)
	t.Logf("after reward change: %v", counts)
	assert.Greater(t, counts[3], steps/2)
}

func runMAB(r *rand.Rand, bandit MAB[int], arms []float64, steps int) []int {
	counts := make([]int, len(arms))
	for i := 0; i < steps; i++ {
		action := bandit.Action(r)
		reward := r.Float64() * arms[action.Arm]
		counts[action.Arm]++
		bandit.SaveReward(action, reward)
	}
	return counts
}

func TestFenwickTreeFind(t *testing.T) {
	fw := fenwickTree[int]{}
	fw.add(0) // prefix sum: 0
	fw.add(1) // prefix sum: 1
	fw.add(2) // prefix sum: 3
	fw.add(3) // prefix sum: 6

	assert.Equal(t, 0, fw.findPrefix(-1))
	assert.Equal(t, 1, fw.findPrefix(0))
	assert.Equal(t, 2, fw.findPrefix(1))
	assert.Equal(t, 2, fw.findPrefix(2))
	assert.Equal(t, 3, fw.findPrefix(3))
	assert.Equal(t, 3, fw.findPrefix(4))
	assert.Equal(t, 4, fw.findPrefix(10))
}

func TestFenwickTree(t *testing.T) {
	fw := fenwickTree[int]{}
	fw.add(1)
	assert.Equal(t, 1, fw.prefixSum(0))

	fw.update(0, 2) // now it's 3
	assert.Equal(t, 3, fw.prefixSum(0))

	fw.add(1)
	assert.Equal(t, 3, fw.prefixSum(0))
	assert.Equal(t, 4, fw.prefixSum(1))

	fw.add(-5)
	assert.Equal(t, 3, fw.prefixSum(0))
	assert.Equal(t, 4, fw.prefixSum(1))
	assert.Equal(t, -1, fw.prefixSum(2))

	fw.add(10)
	assert.Equal(t, 9, fw.prefixSum(3))

	// The array looks like 3, 1, -5, 10.
	fw.update(1, 3)

	// Now it's 3, 4, -5, 10.
	assert.Equal(t, 3, fw.prefixSum(0))
	assert.Equal(t, 7, fw.prefixSum(1))
	assert.Equal(t, 2, fw.prefixSum(2))
	assert.Equal(t, 12, fw.prefixSum(3))
}
