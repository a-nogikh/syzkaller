// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"math"
	"math/rand"
)

type Action[T comparable] struct {
	Arm   T
	index int
}

type MAB[T comparable] interface {
	Rebuild(newArms []T)
	AddArm(arm T)
	Action(r *rand.Rand) Action[T]
	// Reward must be [0;1].
	SaveReward(action Action[T], reward float64)
}

type PlainMAB[T comparable] struct {
	LearningRate    float64
	ExplorationRate float64
	arms            []T
	weights         []float64
}

func (p *PlainMAB[T]) AddArm(arm T) {
	p.arms = append(p.arms, arm)
	p.weights = append(p.weights, 1.0)
}

func (p *PlainMAB[T]) Action(r *rand.Rand) Action[T] {
	var pos int
	if r.Float64() < p.ExplorationRate {
		pos = r.Intn(len(p.arms))
	} else {
		for i := 1; i < len(p.arms); i++ {
			if p.weights[i] > p.weights[pos] {
				pos = i
			}
		}
	}
	return Action[T]{Arm: p.arms[pos], index: pos}
}

func (p *PlainMAB[T]) SaveReward(action Action[T], reward float64) {
	if action.index >= len(p.arms) || p.arms[action.index] != action.Arm {
		return
	}
	oldWeight := p.weights[action.index]
	delta := (reward - oldWeight) * p.LearningRate
	p.weights[action.index] += delta
}

func (p *PlainMAB[T]) Rebuild(newArms []T) {
	panic("not implemented!")
}

type SoftMax[T comparable] struct {
	ExplorationRate float64
	LearningRate    float64
	Tau             float64
	arms            []T
	values          []valueCount
	weights         []int64
	prefixes        fenwickTree[int64]
}

func (s *SoftMax[T]) AddArm(arm T) {
	s.moveArm(arm, valueCount{0, 0})
}

func (s *SoftMax[T]) moveArm(arm T, v valueCount) {
	w := s.weight(v.value)

	s.weights = append(s.weights, w)
	s.values = append(s.values, v)
	s.arms = append(s.arms, arm)
	s.prefixes.add(w)
}

func (s *SoftMax[T]) Rebuild(newArms []T) {
	armToIndex := map[T]int{}
	for i, arm := range s.arms {
		armToIndex[arm] = i
	}
	sNew := &SoftMax[T]{
		ExplorationRate: s.ExplorationRate,
		LearningRate:    s.LearningRate,
		Tau:             s.Tau,
	}
	for _, arm := range newArms {
		oldIndex, ok := armToIndex[arm]
		if !ok {
			sNew.AddArm(arm)
			continue
		}
		sNew.moveArm(arm, s.values[oldIndex])
	}
	*s = *sNew
}

func (s *SoftMax[T]) Action(r *rand.Rand) Action[T] {
	var pos int
	if r.Float64() < s.ExplorationRate {
		pos = r.Intn(len(s.arms))
	} else {
		totalWeight := s.prefixes.prefixSum(len(s.arms) - 1)
		randPrefix := r.Float64() * float64(totalWeight)
		pos = s.prefixes.findPrefix(int64(randPrefix))
	}
	if pos >= len(s.arms) {
		pos = len(s.arms) - 1
	}
	return Action[T]{
		Arm:   s.arms[pos],
		index: pos,
	}
}

func (s *SoftMax[T]) SaveReward(action Action[T], reward float64) {
	// There's a chance that the action refers to the situation before Rebuild().
	if action.index >= len(s.arms) || s.arms[action.index] != action.Arm {
		return
	}
	s.values[action.index].update(reward, s.LearningRate)
	oldWeight := s.weights[action.index]
	newWeight := s.weight(s.values[action.index].value)
	delta := newWeight - oldWeight

	s.weights[action.index] += delta
	s.prefixes.update(action.index, delta)
}

func (s *SoftMax[T]) Weights() map[T]int64 {
	m := map[T]int64{}
	for i, k := range s.arms {
		m[k] = s.weights[i]
	}
	return m
}

func (s *SoftMax[T]) weight(w float64) int64 {
	return int64(math.Exp(w/s.Tau) * 100.0)
}

type valueCount struct {
	value float64
	count int64
}

func (vc *valueCount) update(value, minRate float64) {
	alpha := 1.0 / (float64(vc.count) + 1.0)
	if alpha < minRate {
		alpha = minRate
	}
	vc.count++
	vc.value = vc.value + (value-vc.value)*alpha
}

// Fenwick tree provides log(N) prefix sum operations.
type fenwickTree[T int | float64 | int64] struct {
	elements []T
}

// findPrefix() finds the first index i for which prefixSum(i) > sum.
// If there's no such element, it returns |N|.
func (f *fenwickTree[T]) findPrefix(sum T) int {
	size := len(f.elements)
	log2 := int(math.Log2(float64(size))) + 1
	ret := 0
	for power2 := 1 << log2; power2 > 0; power2 /= 2 {
		testPos := ret + power2
		if testPos > size {
			continue
		}
		if f.elements[testPos-1] <= sum {
			ret += power2
			sum -= f.elements[testPos-1]
		}
	}
	return ret
}

func (f *fenwickTree[T]) prefixSum(untilIndex int) T {
	var sum T
	i := untilIndex + 1
	for i > 0 {
		sum += f.elements[i-1]
		i -= i & (-i)
	}
	return sum
}

func (f *fenwickTree[T]) update(i int, delta T) {
	i++
	for i <= len(f.elements) {
		f.elements[i-1] += delta
		i += i & (-i)
	}
}

func (f *fenwickTree[T]) add(value T) {
	size := len(f.elements) + 1
	for pow2 := 1; pow2 < size; pow2 *= 2 {
		prev := size - pow2
		if prev+(prev&(-prev)) == size {
			value += f.elements[prev-1]
		}
	}
	f.elements = append(f.elements, value)
}

func (f *fenwickTree[T]) scale(scale T) {
	for i := 0; i < len(f.elements); i++ {
		f.elements[i] *= scale
	}
}
