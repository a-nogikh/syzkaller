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

type ExpectedMAB[T comparable] struct {
	LearningRate    float64
	ExplorationRate float64
	baseMAB[T]
}

func (e *ExpectedMAB[T]) AddArm(arm T) {
	e.baseMAB.AddArm(arm, 0.001)
}

func (e *ExpectedMAB[T]) AddWeightedArm(arm T, weight float64) {
	e.baseMAB.AddArm(arm, weight)
}

func (e *ExpectedMAB[T]) Action(r *rand.Rand) Action[T] {
	return e.baseMAB.Action(r, e.ExplorationRate)
}

func (e *ExpectedMAB[T]) SaveReward(action Action[T], reward float64) {
	// There's a chance that the action refers to the situation before Rebuild().
	if action.index >= len(e.arms) || e.arms[action.index] != action.Arm {
		return
	}
	reward = math.Pow(reward, 8)
	//	reward = math.Exp(5 * (reward - 0.5))
	oldWeight := e.weights[action.index]
	delta := (reward - oldWeight) * e.LearningRate
	e.updateWeight(action.index, delta)
}

type baseMAB[T comparable] struct {
	totalWeight float64
	weights     []float64
	arms        []T
	prefixes    fenwickTree[float64]
}

func (b *baseMAB[T]) Rebuild(newArms []T) {
	armToIndex := map[T]int{}
	for i, arm := range b.arms {
		armToIndex[arm] = i
	}

	var addArms []T
	bNew := &baseMAB[T]{}
	for _, arm := range newArms {
		oldIndex, ok := armToIndex[arm]
		if !ok {
			addArms = append(addArms, arm)
			continue
		}
		weight := b.weights[oldIndex]
		bNew.arms = append(bNew.arms, arm)
		bNew.weights = append(bNew.weights, weight)
		bNew.totalWeight += weight
		bNew.prefixes.add(weight)
	}
	for _, arm := range addArms {
		bNew.AddArm(arm, 1.0)
	}
	*b = *bNew
}

func (b *baseMAB[T]) AddArm(arm T, w float64) {
	b.totalWeight += w
	b.weights = append(b.weights, w)
	b.arms = append(b.arms, arm)
	b.prefixes.add(w)
}

func (b *baseMAB[T]) Action(r *rand.Rand, exploration float64) Action[T] {
	var pos int
	if r.Float64() < exploration {
		pos = r.Intn(len(b.arms))
	} else {
		randPrefix := r.Float64() * b.prefixes.prefixSum(len(b.prefixes.elements)-1)
		pos = b.prefixes.findPrefix(randPrefix)
	}
	if pos >= len(b.arms) {
		pos = len(b.arms) - 1
	}
	return Action[T]{
		Arm:   b.arms[pos],
		index: pos,
	}
}

func (b *baseMAB[T]) updateWeight(index int, delta float64) {
	b.totalWeight += delta
	b.weights[index] += delta
	b.prefixes.update(index, delta)
}

// Due to exponentially growing weights, we need to periodically rebuild the MAB.
const rebalanceAfter = 1e50

type EXP3[T comparable] struct {
	ExplorationRate float64
	baseMAB[T]

	maxWeight float64
}

func (e *EXP3[T]) AddArm(arm T) {
	w := 1.0
	if len(e.weights) > 0 {
		w = e.totalWeight / float64(len(e.weights))
	}
	e.baseMAB.AddArm(arm, w)
}

func (e *EXP3[T]) Rebuild(newArms []T) {
	e.baseMAB.Rebuild(newArms)
	e.rebalance()
}

func (e *EXP3[T]) Action(r *rand.Rand) Action[T] {
	return e.baseMAB.Action(r, e.ExplorationRate)
}

func (e *EXP3[T]) SaveReward(action Action[T], reward float64) {
	// There's a chance that the action refers to the situation before Rebuild().
	if action.index >= len(e.arms) || e.arms[action.index] != action.Arm {
		return
	}
	total := float64(len(e.arms))
	oldWeight := e.weights[action.index]
	// Let's pretend that we've just selected the action.
	p := (1.0-e.ExplorationRate)*oldWeight/e.totalWeight + e.ExplorationRate/total
	// EXP3.S: see https://arxiv.org/pdf/2201.01628.pdf.
	// We need this addition to better handle the non-stationary case.
	const alpha = 0.01
	newWeight := oldWeight*math.Exp(e.ExplorationRate*(reward/p)/total) + math.E*alpha*e.totalWeight/total
	if math.IsInf(newWeight, 0) || math.IsNaN(newWeight) {
		panic("inf/nan arm weight")
	}
	if newWeight > e.maxWeight {
		e.maxWeight = newWeight
	}
	e.updateWeight(action.index, newWeight-oldWeight)
	e.tryRebalance()
}

func (e *EXP3[T]) tryRebalance() {
	if e.maxWeight < rebalanceAfter {
		return
	}
	e.rebalance()
}

func (e *EXP3[T]) rebalance() {
	maxWeight := e.weights[0]
	for i := 0; i < len(e.arms); i++ {
		w := e.weights[i]
		if w > maxWeight {
			maxWeight = w
		}
	}
	scale := float64(len(e.arms)) / maxWeight
	for i := 0; i < len(e.arms); i++ {
		e.weights[i] *= scale
	}
	e.totalWeight *= scale
	e.prefixes.scale(scale)
	e.maxWeight = maxWeight * scale
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

func (s *SoftMax[T]) weight(w float64) int64 {
	return int64(math.Exp(w/s.Tau) * 100.0)
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
