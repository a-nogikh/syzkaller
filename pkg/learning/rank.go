package learning

import (
	"math"
	"sync"
)

const maxBuckets = 48

type RankerType interface {
	int | float64
}

type WindowRanker[T RankerType] struct {
	Size int

	mu       sync.RWMutex
	ranker   Ranker[T]
	elements []T
	pos      int
}

func (wr *WindowRanker[T]) Save(val T) {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	if wr.elements == nil {
		wr.elements = make([]T, wr.Size)
	}
	index := wr.pos % wr.Size
	prevVal := wr.elements[index]
	wr.elements[index] = val
	wr.pos++

	if wr.ranker.total < wr.Size {
		wr.ranker.Add(val)
	} else {
		wr.ranker.Remove(prevVal)
		wr.ranker.Add(val)
	}
}

func (wr *WindowRanker[T]) RatioLessThan(val T) float64 {
	wr.mu.RLock()
	defer wr.mu.RUnlock()
	total := wr.ranker.total
	if total == 0 {
		if val == 0 {
			return 0
		}
		return 1.0
	}
	return float64(wr.ranker.CountLessThan(val)) / float64(total)
}

func (wr *WindowRanker[T]) Distribution() []int {
	wr.mu.RLock()
	defer wr.mu.RUnlock()
	return wr.ranker.distribution()
}

type Ranker[T RankerType] struct {
	total   int
	zeros   int
	buckets [][]T
}

func (r *Ranker[T]) Add(v T) {
	if v < 0 {
		panic("only positive values are expected!")
	}
	r.total++
	if v == 0 {
		r.zeros++
		return
	}
	if r.buckets == nil {
		r.buckets = make([][]T, maxBuckets)
	}
	index := r.bucket(v)
	r.buckets[index] = append(r.buckets[index], v)
}

func (r *Ranker[T]) Remove(v T) {
	if v < 0 {
		panic("only positive values are expected!")
	}
	r.total--
	if r.total < 0 {
		panic("ranker length is negative")
	}
	if v == 0 {
		r.zeros--
		return
	}
	index := r.bucket(v)
	for i, bucketVal := range r.buckets[index] {
		if bucketVal != v {
			continue
		}

		if len(r.buckets) > 1 {
			r.buckets[index][i] = r.buckets[index][len(r.buckets[index])-1]
		}
		r.buckets[index] = r.buckets[index][:len(r.buckets[index])-1]
		return
	}
	panic("value is not present")
}

func (r *Ranker[T]) distribution() []int {
	ret := make([]int, maxBuckets)
	for i := 0; i < len(r.buckets); i++ {
		ret[i] = len(r.buckets[i])
	}
	return ret
}

func (r *Ranker[T]) CountLessThan(v T) int {
	ret := 0
	if v > 0 {
		ret += r.zeros
	}
	if len(r.buckets) == 0 {
		return ret
	}
	index := r.bucket(v)
	for i := 0; i < index; i++ {
		ret += len(r.buckets[i])
	}
	for _, inBucket := range r.buckets[index] {
		if inBucket < v {
			ret++
		}
	}
	return ret
}

func (r *Ranker[T]) bucket(v T) int {
	ret := int(math.Sqrt(float64(v)) * 4.0)
	if ret >= maxBuckets {
		return maxBuckets - 1
	}
	return ret
}
