// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package minimize

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestBisectSliceToZero(t *testing.T) {
	t.Parallel()
	array := make([]int, 100)
	ret, err := Slice(Config[int]{
		PredBool: func(arr []int) (bool, error) {
			// No elements are needed.
			return true, nil
		},
		Logf: t.Logf,
	}, array)
	assert.NoError(t, err)
	assert.Len(t, ret, 0)
}

func TestBisectSliceFull(t *testing.T) {
	t.Parallel()
	array := make([]int, 100)
	ret, err := Slice(Config[int]{
		PredBool: func(arr []int) (bool, error) {
			// All elements are needed.
			return false, nil
		},
		Logf: t.Logf,
	}, array)
	assert.NoError(t, err)
	assert.Equal(t, ret, array)
}

func TestBisectSliceWithFixed(t *testing.T) {
	t.Parallel()
	array := make([]int, 100)
	for i := range 100 {
		array[i] = i
	}
	ret, err := SliceWithFixed(Config[int]{
		PredBool: func(arr []int) (bool, error) {
			// Let's ensure that there are always fixed elements.
			values := map[int]bool{}
			for _, v := range arr {
				values[v] = true
			}
			if !values[0] || !values[20] || !values[40] {
				t.Fatal("predicate step without fixed elements")
			}
			// And also require the elements 25 and 50.
			return values[25] && values[50], nil
		},
		Logf: t.Logf,
	}, array, func(elem int) bool {
		// Let's keep these 3 elements.
		return elem == 0 || elem == 20 || elem == 40
	})
	assert.NoError(t, err)
	assert.Equal(t, []int{0, 20, 25, 40, 50}, ret)
}

func TestBisectRandomSlice(t *testing.T) {
	t.Parallel()
	r := rand.New(testutil.RandSource(t))
	for range testutil.IterCount() {
		// Create an array of random size and set the elements that must remain to non-zero values.
		size := r.Intn(50)
		subset := r.Intn(size + 1)
		array := make([]int, size)
		for _, j := range r.Perm(size)[:subset] {
			array[j] = j + 1
		}
		var expect []int
		for _, j := range array {
			if j > 0 {
				expect = append(expect, j)
			}
		}
		predCalls := 0
		ret, err := Slice(Config[int]{
			PredBool: func(arr []int) (bool, error) {
				predCalls++
				// All elements of the subarray must be present.
				nonZero := 0
				for _, x := range arr {
					if x > 0 {
						nonZero++
					}
				}
				return nonZero == subset, nil
			},
			Logf: t.Logf,
		}, array)
		assert.NoError(t, err)
		assert.EqualValues(t, expect, ret)
		// Ensure we don't make too many predicate calls.
		maxCalls := 3 + 2*subset*(1+int(math.Floor(math.Log2(float64(size)))))
		assert.LessOrEqual(t, predCalls, maxCalls)
	}
}

func TestBisectUnknownCircumventsUnrelated(t *testing.T) {
	t.Parallel()
	// Array of 50 elements: [0, 1, 2, ..., 49].
	// Target bug requires element 10 and 20.
	// An unrelated bug is at element 35.
	// If element 35 is present in the tested slice, it crashes with the unrelated bug (ResultUnknown).
	// If element 35 is absent:
	//   - if elements 10 and 20 are both present, target crash reproduces (ResultTrue).
	//   - otherwise, no crash (ResultFalse).
	array := make([]int, 50)
	for i := range 50 {
		array[i] = i
	}
	ret, err := Slice(Config[int]{
		Pred: func(arr []int) (Result, error) {
			has := make(map[int]bool)
			for _, v := range arr {
				has[v] = true
			}
			if has[35] {
				return ResultUnknown, nil
			}
			if has[10] && has[20] {
				return ResultTrue, nil
			}
			return ResultFalse, nil
		},
		Logf: t.Logf,
	}, array)
	assert.NoError(t, err)
	assert.Equal(t, []int{10, 20}, ret)
}

func TestBisectUnknownAlwaysUnknown(t *testing.T) {
	t.Parallel()
	// When every predicate call returns ResultUnknown, the bisection splits until
	// chunks cannot be further split (size 1) and retains all elements without hanging.
	array := []int{1, 2, 3, 4}
	ret, err := Slice(Config[int]{
		Pred: func(arr []int) (Result, error) {
			return ResultUnknown, nil
		},
		Logf: t.Logf,
	}, array)
	assert.NoError(t, err)
	assert.Equal(t, array, ret)
}

func TestBisectUnknownMaxChunks(t *testing.T) {
	t.Parallel()
	// When too many chunks return ResultUnknown, MaxChunks limit stops bisection.
	array := make([]int, 64)
	for i := range 64 {
		array[i] = i
	}
	_, err := Slice(Config[int]{
		Pred: func(arr []int) (Result, error) {
			return ResultUnknown, nil
		},
		MaxChunks: 3,
		Logf:      t.Logf,
	}, array)
	assert.ErrorIs(t, err, ErrTooManyChunks)
}

func BenchmarkSplits(b *testing.B) {
	for _, guilty := range []int{1, 2, 3, 4} {
		b.Run(fmt.Sprintf("%d_guilty", guilty), func(b *testing.B) {
			var sum int
			for range b.N {
				sum += runMinimize(guilty)
			}
			b.ReportMetric(float64(sum)/float64(b.N), "remaining-elements")
		})
	}
}

func runMinimize(guilty int) int {
	const size = 300
	const steps = 5

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	array := make([]int, size)
	for _, j := range r.Perm(size)[:guilty] {
		array[j] = 1
	}

	ret, _ := Slice(Config[int]{
		MaxSteps: steps,
		PredBool: func(arr []int) (bool, error) {
			nonZero := 0
			for _, x := range arr {
				if x > 0 {
					nonZero++
				}
			}
			return nonZero == guilty, nil
		},
	}, array)
	return len(ret)
}
