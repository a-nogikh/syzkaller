// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package generic

import (
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestBisectArrayToZero(t *testing.T) {
	t.Parallel()
	array := make([]int, 100)
	ret, err := Array(ArrayConfig[int]{
		Pred: func(arr []int) (bool, error) {
			// No elements are needed.
			return true, nil
		},
		Logf: t.Logf,
	}, array[:50], array[50:])
	assert.NoError(t, err)
	assert.Len(t, ret, 0)
}

func TestBisectArrayFull(t *testing.T) {
	t.Parallel()
	array := make([]int, 100)
	ret, err := Array(ArrayConfig[int]{
		Pred: func(arr []int) (bool, error) {
			// All elements are needed.
			return false, nil
		},
		Logf: t.Logf,
	}, array)
	assert.NoError(t, err)
	assert.Equal(t, ret, array)
}

func TestBisectRandomArray(t *testing.T) {
	t.Parallel()
	r := rand.New(testutil.RandSource(t))
	for i := 0; i < testutil.IterCount(); i++ {
		// Create an array of random size and set the elements that must remain to non-zero values.
		size := 1 + r.Intn(50)
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
		ret, err := Array(ArrayConfig[int]{
			Pred: func(arr []int) (bool, error) {
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
		maxCalls := 1 + 2*subset*(1+int(math.Floor(math.Log2(float64(size)))))
		assert.True(t, predCalls <= maxCalls)
	}
}
