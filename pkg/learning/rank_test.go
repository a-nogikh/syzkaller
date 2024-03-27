package learning

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRank(t *testing.T) {
	r := &Ranker[int]{}
	assert.Equal(t, 0, r.CountLessThan(0))

	r.Add(0)
	assert.Equal(t, 0, r.CountLessThan(0))
	assert.Equal(t, 1, r.CountLessThan(1))

	for i := 1; i <= 50; i++ {
		r.Add(i)
	}

	for i := 0; i <= 50; i++ {
		assert.Equal(t, i, r.CountLessThan(i), "i=%d", i)
	}

	for i := 0; i <= 50; i++ {
		r.Remove(i)
		assert.Equal(t, 50-i, r.CountLessThan(51), "i=%d", i)
	}

	r.Add(1e8)
	assert.Equal(t, 1, r.CountLessThan(1e8+1))
}

func TestWindowRanker(t *testing.T) {
	wr := &WindowRanker[float64]{
		Size: 3,
	}
	assert.Equal(t, 0.0, wr.RatioLessThan(0))
	for i := 1; i <= 3; i++ {
		wr.Save(float64(i))
	}
	for i := 0; i < 3; i++ {
		assert.InDelta(t, 0.0, wr.RatioLessThan(1.0), 0.01, "iter=%d", i)
		assert.InDelta(t, 1.0/3.0, wr.RatioLessThan(2.0), 0.01, "iter=%d", i)
		assert.InDelta(t, 2.0/3.0, wr.RatioLessThan(3.0), 0.01, "iter=%d", i)
		assert.InDelta(t, 3.0/3.0, wr.RatioLessThan(4.0), 0.01, "iter=%d", i)
		for i := 1; i <= 3; i++ {
			wr.Save(float64(i))
		}
	}
	for i := 10; i <= 12; i++ {
		wr.Save(float64(i))
	}

	assert.InDelta(t, 0.0, wr.RatioLessThan(10.0), 0.01)
	assert.InDelta(t, 1.0/3.0, wr.RatioLessThan(11.0), 0.01)
	assert.InDelta(t, 2.0/3.0, wr.RatioLessThan(12.0), 0.01)
	assert.InDelta(t, 3.0/3.0, wr.RatioLessThan(13.0), 0.01)
}
