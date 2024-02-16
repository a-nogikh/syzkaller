// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrioQueueOrder(t *testing.T) {
	pq := makePriorityQueue[int]()
	pq.push(&priorityQueueItem[int]{value: 1, prio: 1})
	pq.push(&priorityQueueItem[int]{value: 3, prio: 3})
	pq.push(&priorityQueueItem[int]{value: 2, prio: 2})

	assert.Equal(t, 3, pq.popWait().value)
	assert.Equal(t, 2, pq.popWait().value)
	assert.Equal(t, 1, pq.popWait().value)
	assert.Nil(t, pq.pop(0))
}

func TestPrioQueuePop(t *testing.T) {
	pq := makePriorityQueue[int]()
	pq.push(&priorityQueueItem[int]{value: 1, prio: 1})
	pq.push(&priorityQueueItem[int]{value: 2, prio: 2})
	assert.Nil(t, pq.pop(2))
	assert.Equal(t, 2, pq.pop(1).value)
}

func TestPrioQueueWait(t *testing.T) {
	var wg sync.WaitGroup
	pq := makePriorityQueue[int]()
	assert.Nil(t, pq.pop(0))

	wg.Add(1)
	go func() {
		assert.Equal(t, 10, pq.popWait().value)
		wg.Done()
	}()

	pq.push(&priorityQueueItem[int]{value: 10, prio: 1})
	wg.Wait()
}
