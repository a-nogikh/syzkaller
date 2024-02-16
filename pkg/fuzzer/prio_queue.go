// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"container/heap"
	"sync"
)

type priority uint

const zeroPrio priority = 0

func (p priority) lessThan(other priority) bool {
	return p < other
}

func (p priority) maxWith(other priority) priority {
	if p.lessThan(other) {
		return other
	}
	return p
}

type priorityQueue[T any] struct {
	impl priorityQueueImpl[T]
	c    *sync.Cond
}

func makePriorityQueue[T any]() *priorityQueue[T] {
	return &priorityQueue[T]{
		c: sync.NewCond(&sync.Mutex{}),
	}
}

func (pq *priorityQueue[T]) Len() int {
	pq.c.L.Lock()
	defer pq.c.L.Unlock()
	return pq.impl.Len()
}

func (pq *priorityQueue[T]) push(item *priorityQueueItem[T]) {
	// TODO: what order will there be in case of equal prios?
	pq.c.L.Lock()
	defer pq.c.L.Unlock()
	heap.Push(&pq.impl, item)
	pq.c.Signal()
}

func (pq *priorityQueue[T]) popWait() *priorityQueueItem[T] {
	pq.c.L.Lock()
	defer pq.c.L.Unlock()
	for pq.impl.Len() == 0 {
		pq.c.Wait()
	}
	return heap.Pop(&pq.impl).(*priorityQueueItem[T])
}

// pop() returns an item whose prio is strictly greater than minPrio.
func (pq *priorityQueue[T]) pop(minPrio priority) *priorityQueueItem[T] {
	pq.c.L.Lock()
	defer pq.c.L.Unlock()
	if len(pq.impl) == 0 {
		return nil
	}
	if minPrio.lessThan(pq.impl[0].prio) {
		return heap.Pop(&pq.impl).(*priorityQueueItem[T])
	}
	return nil
}

// The implementation below is based on the example provided
// by https://pkg.go.dev/container/heap.

type priorityQueueItem[T any] struct {
	value T
	prio  priority
}

type priorityQueueImpl[T any] []*priorityQueueItem[T]

func (pq priorityQueueImpl[T]) Len() int { return len(pq) }

func (pq priorityQueueImpl[T]) Less(i, j int) bool {
	// We want Pop to give us the highest, not lowest,
	// priority so we use greater than here.
	return pq[j].prio.lessThan(pq[i].prio)
}

func (pq priorityQueueImpl[T]) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *priorityQueueImpl[T]) Push(x any) {
	*pq = append(*pq, x.(*priorityQueueItem[T]))
}

func (pq *priorityQueueImpl[T]) Pop() any {
	n := len(*pq)
	item := (*pq)[n-1]
	(*pq)[n-1] = nil
	*pq = (*pq)[:n-1]
	return item
}
