// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"container/heap"
	"fmt"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

// Work queues hold work items (see Work* struct) and do prioritization among
// them. For example, we want to triage and send to manager new inputs before
// we smash programs in order to not permanently lose interesting programs in
// case of a VM crash.

// GlobalWorkQueue holds work items that are global to the whole syz-fuzzer.
// At the moment these are the work items coming from syz-manager, and we
// naturally want them to be distributed among all procs.
type GlobalWorkQueue struct {
	mu             sync.RWMutex
	candidate      []*WorkCandidate
	procs          int
	needCandidates chan struct{}
}

// GroupWorkQueue holds work items for a particular subset of procs. The intent is
// to let the fuzzer operate on different subsystems simultaneously. If only one
// work queue is used for the whole syz-fuzzer, similar progs tend to spread
// over almost all procs. It is not very efficient, e.g. when such progs contain many
// blocking syscalls and, as a result, the whole VM is just idle most of the time.
type GroupWorkQueue struct {
	mu              sync.RWMutex
	globalQueue     *GlobalWorkQueue
	triage          []*WorkTriage
	triageCandidate []*WorkTriage
	smash           *SmashQueue
}

type ProgTypes int

const (
	ProgCandidate ProgTypes = 1 << iota
	ProgMinimized
	ProgSmashed
	ProgNormal ProgTypes = 0
)

// WorkTriage are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type WorkTriage struct {
	p     *prog.Prog
	call  int
	info  ipc.CallInfo
	flags ProgTypes
}

// WorkCandidate are programs from hub.
// We don't know yet if they are useful for this fuzzer or not.
// A proc handles them the same way as locally generated/mutated programs.
type WorkCandidate struct {
	p     *prog.Prog
	flags ProgTypes
}

// WorkSmash are programs just added to corpus.
// During smashing these programs receive a one-time special attention
// (emit faults, collect comparison hints, etc).
type WorkSmash struct {
	p          *prog.Prog
	call       int
	subtype    interface{}
	randomPrio float64
}

type DoFaultInjection struct{}
type DoProgHints struct{}
type DoProgSmash struct {
	newSignal        int
	durationLastTime time.Duration
	totalIterations  int
	totalDuration    time.Duration
}

type SmashQueue []*WorkSmash

func (queue SmashQueue) Len() int {
	return len(queue)
}

func (queue SmashQueue) Swap(i, j int) {
	queue[i], queue[j] = queue[j], queue[i]
}

func (queue *SmashQueue) Push(item interface{}) {
	*queue = append(*queue, item.(*WorkSmash))
}

func (queue *SmashQueue) Pop() (ret interface{}) {
	len := queue.Len()
	if len == 0 {
		panic("queue is empty")
	}
	ret = (*queue)[len-1]
	(*queue)[len-1] = nil
	*queue = (*queue)[:len-1]
	return
}

func (w *WorkSmash) GetPriority() int {
	const hintsPrio = 1e6
	const newSmashPrio = 1e6
	const smashPrio = 2e6

	// The priority is based on the following principles.
	// 1. Fault injection has the highest priority (i.e. the lowest number).
	// 2. Not-yet-attempted smash and hints have the same priority.
	// 3. Among attempted smashes, ones that found more new signal on avg have precedence.
	prio := 0
	switch v := w.subtype.(type) {
	case *DoFaultInjection:
	case *DoProgHints:
		prio += hintsPrio
	case *DoProgSmash:
		if v.totalIterations == 0 {
			prio += newSmashPrio
		} else {
			prio = smashPrio - 10*v.newSignal/v.totalIterations
		}

	default:
		panic(fmt.Sprintf("cannot calculate priority for %T", v))
	}
	return prio
}

func (queue SmashQueue) Less(i, j int) bool {
	first, second := queue[i], queue[j]
	pLeft, pRight := first.GetPriority(), second.GetPriority()
	if pLeft != pRight {
		return pLeft < pRight
	}
	return first.randomPrio < second.randomPrio
}

func newGlobalWorkQueue(procs int, needCandidates chan struct{}) *GlobalWorkQueue {
	return &GlobalWorkQueue{
		procs:          procs,
		needCandidates: needCandidates,
	}
}

func (wq *GlobalWorkQueue) enqueue(item interface{}) {
	wq.mu.Lock()
	defer wq.mu.Unlock()
	switch item := item.(type) {
	case *WorkCandidate:
		wq.candidate = append(wq.candidate, item)
	default:
		panic("GlobalWorkQueue: unknown work type")
	}
}

func (wq *GlobalWorkQueue) dequeue() (item interface{}) {
	wq.mu.Lock()
	wantCandidates := false
	if len(wq.candidate) != 0 {
		last := len(wq.candidate) - 1
		item = wq.candidate[last]
		wq.candidate = wq.candidate[:last]
		wantCandidates = len(wq.candidate) < wq.procs

	}
	wq.mu.Unlock()
	if wantCandidates {
		select {
		case wq.needCandidates <- struct{}{}:
		default:
		}
	}
	return item
}

func (wq *GlobalWorkQueue) wantCandidates() bool {
	wq.mu.RLock()
	defer wq.mu.RUnlock()
	return len(wq.candidate) < wq.procs
}

func newGroupWorkQueue(global *GlobalWorkQueue) *GroupWorkQueue {
	return &GroupWorkQueue{
		globalQueue: global,
		smash:       &SmashQueue{},
	}
}

func (wq *GroupWorkQueue) enqueue(item interface{}) {
	wq.mu.Lock()
	defer wq.mu.Unlock()
	switch item := item.(type) {
	case *WorkTriage:
		if item.flags&ProgCandidate != 0 {
			wq.triageCandidate = append(wq.triageCandidate, item)
		} else {
			wq.triage = append(wq.triage, item)
		}
	case *WorkSmash:
		heap.Push(wq.smash, item)
	default:
		panic("GroupWorkQueue: unknown work type")
	}
}

func (wq *GroupWorkQueue) detach() {
	wq.mu.Lock()
	wq.globalQueue = nil
	wq.mu.Unlock()
}

func (wq *GroupWorkQueue) dequeue() (item interface{}) {
	// Triage candidate have the highest priority - handle them first.
	wq.mu.Lock()
	if len(wq.triageCandidate) != 0 {
		last := len(wq.triageCandidate) - 1
		item = wq.triageCandidate[last]
		wq.triageCandidate = wq.triageCandidate[:last]
	}
	globalQueue := wq.globalQueue
	wq.mu.Unlock()
	if item != nil {
		return
	}

	if globalQueue != nil {
		// If there are no triage candidates, ry to query the global queue
		// for a candidate.
		item = globalQueue.dequeue()
		if item != nil {
			return
		}
	}
	wq.mu.Lock()
	if len(wq.triage) != 0 {
		last := len(wq.triage) - 1
		item = wq.triage[last]
		wq.triage = wq.triage[:last]
	} else if wq.smash.Len() != 0 {
		item = heap.Pop(wq.smash)
	}
	wq.mu.Unlock()
	return item
}
