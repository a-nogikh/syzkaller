// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/prog"
)

// WorkQueue holds global non-fuzzing work items (see the Work* structs below).
// WorkQueue also does prioritization among work items, for example, we want
// to triage and send to manager new inputs before we smash programs
// in order to not permanently lose interesting programs in case of VM crash.
type WorkQueue struct {
	mu              sync.RWMutex
	triageCandidate []interface{}
	candidate       []interface{}
	triage          []interface{}
	smash           []interface{}

	procs          int
	rnd            *rand.Rand
	needCandidates chan struct{}
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
	p             *prog.Prog
	call          int
	injectionDone bool
	hintsDone     bool
	mutationsDone int
}

func newWorkQueue(procs int, needCandidates chan struct{}) *WorkQueue {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &WorkQueue{
		procs:          procs,
		needCandidates: needCandidates,
		rnd:            rnd,
	}
}

func (wq *WorkQueue) enqueue(item interface{}) {
	wq.mu.Lock()
	defer wq.mu.Unlock()
	switch item := item.(type) {
	case *WorkTriage:
		if item.flags&ProgCandidate != 0 {
			wq.triageCandidate = append(wq.triageCandidate, item)
		} else {
			wq.triage = append(wq.triage, item)
		}
	case *WorkCandidate:
		wq.candidate = append(wq.candidate, item)
	case *WorkSmash:
		wq.smash = append(wq.smash, item)
	default:
		panic("unknown work type")
	}
}

func (wq *WorkQueue) extractElement(queue *[]interface{}) interface{} {
	size := len(*queue)
	randElem := &(*queue)[wq.rnd.Intn(size)]
	ret := *randElem
	*randElem = (*queue)[size-1]
	*queue = (*queue)[:size-1]
	return ret
}

func (wq *WorkQueue) dequeue() (item interface{}) {
	wq.mu.RLock()
	if len(wq.triageCandidate)+len(wq.candidate)+len(wq.triage)+len(wq.smash) == 0 {
		wq.mu.RUnlock()
		return nil
	}
	wq.mu.RUnlock()
	wq.mu.Lock()
	wantCandidates := false
	if len(wq.triageCandidate) != 0 {
		item = wq.extractElement(&wq.triageCandidate)
	} else if len(wq.candidate) != 0 {
		item = wq.extractElement(&wq.candidate)
		wantCandidates = len(wq.candidate) < wq.procs
	} else if len(wq.triage) != 0 {
		item = wq.extractElement(&wq.triage)
	} else if len(wq.smash) != 0 {
		item = wq.extractElement(&wq.smash)
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

func (wq *WorkQueue) wantCandidates() bool {
	wq.mu.RLock()
	defer wq.mu.RUnlock()
	return len(wq.candidate) < wq.procs
}
