// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"container/heap"
	"math/rand"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestSmashQueue(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, runtime.GOARCH)
	if err != nil {
		t.Skipf("%s arch is not supported for Linux", runtime.GOARCH)
	}
	prog := target.Generate(rand.NewSource(0), 10, target.DefaultChoiceTable())
	_testSmashPrios(prog, t)
	_testSmashQueue(prog, t)
}

func _testSmashPrios(prog *prog.Prog, t *testing.T) {
	ensureLess := func(subtypeLeft, subtypeRight interface{}, allowEq bool) {
		left := &WorkSmash{
			p:       prog,
			subtype: subtypeLeft,
		}
		right := &WorkSmash{
			p:       prog,
			subtype: subtypeRight,
		}
		pLeft, pRight := left.GetPriority(), right.GetPriority()
		if !allowEq && pLeft >= pRight {
			t.Fatalf("%#v's prio %d >= than %#v's prio %d", left, pLeft, right, pRight)
		}
		if allowEq && pLeft > pRight {
			t.Fatalf("%#v's prio %d > than %#v's prio %d", left, pLeft, right, pRight)
		}
	}
	// Lower number means higher priority.
	ensureLess(&DoFaultInjection{}, &DoProgHints{}, false)

	// Not-yet-run hints and smash tasks have the same prio.
	ensureLess(&DoFaultInjection{}, &DoProgSmash{}, true)
	ensureLess(&DoProgSmash{}, &DoProgHints{}, true)

	// Smashes that yield more signal on avg are prioritized.
	ensureLess(&DoProgSmash{
		newSignal:       40,
		totalIterations: 20,
		totalDuration:   time.Minute,
	}, &DoProgSmash{
		newSignal:       15,
		totalIterations: 10,
		totalDuration:   time.Minute,
	}, false)
}

func _testSmashQueue(prog *prog.Prog, t *testing.T) {
	inj := &WorkSmash{
		p:       prog,
		subtype: &DoFaultInjection{},
	}
	hints := &WorkSmash{
		p:          prog,
		subtype:    &DoProgHints{},
		randomPrio: 10,
	}
	lowPrioSmash := &WorkSmash{
		p: prog,
		subtype: &DoProgSmash{
			newSignal:       0,
			totalIterations: 10,
			totalDuration:   time.Minute * 10,
		},
		randomPrio: 10,
	}
	q := &SmashQueue{}
	heap.Push(q, hints)
	heap.Push(q, inj)
	heap.Push(q, lowPrioSmash)

	task := heap.Pop(q)
	if task != inj {
		t.Fatalf("pop queue: expect DoFaultInjection, got %T %v", task, task)
	}
	task = heap.Pop(q)
	if task != hints {
		t.Fatalf("pop queue: expect DoProgHints, got %T %v", task, task)
	}
	task = heap.Pop(q)
	if task != lowPrioSmash {
		t.Fatalf("pop queue: expect DoProgSmash, got %T %v", task, task)
	}
}
