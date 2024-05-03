// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"context"
	"math/rand"
	"sync"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

type Request struct {
	Prog       *prog.Prog
	NeedSignal SignalType
	NeedCover  bool
	NeedHints  bool
	// If specified, the resulting signal for call SignalFilterCall
	// will include subset of it even if it's not new.
	SignalFilter     signal.Signal
	SignalFilterCall int

	// This stat will be incremented on request completion.
	Stat *stats.Val

	// The callback will be called on request completion in the LIFO order.
	// If it returns false, all further processing will be stopped.
	// It allows wrappers to intercept Done() requests.
	callback DoneCallback

	resultC chan *Result
}

type DoneCallback func(*Request, *Result) bool

func (r *Request) OnDone(cb DoneCallback) {
	oldCallback := r.callback
	r.callback = func(req *Request, res *Result) bool {
		r.callback = oldCallback
		if !cb(req, res) {
			return false
		}
		if oldCallback == nil {
			return true
		}
		return oldCallback(req, res)
	}
}

func (r *Request) Done(res *Result) {
	if r.callback != nil {
		if !r.callback(r, res) {
			return
		}
	}
	if r.Stat != nil {
		r.Stat.Add(1)
	}
	if r.resultC != nil {
		r.resultC <- res
	}
}

// Execute puts the request on the queue and blocks execution until
// either the request is done or the context is cancelled.
func Execute(ctx context.Context, executor Executor, req *Request) *Result {
	req.resultC = make(chan *Result, 1)
	executor.Submit(req)
	select {
	case <-ctx.Done():
		return &Result{Status: ExecFailure}
	case res := <-req.resultC:
		close(req.resultC)
		return res
	}
}

type SignalType int

const (
	NoSignal  SignalType = iota // we don't need any signal
	NewSignal                   // we need the newly seen signal
	AllSignal                   // we need all signal
)

type Result struct {
	Info   *ipc.ProgInfo
	Status Status
}

func (r *Result) Stop() bool {
	return r.Status == ExecFailure || r.Status == Crashed
}

type Status int

const (
	Success     Status = 0
	ExecFailure Status = 1 // For e.g. serialization errors.
	Crashed     Status = 2 // The VM crashed holding the request.
	Restarted   Status = 3 // The VM was restarted holding the request.
)

// Executor describes the interface wanted by the producers of requests.
type Executor interface {
	Submit(req *Request)
}

// Source describes the interface wanted by the consumers of requests.
type Source interface {
	Next() *Request
}

// PlainQueue is a straighforward thread-safe Request queue implementation.
type PlainQueue struct {
	stat  *stats.Val
	mu    sync.Mutex
	queue []*Request
	pos   int
}

func Plain() *PlainQueue {
	return &PlainQueue{}
}

func PlainWithStat(val *stats.Val) *PlainQueue {
	return &PlainQueue{stat: val}
}

func (pq *PlainQueue) Len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.queue) - pq.pos
}

func (pq *PlainQueue) Submit(req *Request) {
	if pq.stat != nil {
		pq.stat.Add(1)
	}
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// It doesn't make sense to compact the queue too often.
	const minSizeToCompact = 128
	if pq.pos > len(pq.queue)/2 && len(pq.queue) >= minSizeToCompact {
		copy(pq.queue, pq.queue[pq.pos:])
		for pq.pos > 0 {
			newLen := len(pq.queue) - 1
			pq.queue[newLen] = nil
			pq.queue = pq.queue[:newLen]
			pq.pos--
		}
	}
	pq.queue = append(pq.queue, req)
}

func (pq *PlainQueue) Next() *Request {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return pq.nextLocked()
}

func (pq *PlainQueue) tryNext() *Request {
	if !pq.mu.TryLock() {
		return nil
	}
	defer pq.mu.Unlock()
	return pq.nextLocked()
}

func (pq *PlainQueue) nextLocked() *Request {
	if pq.pos < len(pq.queue) {
		ret := pq.queue[pq.pos]
		pq.queue[pq.pos] = nil
		pq.pos++
		if pq.stat != nil {
			pq.stat.Add(-1)
		}
		return ret
	}
	return nil
}

// SourceMultiplexer combines several different sources in a particular order.
// It is NOT thread-safe.
type SourceMultiplexer struct {
	sources []Source
}

func Multiplex(sources ...Source) Source {
	return &SourceMultiplexer{sources: sources}
}

func (sm *SourceMultiplexer) Next() *Request {
	for _, s := range sm.sources {
		req := s.Next()
		if req != nil {
			return req
		}
	}
	return nil
}

type callback struct {
	cb func() *Request
}

// Callback produces a source that calls the callback to serve every Next() request.
func Callback(cb func() *Request) Source {
	return &callback{cb}
}

func (cb *callback) Next() *Request {
	return cb.cb()
}

type alternate struct {
	base Source
	mu   sync.Mutex
	rnd  *rand.Rand
	prob float32
}

// Alternate returns a nil *Request in `prob` share of requests.
func Alternate(base Source, rnd *rand.Rand, prob float32) Source {
	return &alternate{
		base: base,
		rnd:  rnd,
		prob: prob,
	}
}

func (a *alternate) Next() *Request {
	var skip bool
	if a.mu.TryLock() {
		skip = a.rnd.Float32() < a.prob
		a.mu.Unlock()
	}
	if skip {
		return nil
	}
	return a.base.Next()
}
