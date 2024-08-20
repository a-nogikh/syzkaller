// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import "sync"

const maxQueue = 2500

type seedSelection struct {
	mu       sync.Mutex
	counts   map[uint64]int
	queue    [][]uint64
	queuePos int
}

// The bigger the better.
func (s *seedSelection) evaluate(raw []uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	ret := 0
	for _, pc := range raw {
		if s.counts[pc] < 25 {
			ret++
		}
	}

	return ret
}

func (s *seedSelection) save(raw []uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counts == nil {
		s.counts = make(map[uint64]int)
	}
	if len(s.queue) < maxQueue {
		s.queue = append(s.queue, raw)
	} else {
		old := s.queue[s.queuePos]
		s.queue[s.queuePos] = raw
		s.queuePos = (s.queuePos + 1) % maxQueue
		for _, pc := range old {
			s.counts[pc]--
		}
	}
	for _, pc := range raw {
		s.counts[pc]++
	}
}
