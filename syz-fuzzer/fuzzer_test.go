// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueueToChan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan int, 100)
	q := newQueueToChan(out, 5)
	go q.run(ctx)
	for i := 0; ; {
		<-q.needMore
		var elements []int
		for j := 0; j < 10; j++ {
			i++
			elements = append(elements, i)
		}
		q.addList(elements)
		if i == 100 {
			break
		}
	}
	for i := 0; i < 100; i++ {
		assert.Equal(t, i+1, <-out)
	}
	close(out)
}
