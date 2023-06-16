// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package minimize

import (
	"errors"
	"fmt"
	"strings"
)

type Config[T any] struct {
	// The original slice is minimized with respect to this predicate.
	// If Pred(X) returns true, X is assumed to contain all elements that must stay.
	Pred func([]T) (bool, error)
	// MaxSteps is a limit on the number of predicate calls during bisection.
	// If it's hit, the bisection continues as if Pred() begins to return false.
	// If it's set to 0 (by default), no limit is applied.
	MaxSteps int
	// MaxChunks sets a limit on the number of chunks pursued by the bisection algorithm.
	// If we hit the limit, bisection is stopped and Array() returns ErrTooManyChunks
	// anongside the intermediate bisection result (a valid, but not fully minimized slice).
	MaxChunks int
	// Logf is used for sharing debugging output.
	Logf func(string, ...interface{})
}

// Slice() finds a minimal subsequence of slice elements that still gives Pred() == true.
// The algorithm works by sequentially splitting the slice into smaller-size chunks and running
// Pred() witout those chunks. Slice() receives the original slice chunks.
// The expected number of Pred() runs is O(|result|*log2(|elements|)).
func Slice[T any](config Config[T], startChunks ...[]T) ([]T, error) {
	if config.Logf == nil {
		config.Logf = func(string, ...interface{}) {}
	}
	var chunks []*arrayChunk[T]
	for _, elems := range startChunks {
		if len(elems) == 0 {
			continue
		}
		chunks = append(chunks, &arrayChunk[T]{
			elements: elems,
		})
	}
	ctx := &sliceCtx[T]{
		Config: config,
		chunks: chunks,
	}
	return ctx.bisect()
}

type sliceCtx[T any] struct {
	Config[T]
	chunks   []*arrayChunk[T]
	predRuns int
}

type arrayChunk[T any] struct {
	elements []T
	final    bool // There's no way to further split this chunk.
}

// ErrTooManyChunks is returned if the number of necessary chunks surpassed MaxChunks.
var ErrTooManyChunks = errors.New("the bisection process is following too many necessary chunks")

func (ctx *sliceCtx[T]) bisect() ([]T, error) {
	// At first, we don't know if the original chunks are really necessary.
	err := ctx.dropIndividualChunks()
	// Then, keep on splitting the chunks layer by layer until we have identified
	// all necessary elements.
	// This way we ensure that we always go from larger to smaller chunks.
	for err == nil && !ctx.done() {
		if ctx.MaxChunks > 0 && len(ctx.chunks) > ctx.MaxChunks {
			err = ErrTooManyChunks
			break
		}
		err = ctx.splitChunks()
	}
	if err != nil && err != ErrTooManyChunks {
		return nil, err
	}
	return ctx.elements(), err
}

// dropIndividualChunks() attempts to remove each known chunk.
func (ctx *sliceCtx[T]) dropIndividualChunks() error {
	ctx.Logf("drop individual chunks: %s", ctx.chunkInfo())
	var newChunks []*arrayChunk[T]
	for i, chunk := range ctx.chunks {
		ctx.Logf("try to drop chunk #%d <%d>", i, len(chunk.elements))
		ret, err := ctx.predRun(newChunks, nil, ctx.chunks[i+1:])
		if err != nil {
			return err
		}
		if ret {
			ctx.Logf("predicate returned true without the chunk, drop it")
			continue
		}
		ctx.Logf("the chunk is needed")
		newChunks = append(newChunks, chunk)
	}
	ctx.chunks = newChunks
	return nil
}

// splitChunks() splits each chunk in two and only leaves the necessary sub-parts.
func (ctx *sliceCtx[T]) splitChunks() error {
	ctx.Logf("split chunks: %s", ctx.chunkInfo())
	var newChunks []*arrayChunk[T]
	for i, chunk := range ctx.chunks {
		if chunk.final {
			newChunks = append(newChunks, chunk)
			continue
		}
		ctx.Logf("split chunk #%d of len %d", i, len(chunk.elements))
		chunkA, chunkB := splitChunk[T](chunk.elements)
		if len(chunkA) == 0 || len(chunkB) == 0 {
			ctx.Logf("no way to further split the chunk")
			chunk.final = true
			return nil
		}
		ctx.Logf("new sub-chunks: A <%d> and B <%d>", len(chunkA), len(chunkB))
		ctx.Logf("try without A")
		retA, err := ctx.predRun(newChunks, chunkB, ctx.chunks[i+1:])
		if err != nil {
			return err
		}
		retB := false
		if !retA {
			// Pred() returned false without A => we must keep A for now.
			// However, it doesn't say anything about B.
			ctx.Logf("A was necessary; try with A, but without B")
			retB, err = ctx.predRun(newChunks, chunkA, ctx.chunks[i+1:])
			if err != nil {
				return err
			}
			newChunks = append(newChunks, &arrayChunk[T]{
				elements: chunkA,
			})
		} else {
			// Pred() returned true without A => drop it.
			// In this case, we don't need to run Pred() without B,
			// it should return false anyway.
			ctx.Logf("A was unnecessary, drop it")
		}
		if !retB {
			ctx.Logf("B was necessary; keep it")
			newChunks = append(newChunks, &arrayChunk[T]{
				elements: chunkB,
			})
		} else {
			ctx.Logf("B was unnecessary, drop it")
		}
	}
	ctx.chunks = newChunks
	return nil
}

// predRun() determines whether (before + mid + after) covers the necessary elements.
func (ctx *sliceCtx[T]) predRun(before []*arrayChunk[T], mid []T, after []*arrayChunk[T]) (bool, error) {
	if ctx.MaxSteps > 0 && ctx.predRuns >= ctx.MaxSteps {
		ctx.Logf("we have reached the limit on predicate runs (%d); pretend it returns false",
			ctx.MaxSteps)
		return false, nil
	}
	ctx.predRuns++
	return ctx.Pred(mergeChunks(before, mid, after))
}

// The bisection process is done once every chunk is marked as final.
func (ctx *sliceCtx[T]) done() bool {
	for _, chunk := range ctx.chunks {
		if !chunk.final {
			return false
		}
	}
	return true
}

func (ctx *sliceCtx[T]) elements() []T {
	return mergeChunks(ctx.chunks, nil, nil)
}

func (ctx *sliceCtx[T]) chunkInfo() string {
	var parts []string
	for _, chunk := range ctx.chunks {
		str := ""
		if chunk.final {
			str = ", final"
		}
		parts = append(parts, fmt.Sprintf("<%d%s>", len(chunk.elements), str))
	}
	return strings.Join(parts, ", ")
}

func mergeChunks[T any](before []*arrayChunk[T], mid []T, after []*arrayChunk[T]) []T {
	var ret []T
	for _, chunk := range before {
		ret = append(ret, chunk.elements...)
	}
	ret = append(ret, mid...)
	for _, chunk := range after {
		ret = append(ret, chunk.elements...)
	}
	return ret
}

func splitChunk[T any](chunk []T) ([]T, []T) {
	return chunk[:len(chunk)/2], chunk[len(chunk)/2:]
}
