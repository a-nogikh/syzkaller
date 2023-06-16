// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package generic

import (
	"errors"
	"fmt"
	"strings"
)

type ArrayConfig[T any] struct {
	Pred      func([]T) (bool, error)
	PredLimit int
	MaxChunks int
	Logf      func(string, ...interface{})
}

// Array performs a generic binary-search based minimization algorithm.
// The aim is to remove as many invidiual elements as possible while still
// ensuring that Pred(concatenated remaining parts) == true.
func Array[T any](config ArrayConfig[T], startElements ...[]T) ([]T, error) {
	if config.Logf == nil {
		config.Logf = func(string, ...interface{}) {}
	}
	var chunks []*arrayChunk[T]
	for _, elems := range startElements {
		if len(elems) == 0 {
			continue
		}
		chunks = append(chunks, &arrayChunk[T]{
			elements: elems,
		})
	}
	ctx := &arrayCtx[T]{
		config: config,
		chunks: chunks,
	}
	return ctx.bisect()
}

type arrayCtx[T any] struct {
	config   ArrayConfig[T]
	chunks   []*arrayChunk[T]
	predRuns int
}

type arrayChunk[T any] struct {
	elements []T
	final    bool // There's no way to further split this chunk.
}

var ErrTooManyChunks = errors.New("too many chunks")

func (ctx *arrayCtx[T]) bisect() ([]T, error) {
	// At first, we don't know if the original chunks are really necessary.
	err := ctx.dropIndividualChunks()
	// Then, keep on splitting the chunks layer by layer until we have identified
	// all necessary elements.
	// This way we ensure that we always go from lager to smaller chunks.
	for err == nil && !ctx.done() {
		if ctx.config.MaxChunks > 0 && len(ctx.chunks) > ctx.config.MaxChunks {
			err = ErrTooManyChunks
			continue
		}
		err = ctx.splitChunks()
	}
	// If we hit the limit on the number of runs, just let it return the current result.
	if err == errTooManySteps {
		err = nil
	}
	if err != nil && err != ErrTooManyChunks {
		return nil, err
	}
	return ctx.elements(), err
}

// dropIndividualChunks() attempts to remove each known chunk.
func (ctx *arrayCtx[T]) dropIndividualChunks() error {
	ctx.config.Logf("drop individual chunks: %s", ctx.chunkInfo())
	var newChunks []*arrayChunk[T]
	for i, chunk := range ctx.chunks {
		ctx.config.Logf("try to drop chunk #%d <%d>", i, len(chunk.elements))
		ret, err := ctx.run(newChunks, nil, ctx.chunks[i+1:])
		if err != nil {
			return err
		}
		if ret {
			ctx.config.Logf("predicate returned true without the chunk, drop it")
			continue
		}
		ctx.config.Logf("the chunk is needed")
		newChunks = append(newChunks, chunk)
	}
	ctx.chunks = newChunks
	return nil
}

// splitChunks() splits each chunk in two and only leaves the necessary sub-parts.
func (ctx *arrayCtx[T]) splitChunks() error {
	ctx.config.Logf("split chunks: %s", ctx.chunkInfo())
	var newChunks []*arrayChunk[T]
	for i, chunk := range ctx.chunks {
		if chunk.final {
			newChunks = append(newChunks, chunk)
			continue
		}
		ctx.config.Logf("split chunk #%d of len %d", i, len(chunk.elements))
		chunkA, chunkB := splitChunk[T](chunk.elements)
		if len(chunkA) == 0 || len(chunkB) == 0 {
			ctx.config.Logf("no way to further split the chunk")
			chunk.final = true
			return nil
		}
		ctx.config.Logf("new sub-chunks: A <%d> and B <%d>", len(chunkA), len(chunkB))
		ctx.config.Logf("try without A")
		retA, err := ctx.run(newChunks, chunkB, ctx.chunks[i+1:])
		if err != nil {
			return err
		}
		retB := false
		if !retA {
			ctx.config.Logf("A was necessary; try with A, but without B")
			retB, err = ctx.run(newChunks, chunkA, ctx.chunks[i+1:])
			if err != nil {
				return err
			}
			newChunks = append(newChunks, &arrayChunk[T]{
				elements: chunkA,
			})
		} else {
			ctx.config.Logf("A was unnecessary, drop it")
		}
		if !retB {
			ctx.config.Logf("B was necessary; keep it")
			newChunks = append(newChunks, &arrayChunk[T]{
				elements: chunkB,
			})
		} else {
			ctx.config.Logf("B was unnecessary, drop it")
		}
	}
	ctx.chunks = newChunks
	return nil
}

var errTooManySteps = errors.New("we reached the limit of predicate runs")

func (ctx *arrayCtx[T]) run(before []*arrayChunk[T], mid []T, after []*arrayChunk[T]) (bool, error) {
	if ctx.config.PredLimit > 0 && ctx.predRuns >= ctx.config.PredLimit {
		ctx.config.Logf("we have reached the limit of predicate runs (%d)", ctx.config.PredLimit)
		return false, errTooManySteps
	}
	ctx.predRuns++
	return ctx.config.Pred(mergeChunks(before, mid, after))
}

func (ctx *arrayCtx[T]) done() bool {
	for _, chunk := range ctx.chunks {
		if !chunk.final {
			return false
		}
	}
	return true
}

func (ctx *arrayCtx[T]) elements() []T {
	return mergeChunks(ctx.chunks, nil, nil)
}

func (ctx *arrayCtx[T]) chunkInfo() string {
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
