// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type InputTest struct {
	p    *prog.Prog
	sign signal.Signal
	sig  hash.Sig
}

func TestAddInputConcurrency(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}

	const (
		routines = 10
		iters    = 100
	)

	for i := 0; i < routines; i++ {
		go func() {
			rs := rand.NewSource(0)
			r := rand.New(rs)
			for it := 0; it < iters; it++ {
				inp := generateInput(target, rs, 10, it)
				fuzzer.addInputToCorpus(inp.p, inp.sign, inp.sig)
				fuzzer.chooseProgram(r).Clone()
			}
		}()
	}
}

func generateInput(target *prog.Target, rs rand.Source, ncalls, sizeSig int) (inp InputTest) {
	inp.p = target.Generate(rs, ncalls, target.DefaultChoiceTable())
	var raw []uint32
	for i := 1; i <= sizeSig; i++ {
		raw = append(raw, uint32(i))
	}
	inp.sign = signal.FromRaw(raw, 0)
	inp.sig = hash.Hash(inp.p.Serialize())
	return
}

func getTarget(t *testing.T, os, arch string) *prog.Target {
	t.Parallel()
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}
