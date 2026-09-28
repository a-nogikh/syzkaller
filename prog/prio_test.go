// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestNormalizePrios(t *testing.T) {
	prios := [][]int32{
		{2, 2, 2},
		{1, 2, 4},
		{1, 2, 0},
	}
	want := [][]int32{
		{10, 10, 10},
		{4, 8, 17},
		{10, 20, 0},
	}
	t.Logf("had:  %+v", prios)
	normalizePrios(prios, len(prios))
	if !reflect.DeepEqual(prios, want) {
		t.Logf("got:  %+v", prios)
		t.Errorf("want: %+v", want)
	}
}

// Test static priorities assigned based on argument direction.
func TestStaticPriorities(t *testing.T) {
	target := initTargetTest(t, "linux", "amd64")
	rs := rand.NewSource(0)
	// The test is probabilistic and needs some sensible number of iterations to succeed.
	// If it fails try to increase the number a bit.
	const iters = 200000
	// The first call is the one that creates a resource and the rest are calls that can use that resource.
	tests := [][]string{
		{"open", "read", "write", "mmap"},
		{"socket", "listen", "setsockopt"},
	}
	ct := target.DefaultChoiceTable()
	r := rand.New(rs)
	for _, syscalls := range tests {
		// Counts the number of times a call is chosen after a call that creates a resource (referenceCall).
		counter := make(map[string]int)
		referenceCall := syscalls[0]
		for _, call := range syscalls {
			count := 0
			for range iters {
				chosenCall := target.Syscalls[ct.choose(r, target.SyscallMap[call].ID)].Name
				if call == referenceCall {
					counter[chosenCall]++
				} else if chosenCall == referenceCall {
					count++
				}
			}
			if call == referenceCall {
				continue
			}
			// Checks that prio[callCreatesRes][callUsesRes] > prio[callUsesRes][callCreatesRes]
			if count >= counter[call] {
				t.Fatalf("too high priority for %s -> %s: %d vs %s -> %s: %d",
					call, referenceCall, count, referenceCall, call, counter[call])
			}
		}
	}
}

func TestNoGenerateBias(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	noGen := target.SyscallMap["test$no_generate_produce_common"]
	staticRelated := target.SyscallMap["test$consume_common"]
	dynamicRelated := target.SyscallMap["test$int"]
	unrelated := target.SyscallMap["test"]

	enabled := map[*Syscall]bool{
		noGen:          true,
		staticRelated:  true,
		dynamicRelated: true,
		unrelated:      true,
	}
	corpus := []*Prog{
		{
			Target: target,
			Calls:  []*Call{MakeCall(noGen, nil), MakeCall(dynamicRelated, nil)},
		},
	}
	prios, _ := target.CalculatePriorities(corpus, enabled)
	require.Greater(t, prios[noGen.ID][staticRelated.ID], prios[noGen.ID][unrelated.ID])
	require.Greater(t, prios[noGen.ID][dynamicRelated.ID], prios[noGen.ID][unrelated.ID])
	for c := range enabled {
		require.Zero(t, prios[c.ID][noGen.ID])
	}

	ct := target.BuildChoiceTable(corpus, enabled)
	require.True(t, ct.Enabled(noGen.ID))
	require.False(t, ct.Generatable(noGen.ID))

	r := rand.New(rand.NewSource(0))
	counts := make(map[int]int)
	for range 1000 {
		chosen := ct.choose(r, noGen.ID)
		require.NotEqual(t, noGen.ID, chosen)
		counts[chosen]++
	}
	require.Greater(t, counts[staticRelated.ID], counts[unrelated.ID])
	require.Greater(t, counts[dynamicRelated.ID], counts[unrelated.ID])
}

func TestPrioDeterminism(t *testing.T) {
	if testutil.RaceEnabled {
		t.Skip("skipping in race mode, too slow")
	}
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	var corpus []*Prog
	for range 100 {
		corpus = append(corpus, target.Generate(rs, 10, ct))
	}
	ct0 := target.BuildChoiceTable(corpus, nil)
	ct1 := target.BuildChoiceTable(corpus, nil)
	if !reflect.DeepEqual(ct0.runs, ct1.runs) {
		t.Fatal("non-deterministic ChoiceTable")
	}
	for i := range iters {
		seed := rs.Int63()
		call0 := ct0.choose(rand.New(rand.NewSource(seed)), -1)
		call1 := ct1.choose(rand.New(rand.NewSource(seed)), -1)
		if call0 != call1 {
			t.Fatalf("seed=%v iter=%v call=%v/%v", seed, i, call0, call1)
		}
	}
}

func BenchmarkBuildChoiceTable(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	for range b.N {
		target.BuildChoiceTable(nil, nil)
	}
}
