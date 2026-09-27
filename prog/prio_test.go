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

func TestChoiceTableBoost(t *testing.T) {
	target, rs, _ := initTest(t)
	boosted := target.SyscallMap["getpid"]
	enabled := map[*Syscall]bool{boosted: true}
	for _, c := range target.Syscalls[:200] {
		if !c.Attrs.Disabled && !c.Attrs.NoGenerate {
			enabled[c] = true
		}
	}
	ct := target.BuildChoiceTable(nil, enabled)
	ctBoosted := *ct
	// The mmap call is not enabled, so it must be ignored.
	mmap := target.SyscallMap["mmap"]
	require.False(t, enabled[mmap])
	ctBoosted.Boost([]int{boosted.ID, mmap.ID})
	r := rand.New(rs)
	const iters = 10000
	count := func(ct *ChoiceTable) int {
		n := 0
		for range iters {
			id := ct.choose(r, -1)
			require.NotEqual(t, mmap.ID, id)
			if id == boosted.ID {
				n++
			}
		}
		return n
	}
	require.Less(t, count(ct), iters/20)
	require.Greater(t, count(&ctBoosted), iters/10)
}
