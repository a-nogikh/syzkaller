// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
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
	normalizePrios(prios, len(prios))
	require.Equal(t, want, prios)
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
			require.Lessf(t, count, counter[call], "too high priority for %s -> %s: %d vs %s -> %s: %d",
				call, referenceCall, count, referenceCall, call, counter[call])
		}
	}
}

func TestDynamicPriorities(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	pColocated, err := target.Deserialize([]byte("test$res0()\ntest$int(0x1, 0x2, 0x3, 0x4, 0x5)\n"), Strict)
	require.NoError(t, err)
	pMulti, err := target.Deserialize([]byte("test$res0()\ntest$opt1(0x0)\ntest$align0(0x0)\n"), Strict)
	require.NoError(t, err)
	pSinglePair, err := target.Deserialize([]byte("test$align1(0x0)\ntest$align2(0x0)\n"), Strict)
	require.NoError(t, err)

	var corpus []*Prog
	for range 80 {
		corpus = append(corpus, pColocated.Clone())
	}
	for range 20 {
		corpus = append(corpus, pMulti.Clone())
	}
	corpus = append(corpus, pSinglePair)

	ct := target.BuildChoiceTable(corpus, nil)
	res0ID := target.SyscallMap["test$res0"].ID
	intID := target.SyscallMap["test$int"].ID
	align0ID := target.SyscallMap["test$align0"].ID
	align1ID := target.SyscallMap["test$align1"].ID
	align2ID := target.SyscallMap["test$align2"].ID

	// Verify that dynamic colocation boosts test$int after test$res0 while still exploring static/other calls.
	r := rand.New(rand.NewSource(0))
	const iters = 10000
	counts := make(map[int]int)
	for range iters {
		counts[ct.choose(r, res0ID)]++
	}
	assert.Greater(t, counts[intID], iters/20, "colocated call should be chosen frequently")
	assert.Less(t, counts[intID], iters*4/10, "colocated call should not monopolize all choices")

	// Verify that a call with only a single known co-occurring call in the corpus
	// does not hand 50% of all choices to that single pair.
	singleCounts := make(map[int]int)
	for range iters {
		singleCounts[ct.choose(r, align1ID)]++
	}
	assert.Greater(t, singleCounts[align2ID], iters/50, "single corpus pair should still be explored")
	assert.Less(t, singleCounts[align2ID], iters/5, "single corpus pair must not hog 50%% of choices")

	// Verify multi-call context: when prefix is [test$res0, test$opt1], test$align0 is colocated with both.
	prefixProg, err := target.Deserialize([]byte("test$res0()\ntest$opt1(0x0)\n"), Strict)
	require.NoError(t, err)
	multiCounts := make(map[int]int)
	for range iters {
		multiCounts[ct.chooseCalls(r, prefixProg.Calls)]++
	}
	assert.Greater(t, multiCounts[align0ID], iters/20, "multi-call colocated call should be boosted")
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
	require.Equal(t, ct0.callTags, ct1.callTags)
	require.Equal(t, ct0.tagCalls, ct1.tagCalls)
	require.Equal(t, ct0.dynamicCalls, ct1.dynamicCalls)
	for i := range iters {
		seed := rs.Int63()
		call0 := ct0.choose(rand.New(rand.NewSource(seed)), -1)
		call1 := ct1.choose(rand.New(rand.NewSource(seed)), -1)
		require.Equal(t, call0, call1, "seed=%v iter=%v", seed, i)

		p := corpus[i%len(corpus)]
		callCtx0 := ct0.chooseCalls(rand.New(rand.NewSource(seed)), p.Calls)
		callCtx1 := ct1.chooseCalls(rand.New(rand.NewSource(seed)), p.Calls)
		require.Equal(t, callCtx0, callCtx1, "seed=%v iter=%v", seed, i)
	}
}

func BenchmarkBuildChoiceTable(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	for range b.N {
		target.BuildChoiceTable(nil, nil)
	}
}

func BenchmarkChoiceTableChoose(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	rs := rand.NewSource(0)
	ct0 := target.DefaultChoiceTable()
	var corpus []*Prog
	for range 1000 {
		corpus = append(corpus, target.Generate(rs, 20, ct0))
	}
	ct := target.BuildChoiceTable(corpus, nil)
	r := rand.New(rs)
	sampleProg := corpus[0]
	b.ResetTimer()
	for i := range b.N {
		ct.chooseCalls(r, sampleProg.Calls[:i%len(sampleProg.Calls)+1])
	}
}
