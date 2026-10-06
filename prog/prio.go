// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"cmp"
	"fmt"
	"maps"
	"math"
	"math/rand"
	"slices"
	"sort"
	"strings"
)

// Calculation of call-to-call priorities.
// For a given pair of calls X and Y, the priority is our guess as to whether
// additional of call Y into a program containing call X is likely to give
// new coverage or not.
// The current algorithm has two components: static and dynamic.
// The static component is based on analysis of argument types. For example,
// if call X and call Y both accept fd[sock], then they are more likely to give
// new coverage together.
// The dynamic component is based on frequency of occurrence of a particular
// pair of syscalls in a single program in corpus. For example, if socket and
// connect frequently occur in programs together, we give higher priority to
// this pair of syscalls.
// Note: the current implementation is very basic, there is no theory behind any
// constants.

// CalculatePriorities returns the priority matrix as well as the map of generatable syscalls.
// The rows/columns corresponding to the non-generatable syscalls are left to be 0.
func (target *Target) CalculatePriorities(corpus []*Prog, enabled map[*Syscall]bool) ([][]int32, map[*Syscall]bool) {
	enabled = target.prepareEnabledSyscalls(corpus, enabled)
	static := target.calcStaticPriorities(enabled)
	if len(corpus) != 0 {
		// Let's just sum the static and dynamic distributions.
		dynamic := target.calcDynamicPrio(corpus, enabled)
		for i, prios := range dynamic {
			dst := static[i]
			for j, p := range prios {
				dst[j] += p
			}
		}
	}
	if debug {
		for _, syscall := range target.Syscalls {
			if enabled[syscall] {
				continue
			}
			for i := range static {
				if static[i][syscall.ID] != 0 || static[syscall.ID][i] != 0 {
					panic(fmt.Sprintf("prio matrix has non-zero value for a disabled syscall %d",
						syscall.ID))
				}
			}
		}
	}
	return static, enabled
}

func (target *Target) prepareEnabledSyscalls(corpus []*Prog, enabled map[*Syscall]bool) map[*Syscall]bool {
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	noGenerateCalls := make(map[int]bool)
	enabledCalls := make(map[*Syscall]bool)
	for call := range enabled {
		if call.Attrs.NoGenerate {
			noGenerateCalls[call.ID] = true
		} else if !call.Attrs.Disabled {
			enabledCalls[call] = true
		}
	}
	// Some validation checks.
	if len(enabledCalls) == 0 {
		panic("no syscalls enabled and generatable")
	}
	for _, p := range corpus {
		for _, call := range p.Calls {
			if !enabledCalls[call.Meta] && !noGenerateCalls[call.Meta.ID] {
				fmt.Printf("corpus contains disabled syscall %v\n", call.Meta.Name)
				for call := range enabled {
					fmt.Printf("%s: enabled\n", call.Name)
				}
				panic("disabled syscall")
			}
		}
	}
	return enabledCalls
}

func (target *Target) calcStaticPriorities(enabled map[*Syscall]bool) [][]int32 {
	uses := target.calcResourceUsage(enabled)
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, weightMap := range uses {
		// Iteration over map is slow, especially here when we do it O(N^2) times.
		callWeights := slices.Collect(maps.Values(weightMap))
		for _, w0 := range callWeights {
			for _, w1 := range callWeights {
				if w0.call == w1.call {
					// Self-priority is assigned below.
					continue
				}
				// The static priority is assigned based on the direction of arguments. A higher priority will be
				// assigned when c0 is a call that produces a resource and c1 a call that uses that resource.
				prios[w0.call][w1.call] += w0.inout*w1.in*3/2 + w0.inout*w1.inout
			}
		}
	}
	// The value assigned for self-priority (call wrt itself) have to be high, but not too high.
	for c := range enabled {
		pp := prios[c.ID]
		pp[c.ID] = max(1, slices.Max(pp)*3/4)
	}
	normalizePrios(prios, len(enabled))
	return prios
}

func (target *Target) calcResourceUsage(enabled map[*Syscall]bool) map[string]map[int]weights {
	uses := make(map[string]map[int]weights)
	ForeachType(target.Syscalls, func(t Type, ctx *TypeCtx) {
		c := ctx.Meta
		if !enabled[c] {
			ctx.Stop = true
			return
		}
		switch a := t.(type) {
		case *ResourceType:
			if target.AuxResources[a.Desc.Name] {
				noteUsagef(uses, c, 1, ctx.Dir, "res%v", a.Desc.Name)
			} else {
				var str strings.Builder
				str.WriteString("res")
				for i, k := range a.Desc.Kind {
					str.WriteString("-" + k)
					w := int32(10)
					if i < len(a.Desc.Kind)-1 {
						w = 2
					}
					noteUsage(uses, c, w, ctx.Dir, str.String())
				}
			}
		case *PtrType:
			switch elem := a.Elem.(type) {
			case *StructType, *UnionType:
				noteUsagef(uses, c, 10, ctx.Dir, "ptrto-%v", elem.Name())
			case *ArrayType:
				noteUsagef(uses, c, 10, ctx.Dir, "ptrto-%v", elem.Elem.Name())
			}
		case *BufferType:
			switch a.Kind {
			case BufferBlobRand, BufferBlobRange, BufferText, BufferCompressed:
			case BufferString, BufferGlob:
				if a.SubKind != "" {
					noteUsagef(uses, c, 2, ctx.Dir, "str-%v", a.SubKind)
				}
			case BufferFilename:
				noteUsage(uses, c, 10, DirIn, "filename")
			default:
				panic("unknown buffer kind")
			}
		case *VmaType:
			noteUsage(uses, c, 5, ctx.Dir, "vma")
		case *IntType:
			switch a.Kind {
			case IntPlain, IntRange:
			default:
				panic("unknown int kind")
			}
		}
	})
	return uses
}

type weights struct {
	call  int
	in    int32
	inout int32
}

func noteUsage(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, id string) {
	if uses[id] == nil {
		uses[id] = make(map[int]weights)
	}
	callWeight := uses[id][c.ID]
	callWeight.call = c.ID
	if dir != DirOut {
		callWeight.in = max(callWeight.in, weight)
	}
	callWeight.inout = max(callWeight.inout, weight)
	uses[id][c.ID] = callWeight
}

func noteUsagef(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string, args ...any) {
	noteUsage(uses, c, weight, dir, fmt.Sprintf(str, args...))
}

func (target *Target) calcDynamicPrio(corpus []*Prog, enabled map[*Syscall]bool) [][]int32 {
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, p := range corpus {
		for idx0, c0 := range p.Calls {
			if !enabled[c0.Meta] {
				continue
			}
			for _, c1 := range p.Calls[idx0+1:] {
				if !enabled[c1.Meta] {
					continue
				}
				prios[c0.Meta.ID][c1.Meta.ID]++
			}
		}
	}
	for i := range prios {
		for j, val := range prios[i] {
			// It's more important that some calls do coexist than whether
			// it happened 50 or 100 times.
			// Let's use sqrt() to lessen the effect of large counts.
			prios[i][j] = int32(2.0 * math.Sqrt(float64(val)))
		}
	}
	normalizePrios(prios, len(enabled))
	return prios
}

// normalizePrio distributes |N| * 10 points proportional to the values in the matrix.
// |N| is the number of the generatable syscalls.
func normalizePrios(prios [][]int32, n int) {
	total := 10 * int32(n)
	for _, prio := range prios {
		sum := int32(0)
		for _, p := range prio {
			sum += p
		}
		if sum == 0 {
			continue
		}
		for i, p := range prio {
			prio[i] = p * total / sum
		}
	}
}

const (
	// Number of candidate calls sampled from dynamicCalls[bias] to score against program context.
	dynamicContextCandidates = 4
)

type prioItem struct {
	id     int32
	cumSum int32
}

// ChoiceTable allows making a weighted choice of a syscall for a given syscall
// or program prefix based on static resource/type priorities and dynamic corpus colocation.
type ChoiceTable struct {
	target      *Target
	calls       []*Syscall
	generatable []bool

	// Bipartite static priority table:
	// callTags[callID] stores the usage tags for callID and their cumulative weights.
	// tagCalls[tagID] stores the consumer calls for tagID and their cumulative weights.
	callTags [][]prioItem
	tagCalls [][]prioItem

	// Sparse dynamic priority table:
	// dynamicCalls[callID] stores the syscalls that appear after callID in the corpus,
	// sorted by id, with cumulative sqrt(count) weights.
	dynamicCalls [][]prioItem
	hasDynamic   bool
}

func (target *Target) BuildChoiceTable(corpus []*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	enabledCalls := target.prepareEnabledSyscalls(corpus, enabled)
	var generatableCalls []*Syscall
	generatable := make([]bool, len(target.Syscalls))
	for c := range enabledCalls {
		generatableCalls = append(generatableCalls, c)
		generatable[c.ID] = true
	}
	slices.SortFunc(generatableCalls, func(a, b *Syscall) int {
		return cmp.Compare(a.ID, b.ID)
	})

	callTags, tagCalls := target.buildStaticPrioTable(enabledCalls)
	dynamicCalls, hasDynamic := target.buildDynamicPrioTable(corpus, generatable)

	return &ChoiceTable{
		target:       target,
		calls:        generatableCalls,
		generatable:  generatable,
		callTags:     callTags,
		tagCalls:     tagCalls,
		dynamicCalls: dynamicCalls,
		hasDynamic:   hasDynamic,
	}
}

func (target *Target) buildStaticPrioTable(enabled map[*Syscall]bool) ([][]prioItem, [][]prioItem) {
	uses := target.calcResourceUsage(enabled)
	tagNames := slices.Sorted(maps.Keys(uses))

	callTags := make([][]prioItem, len(target.Syscalls))
	tagCalls := make([][]prioItem, 0, len(tagNames))

	for _, tag := range tagNames {
		weightMap := uses[tag]
		if len(weightMap) < 2 {
			// A tag used by only a single syscall does not connect it to any other syscall.
			continue
		}
		callWeights := slices.Collect(maps.Values(weightMap))
		slices.SortFunc(callWeights, func(a, b weights) int {
			return cmp.Compare(a.call, b.call)
		})

		tagID := int32(len(tagCalls))
		consumers := make([]prioItem, len(callWeights))
		var tagSum int32
		for i, w := range callWeights {
			// Higher priority when c1 uses the resource as an input.
			tagSum += w.in*3 + w.inout*2
			consumers[i] = prioItem{id: int32(w.call), cumSum: tagSum}
		}
		tagCalls = append(tagCalls, consumers)

		// Weight the tag by w0.inout * sqrt(tagSum) so tags with more consumers get
		// higher weight without allowing huge generic tags (like fd) to completely
		// drown out specific resource subkinds (like sock_in).
		tagScale := max(int32(1), int32(math.Sqrt(float64(tagSum))))
		for _, w := range callWeights {
			prevSum := int32(0)
			if n := len(callTags[w.call]); n > 0 {
				prevSum = callTags[w.call][n-1].cumSum
			}
			callTags[w.call] = append(callTags[w.call], prioItem{
				id:     tagID,
				cumSum: prevSum + w.inout*tagScale,
			})
		}
	}
	return callTags, tagCalls
}

func (target *Target) buildDynamicPrioTable(corpus []*Prog, generatable []bool) ([][]prioItem, bool) {
	if len(corpus) == 0 {
		return nil, false
	}
	pairCounts := make([]map[int]int32, len(target.Syscalls))
	for _, p := range corpus {
		for idx0, c0 := range p.Calls {
			id0 := c0.Meta.ID
			if !generatable[id0] {
				continue
			}
			m := pairCounts[id0]
			for _, c1 := range p.Calls[idx0+1:] {
				id1 := c1.Meta.ID
				if !generatable[id1] {
					continue
				}
				if m == nil {
					m = make(map[int]int32)
					pairCounts[id0] = m
				}
				m[id1]++
			}
		}
	}

	dynamicCalls := make([][]prioItem, len(target.Syscalls))
	hasDynamic := false
	for id0, m := range pairCounts {
		if len(m) == 0 {
			continue
		}
		hasDynamic = true
		ids := slices.Sorted(maps.Keys(m))
		row := make([]prioItem, len(ids))
		var sum int32
		for i, id1 := range ids {
			// It's more important that some calls do coexist than whether
			// it happened 50 or 100 times.
			// Use sqrt() to lessen the effect of large counts.
			w := max(int32(1), int32(2.0*math.Sqrt(float64(m[id1]))))
			sum += w
			row[i] = prioItem{id: int32(id1), cumSum: sum}
		}
		dynamicCalls[id0] = row
	}
	return dynamicCalls, hasDynamic
}

func (ct *ChoiceTable) Generatable(call int) bool {
	return call >= 0 && ct.generatable[call]
}

func (ct *ChoiceTable) chooseCalls(r *rand.Rand, calls []*Call) int {
	bias := -1
	if len(calls) > 0 {
		// Choosing the base call is based on the insertion point of the new calls sequence.
		if c := calls[r.Intn(len(calls))].Meta; ct.Generatable(c.ID) {
			// We must be careful not to bias towards a non-generatable call.
			bias = c.ID
		}
	}
	return ct.chooseWithContext(r, bias, calls)
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	return ct.chooseWithContext(r, bias, nil)
}

func (ct *ChoiceTable) chooseWithContext(r *rand.Rand, bias int, contextCalls []*Call) int {
	if r.Intn(100) < 5 {
		// Let's make 5% decisions totally at random.
		return ct.calls[r.Intn(len(ct.calls))].ID
	}
	if bias < 0 {
		bias = ct.calls[r.Intn(len(ct.calls))].ID
	}
	if !ct.Generatable(bias) {
		fmt.Printf("bias to disabled or non-generatable syscall %v\n", ct.target.Syscalls[bias].Name)
		panic("disabled or non-generatable syscall")
	}
	res := -1
	if ct.hasDynamic {
		dynBias := bias
		if len(ct.dynamicCalls[dynBias]) == 0 && len(contextCalls) > 0 {
			// If the chosen bias call has no dynamic history in the corpus, try another
			// call from the program prefix that does have corpus history.
			if c := contextCalls[r.Intn(len(contextCalls))].Meta; len(ct.dynamicCalls[c.ID]) > 0 {
				dynBias = c.ID
			}
		}
		// Scale dynamic probability with the number of distinct co-occurring calls (up to 50%)
		// so a syscall that only appeared once in the corpus doesn't hand 50% of all future
		// choices to a single call.
		if dynProb := min(50, 5*len(ct.dynamicCalls[dynBias])); dynProb > 0 && r.Intn(100) < dynProb {
			res = ct.chooseDynamic(r, dynBias, contextCalls)
		}
	}
	if res < 0 {
		res = ct.chooseStatic(r, bias)
	}
	if !ct.Generatable(res) {
		panic("selected disabled or non-generatable syscall")
	}
	return res
}

func (ct *ChoiceTable) chooseStatic(r *rand.Rand, bias int) int {
	tags := ct.callTags[bias]
	if len(tags) == 0 {
		return bias
	}
	for range 4 {
		tagIdx := samplePrioItem(r, tags)
		if res := samplePrioItem(r, ct.tagCalls[tagIdx]); res != bias || r.Intn(4) == 0 {
			return res
		}
	}
	return bias
}

func samplePrioItem(r *rand.Rand, items []prioItem) int {
	total := int(items[len(items)-1].cumSum)
	x := int32(r.Intn(total) + 1)
	idx := sort.Search(len(items), func(i int) bool {
		return items[i].cumSum >= x
	})
	return int(items[idx].id)
}

func hasDynamicPair(row []prioItem, targetCall int32) bool {
	idx := sort.Search(len(row), func(i int) bool {
		return row[i].id >= targetCall
	})
	return idx < len(row) && row[idx].id == targetCall
}

func (ct *ChoiceTable) chooseDynamic(r *rand.Rand, bias int, contextCalls []*Call) int {
	row := ct.dynamicCalls[bias]
	if len(row) == 0 {
		return -1
	}
	if len(contextCalls) <= 1 || len(row) == 1 {
		return samplePrioItem(r, row)
	}

	// Sample a few candidates from bias's dynamic distribution and boost those
	// that also co-occur in the corpus with other calls in contextCalls.
	var cands [dynamicContextCandidates]prioItem
	var sum int32
	for i := range cands {
		candID := int32(samplePrioItem(r, row))
		weight := int32(1)
		for _, c := range contextCalls {
			otherID := c.Meta.ID
			if otherID != bias && hasDynamicPair(ct.dynamicCalls[otherID], candID) {
				weight += 2
			}
		}
		sum += weight
		cands[i] = prioItem{id: candID, cumSum: sum}
	}
	return samplePrioItem(r, cands[:])
}
