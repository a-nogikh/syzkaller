// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateConditionalFields(t *testing.T) {
	// Ensure that we reach different combinations of conditional fields.
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	r := newRand(target, rs)

	combinations := [][]bool{
		{false, false},
		{false, false},
	}
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	for i := 0; i < 150; i++ {
		p := genConditionalFieldProg(target, ct, r)
		f1, f2 := parseConditionalStructCall(t, p.Calls[len(p.Calls)-1])
		combinations[b2i(f1)][b2i(f2)] = true
	}
	for _, first := range []int{0, 1} {
		for _, second := range []int{0, 1} {
			if !combinations[first][second] {
				t.Fatalf("Did not generate a combination f1=%v f2=%v", first, second)
			}
		}
	}
}

func TestMutateConditionalFields(t *testing.T) {
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	r := newRand(target, rs)
	iters := 500
	if testing.Short() {
		iters /= 10
	}
	nonAny := 0
	for i := 0; i < iters; i++ {
		prog := genConditionalFieldProg(target, ct, r)
		for j := 0; j < 5; j++ {
			prog.Mutate(rs, 10, ct, nil, nil)
			hasAny := bytes.Contains(prog.Serialize(), []byte("ANY="))
			if hasAny {
				// No sense to verify these.
				break
			}
			nonAny++
			validateConditionalProg(t, prog)
		}
	}
	assert.Greater(t, nonAny, 10) // Just in case.
}

func TestEvaluateConditionalFields(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	tests := []struct {
		good []string
		bad  []string
	}{
		{
			good: []string{
				`test$conditional_struct(&AUTO={0x0, @void, @void})`,
				`test$conditional_struct(&AUTO={0x4, @void, @value=0x123})`,
			},
			bad: []string{
				`test$conditional_struct(&AUTO={0x0, @void, @value=0x123})`,
				`test$conditional_struct(&AUTO={0x0, @value={AUTO}, @value=0x123})`,
			},
		},
		{
			good: []string{
				`test$parent_conditions(&AUTO={0x0, @without_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x2, @with_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x4, @without_flag1=0x123, {0x0, @value=0x0}})`,
				`test$parent_conditions(&AUTO={0x6, @with_flag1=0x123, {0x0, @value=0x0}})`,
			},
			bad: []string{
				`test$parent_conditions(&AUTO={0x0, @with_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x2, @without_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x4, @with_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x4, @with_flag1=0x123, {0x0, @value=0x0}})`,
			},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(tt *testing.T) {
			for _, good := range test.good {
				_, err := target.Deserialize([]byte(good), Strict)
				assert.NoError(tt, err)
			}
			for _, bad := range test.bad {
				_, err := target.Deserialize([]byte(bad), Strict)
				assert.ErrorIs(tt, err, ErrViolatedConditions)
			}
		})
	}
}

func genConditionalFieldProg(target *Target, ct *ChoiceTable, r *randGen) *Prog {
	s := newState(target, ct, nil)
	calls := r.generateParticularCall(s, target.SyscallMap["test$conditional_struct"])
	return &Prog{
		Target: target,
		Calls:  calls,
	}
}

const FLAG1 = 2
const FLAG2 = 4

func validateConditionalProg(t *testing.T, p *Prog) {
	for _, call := range p.Calls {
		if call.Meta.Name == "test$conditional_struct" {
			parseConditionalStructCall(t, call)
		}
	}
}

// Validates a test$conditional_struct call.
func parseConditionalStructCall(t *testing.T, c *Call) (bool, bool) {
	if c.Meta.Name != "test$conditional_struct" {
		t.Fatalf("generated wrong call %v", c.Meta.Name)
	}
	if len(c.Args) != 1 {
		t.Fatalf("generated wrong number of args %v", len(c.Args))
	}
	va, ok := c.Args[0].(*PointerArg)
	if !ok {
		t.Fatalf("expected PointerArg: %v", c.Args[0])
	}
	if va.Res == nil {
		// Cannot validate.
		return false, false
	}
	ga, ok := va.Res.(*GroupArg)
	if !ok {
		t.Fatalf("expected GroupArg: %v", va.Res)
	}
	if len(ga.Inner) != 3 {
		t.Fatalf("wrong number of struct args %v", len(ga.Inner))
	}
	mask := ga.Inner[0].(*ConstArg).Val
	f1 := ga.Inner[1].(*UnionArg).Index == 0
	f2 := ga.Inner[2].(*UnionArg).Index == 0
	assert.Equal(t, mask&FLAG1 != 0, f1, "flag1 must only be set if mask&FLAG1")
	assert.Equal(t, mask&FLAG2 != 0, f2, "flag2 must only be set if mask&FLAG2")
	return f1, f2
}
