// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateConditionalFields(t *testing.T) {
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	r := newRand(target, rs)

	combinations := map[bool]map[bool]bool{
		false: {false: false, true: false},
		true:  {false: false, true: false},
	}
	for i := 0; i < 150; i++ {
		p := genConditionalFieldProg(target, ct, r)
		f1, f2 := validateConditionalProgCall(t, p.Calls[len(p.Calls)-1])
		combinations[f1 != nil][f2 != nil] = true
	}
	for _, first := range []bool{false, true} {
		for _, second := range []bool{false, true} {
			if !combinations[first][second] {
				t.Fatalf("Did not generate a combination f1=%v f2=%v", first, second)
			}
		}
	}
}

func TestMutateConditionalFields(t *testing.T) {
	target, rs, it := initRandomTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	r := newRand(target, rs)

	nonAny := 0
	for i := 0; i < it; i++ {
		prog := genConditionalFieldProg(target, ct, r)
		for j := 0; j < 5; j++ {
			prog.Mutate(rs, 10, ct, nil, nil)
			hasAny := bytes.Contains(prog.Serialize(), []byte("ANY="))
			if hasAny {
				// No sense to verify these.
				continue
			}
			nonAny++
			validateConditionalProg(t, prog)
		}
	}
	assert.Greater(t, nonAny, it) // Just in case.
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
			validateConditionalProgCall(t, call)
		}
	}
}

// Validates a test$conditional_struct call.
func validateConditionalProgCall(t *testing.T, c *Call) (Arg, Arg) {
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
	ga, ok := va.Res.(*GroupArg)
	if !ok {
		t.Fatalf("expected GroupArg: %v", va.Res)
	}
	if len(ga.Inner) != 3 {
		t.Fatalf("generated wrong number of struct args %v", len(ga.Inner))
	}
	mask := ga.Inner[0].(*ConstArg).Val
	if mask&FLAG1 != 0 {
		assert.NotNil(t, ga.Inner[1], "flag1 is set in mask %x", mask)
	} else {
		assert.Nil(t, ga.Inner[1], "flag1 is not set in maks %x", mask)
	}
	if mask&FLAG2 != 0 {
		assert.NotNil(t, ga.Inner[2], "flag2 is set in mask %x", mask)
	} else {
		assert.Nil(t, ga.Inner[2], "flag2 is not set in maks %x", mask)
	}
	return ga.Inner[1], ga.Inner[2]
}
