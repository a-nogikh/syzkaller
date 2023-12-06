// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import "fmt"

func (bo *BinaryOperation) Evaluate(target *Target, args []Arg, fields []Field, overlayField int) uint64 {
	left := bo.Left.Evaluate(target, args, fields, overlayField)
	right := bo.Right.Evaluate(target, args, fields, overlayField)
	switch bo.Operator {
	case OperatorCompareEq:
		if left == right {
			return 1
		}
		return 0
	case OperatorCompareNeq:
		if left != right {
			return 1
		}
		return 0
	case OperatorBinaryAnd:
		return left & right
	}
	panic(fmt.Sprintf("unknown operator %q", bo.Operator))
}

func (v *Value) Evaluate(target *Target, args []Arg, fields []Field, overlayField int) uint64 {
	if len(v.Path) == 0 {
		return v.Value
	}
	found := target.findArg(nil, v.Path, args, fields, map[Arg]Arg{}, overlayField)
	if found == nil {
		// This is most likely due to ANY squashing.
		// TODO: figure out how to best handle it.
		return 0
	}
	if found.arg == nil {
		panic("got nil field during expression evaluation")
	}
	a, ok := found.arg.(*ConstArg)
	if !ok {
		panic("value expressions must only rely on int fields")
	}
	return a.Val
}
