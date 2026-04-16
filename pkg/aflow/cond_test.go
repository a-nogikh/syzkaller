// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"
)

// nolint: dupl
func TestIf(t *testing.T) {
	type inputs struct {
		RunIt string
	}
	type outputs struct {
		Done string
	}
	type actionArgs struct {
		RunIt string
	}
	type actionResults struct {
		Done string
	}

	t.Run("True", func(t *testing.T) {
		testFlow[inputs, outputs](t, map[string]any{"RunIt": "yes"}, map[string]any{"Done": "done"},
			&If{
				Condition: "RunIt",
				Do: NewFuncAction("if-body", func(ctx *Context, args actionArgs) (actionResults, error) {
					return actionResults{"done"}, nil
				}),
			},
			nil,
			nil,
		)
	})

	t.Run("False", func(t *testing.T) {
		testFlow[inputs, outputs](t, map[string]any{"RunIt": ""}, map[string]any{"Done": ""},
			&If{
				Condition: "RunIt",
				Do: NewFuncAction("if-body", func(ctx *Context, args actionArgs) (actionResults, error) {
					return actionResults{"done"}, nil
				}),
			},
			nil,
			nil,
		)
	})
}
