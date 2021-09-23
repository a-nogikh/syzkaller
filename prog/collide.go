// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Contains prog transformations that intend to trigger more races.

package prog

import "math/rand"

// TODO: add tests once the contents is more or less finalized.

// Ensures that, if a detached call produces a resource, then
// it is [distanced] from a call consuming the resource at least
// by one non-detached call.
// This does not give 100% guarantee that the detached call finishes
// by that time, but hopefully this is enough for most cases.
func AssignRandomDetached(origProg *Prog, rand *rand.Rand) *Prog {
	prog := origProg.Clone()
	unassigned := make(map[*ResultArg]bool)
	for idx, call := range prog.Calls {
		undoPrev := false
		produces := make(map[*ResultArg]bool)
		ForeachArg(call, func(arg Arg, ctx *ArgCtx) {
			res, ok := arg.(*ResultArg)
			if !ok {
				return
			}

			if res.Dir() != DirOut && res.Res != nil && unassigned[res.Res] {
				// This call uses a resource that is not yet available.
				undoPrev = true
				return
			}

			if res.Dir() != DirIn {
				// If we make this call detached, these resources won't be immediately available.
				produces[res] = true
			}
		})

		if undoPrev {
			prog.Calls[idx-1].Props.Detached = false
			unassigned = make(map[*ResultArg]bool)
		}
		// Assign detached with 50% probability.

		call.Props.Detached = rand.Intn(2) == 0
		if call.Props.Detached {
			for res := range produces {
				unassigned[res] = true
			}
		} else {
			unassigned = make(map[*ResultArg]bool)
		}
	}

	// An extra pass - limiting the total number of detached calls.
	const maxDetachedCnt = 6
	detachedCnt := 0
	for _, call := range prog.Calls {
		if call.Props.Detached {
			detachedCnt++
		}
		if detachedCnt > maxDetachedCnt {
			call.Props.Detached = false
		}
	}
	return prog
}
