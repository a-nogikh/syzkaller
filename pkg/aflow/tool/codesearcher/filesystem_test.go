// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearcher

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
)

func TestDirIndex(t *testing.T) {
	state := fsState{
		KernelSrc: filepath.FromSlash("../../../codesearch/testdata"),
	}

	aflow.TestTool(t, ToolDirIndex, state, dirIndexArgs{Dir: ""}, dirIndexResult{
		Subdirs: []string{"mm"},
		Files:   []string{"global_vars.c", "refs.c", "source0.c", "source0.h", "source1.c", "source2.c"},
	}, "")

	aflow.TestTool(t, ToolDirIndex, state, dirIndexArgs{Dir: "mm"}, dirIndexResult{
		Subdirs: nil,
		Files:   []string{"refs.c", "slub.c", "slub.h"},
	}, "")

	aflow.TestTool(t, ToolDirIndex, state, dirIndexArgs{Dir: "missing"}, dirIndexResult{},
		"the directory does not exist")
	aflow.TestTool(t, ToolDirIndex, state, dirIndexArgs{Dir: "source0.c"}, dirIndexResult{},
		"the path is not a directory")
	aflow.TestTool(t, ToolDirIndex, state, dirIndexArgs{Dir: "../missing"}, dirIndexResult{},
		"path is outside of the source tree")
}

func TestReadFile(t *testing.T) {
	state := fsState{
		KernelSrc: filepath.FromSlash("../../../codesearch/testdata"),
	}

	// 100 lines max
	aflow.TestTool(t, ToolReadFile, state, readFileArgs{File: "source0.c", FirstLine: 1, LineCount: 1000}, readFileResult{
		Contents: `   1:	// Copyright 2025 syzkaller project authors. All rights reserved.
   2:	// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
   3:	
   4:	#include "source0.h"
   5:	
   6:	struct struct_in_c_file {
   7:		int X;
   8:		struct some_struct by_value;
   9:	};
  10:	
  11:	/*
  12:	 * Comment about open.
  13:	 */
  14:	int open()
  15:	{
  16:		return 0;
  17:	}
  18:	
  19:	int close()
  20:	{
  21:		return 0;
  22:	}
  23:	
  24:	void function_with_comment_in_header()
  25:	{
  26:		same_name_in_several_files();
  27:	}
  28:	
  29:	int func_accepting_a_struct(struct some_struct* p)
  30:	{
  31:		return ((some_struct_t*)p)->x +
  32:		       ((union some_union*)p)->x;
  33:	}
  34:	
  35:	void function_with_quotes_in_type(void __attribute__((btf_type_tag("user"))) *)
  36:	{
  37:	}
  38:	
  39:	int field_refs(struct some_struct* p, union some_union* u)
  40:	{
  41:		p->x = p->y;
  42:		*(&p->x) = 1;
  43:		u->p = 0;
  44:		u->s.x = 2;
  45:		return p->x;
  46:	}
  47:	
  48:	void reference_to_header_static()
  49:	{
  50:		func_in_header();
  51:	}
  52:	
  53:	// compile_commands.json we create for tests defines KBUILD_BASENAME.
  54:	// If it's not defined, compile_commands.json is not properly loaded.
  55:	// This is supposed to fail builds, if that happens.
  56:	#ifndef KBUILD_BASENAME
  57:	#error "compile_commands.json is not loaded"
  58:	#endif
`,
	}, "")

	aflow.TestTool(t, ToolReadFile, state, readFileArgs{File: "source0.c", FirstLine: 12, LineCount: 2}, readFileResult{
		Contents: `  12:	 * Comment about open.
  13:	 */
`,
	}, "")

	aflow.TestTool(t, ToolReadFile, state, readFileArgs{File: "missing"}, readFileResult{},
		"the file does not exist")
	aflow.TestTool(t, ToolReadFile, state, readFileArgs{File: "mm"}, readFileResult{},
		"the file is a directory")
	aflow.TestTool(t, ToolReadFile, state, readFileArgs{File: "../missing"}, readFileResult{},
		"path is outside of the source tree")
	aflow.TestTool(t, ToolReadFile, state,
		readFileArgs{File: "source0.c", FirstLine: 100, LineCount: 10},
		readFileResult{},
		"file source0.c does not have line 100, it has only 58 lines")
}
