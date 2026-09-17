// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type MissingConst struct {
	Name     string
	File     string
	Includes []string
	Incdirs  []string
	Defines  map[string]string
}

type TargetResult struct {
	Target        *prog.Target
	MissingConsts []MissingConst
}

// CompileTarget parses .txt and .const files in dir for the base target's OS and architecture.
// If any constants required by the descriptions are missing from .const files,
// TargetResult.MissingConsts is populated and Target is nil.
// Otherwise, it compiles the descriptions and returns a new *prog.Target inheriting base.Revision.
func CompileTarget(dir string, base *prog.Target) (*TargetResult, error) {
	sysTarget := targets.Get(base.OS, base.Arch)
	if sysTarget == nil {
		return nil, fmt.Errorf("unknown target %v/%v", base.OS, base.Arch)
	}

	var errors []string
	eh := func(pos ast.Pos, msg string) {
		errors = append(errors, fmt.Sprintf("%v: %v", pos, msg))
	}

	descriptions := ast.ParseGlob(filepath.Join(dir, "*.txt"), eh)
	if descriptions == nil || len(errors) > 0 {
		return nil, fmt.Errorf("parsing descriptions failed:\n%s", strings.Join(errors, "\n"))
	}

	constInfo := ExtractConsts(descriptions, sysTarget, eh)
	if constInfo == nil || len(errors) > 0 {
		return nil, fmt.Errorf("extracting consts failed:\n%s", strings.Join(errors, "\n"))
	}

	constGlob := filepath.Join(dir, "*.const")
	var constFile *ConstFile
	if matches, _ := filepath.Glob(constGlob); len(matches) == 0 {
		constFile = NewConstFile()
	} else {
		constFile = DeserializeConstFile(constGlob, eh)
		if constFile == nil || len(errors) > 0 {
			return nil, fmt.Errorf("loading const files failed:\n%s", strings.Join(errors, "\n"))
		}
	}
	if base.OS == targets.TestOS {
		FabricateSyscallConsts(sysTarget, constInfo, constFile)
	}

	var missing []MissingConst
	for file, info := range constInfo {
		for _, def := range info.Consts {
			if constFile.ExistsAny(def.Name) {
				continue
			}
			missing = append(missing, MissingConst{
				Name:     def.Name,
				File:     filepath.Base(file),
				Includes: info.Includes,
				Incdirs:  info.Incdirs,
				Defines:  info.Defines,
			})
		}
	}
	if len(missing) > 0 {
		slices.SortFunc(missing, func(a, b MissingConst) int {
			if a.Name != b.Name {
				return cmp.Compare(a.Name, b.Name)
			}
			return cmp.Compare(a.File, b.File)
		})
		return &TargetResult{MissingConsts: missing}, nil
	}

	consts := constFile.Arch(base.Arch)
	prg := Compile(descriptions, consts, sysTarget, eh)
	if prg == nil {
		return nil, fmt.Errorf("compiling descriptions failed:\n%s", strings.Join(errors, "\n"))
	}

	return &TargetResult{Target: prog.NewTarget(base, prg.TargetDesc(consts))}, nil
}
