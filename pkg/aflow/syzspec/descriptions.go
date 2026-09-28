// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
)

// IsDescriptionFile reports whether name is a description (.txt) or a const (.txt.const) file name.
func IsDescriptionFile(name string) bool {
	return strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".txt.const")
}

// ChangedDescriptions compares the top-level description files in newDir against oldDir.
// It returns the new and modified files with their full contents, and a unified diff of the changes.
func ChangedDescriptions(oldDir, newDir string) (map[string]string, string, error) {
	oldFiles, err := descriptionFiles(oldDir)
	if err != nil {
		return nil, "", err
	}
	newFiles, err := descriptionFiles(newDir)
	if err != nil {
		return nil, "", err
	}
	var removed []string
	for _, file := range oldFiles {
		if !slices.Contains(newFiles, file) {
			removed = append(removed, fmt.Sprintf("description file %v was removed", file))
		}
	}
	if len(removed) != 0 {
		return nil, "", &ValidationError{Problems: limitProblems(removed, "removed files")}
	}
	changed := map[string]string{}
	diff := new(strings.Builder)
	for _, file := range newFiles {
		newData, err := os.ReadFile(filepath.Join(newDir, file))
		if err != nil {
			return nil, "", err
		}
		oldData, err := os.ReadFile(filepath.Join(oldDir, file))
		if errors.Is(err, os.ErrNotExist) {
			changed[file] = string(newData)
			diff.WriteString(newFileDiff(file, string(newData)))
			continue
		} else if err != nil {
			return nil, "", err
		}
		oldText, newText := string(oldData), string(newData)
		if oldText == newText {
			continue
		}
		changed[file] = newText
		edits := myers.ComputeEdits(span.URIFromPath(file), oldText, newText)
		fmt.Fprint(diff, gotextdiff.ToUnified("a/"+file, "b/"+file, oldText, edits))
	}
	return changed, diff.String(), nil
}

// newFileDiff formats a unified diff for a newly created file
// (gotextdiff produces a wrong hunk header for an empty original).
func newFileDiff(file, text string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- /dev/null\n+++ b/%v\n", file)
	if text == "" {
		return sb.String()
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	fmt.Fprintf(&sb, "@@ -0,0 +1,%v @@\n", len(lines))
	for _, line := range lines {
		fmt.Fprintf(&sb, "+%v\n", line)
	}
	return sb.String()
}

// descriptionFiles returns sorted names of the top-level description files in dir.
func descriptionFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, ent := range entries {
		if ent.Type().IsRegular() && IsDescriptionFile(ent.Name()) {
			files = append(files, ent.Name())
		}
	}
	slices.Sort(files)
	return files, nil
}
