// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
)

func TestPathCoverQueryPath(t *testing.T) {
	dir := t.TempDir()
	// Create some dir hierarchy.
	err := setupDirLayout(dir, []string{
		"/a/b/c.c",
		"/a/b/d.c",
		"/a/d/y.out",
		"/b/",
		"/c.h",
	})
	if err != nil {
		t.Fatal(err)
	}

	subsystemA, subsystemB, subsystemC := "A", "B", "C"
	matcher := func(path string) []interface{} {
		m := map[string][]interface{}{
			"a/b/c.c": {subsystemA},
			"c.h":     {subsystemB},
		}
		if ret, ok := m[path]; ok {
			return ret
		}
		return []interface{}{subsystemC}
	}

	// Construct the cover object.
	cover, err := BuildPathCover(dir, matcher, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Test queries.
	assert.ElementsMatch(t, cover.queryPath("a/b/c.c"), []interface{}{subsystemA})
	assert.ElementsMatch(t, cover.queryPath("a/b/d.c"), []interface{}{subsystemC})
	assert.ElementsMatch(t, cover.queryPath("a/d/y.out"), []interface{}{})
	assert.ElementsMatch(t, cover.queryPath("c.h"), []interface{}{subsystemB})
}
func setupDirLayout(base string, paths []string) error {
	for _, path := range paths {
		path = filepath.Join(base, filepath.FromSlash(path))
		dir := filepath.Dir(path)
		// Create the directory.
		err := osutil.MkdirAll(dir)
		if err != nil {
			return err
		}
		if path != "" && path[len(path)-1] != filepath.Separator {
			err = osutil.WriteFile(path, nil)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
