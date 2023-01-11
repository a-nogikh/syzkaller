// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
)

func TestPathCoverQuerySubtree(t *testing.T) {
	dir := t.TempDir()
	// Create some dir hierarchy.
	err := setupDirLayout(dir, []string{
		"/a/b/c",
		"/a/d/",
		"/b/",
		"/c",
	})
	if err != nil {
		t.Fatal(err)
	}

	subsystemA, subsystemB, subsystemC := "A", "B", "C"
	matcher := func(path string) []interface{} {
		m := map[string][]interface{}{
			"a/b/c": {subsystemA},
			"a/d":   {subsystemB},
			"c":     {subsystemC},
		}
		return m[path]
	}

	// Construct the cover object.
	cover, err := BuildPathCover(dir, matcher)
	if err != nil {
		t.Fatal(err)
	}

	// Test queries.
	matchMapKeys(t, cover.QuerySubtree("a/b"), []interface{}{subsystemA})
	matchMapKeys(t, cover.QuerySubtree("a/"), []interface{}{subsystemA, subsystemB})
	matchMapKeys(t, cover.QuerySubtree("b"), []interface{}{})
	matchMapKeys(t, cover.QuerySubtree("c"), []interface{}{subsystemC})
	matchMapKeys(t, cover.QuerySubtree(""), []interface{}{subsystemA, subsystemB, subsystemC})
}

func matchMapKeys(t *testing.T, m map[interface{}]struct{}, expected []interface{}) {
	keys := []interface{}{}
	for key := range m {
		keys = append(keys, key)
	}
	assert.ElementsMatch(t, keys, expected)
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
