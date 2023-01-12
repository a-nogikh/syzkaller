// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestPathCoverQuerySubtree(t *testing.T) {
	dir := t.TempDir()
	// Create some dir hierarchy.
	testutil.DirectoryLayout(t, dir, []string{
		"/a/b/c",
		"/a/d/",
		"/b/",
		"/c",
	})

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
