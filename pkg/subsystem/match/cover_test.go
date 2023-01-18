// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"regexp"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestPathCoverQueryPath(t *testing.T) {
	dir := t.TempDir()
	// Create some dir hierarchy.

	testutil.DirectoryLayout(t, dir, []string{
		"/a/b/c.c",
		"/a/b/d.c",
		"/a/d/y.out",
		"/b/",
		"/c.h",
	})

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

func TestPathCoverCoincidence(t *testing.T) {
	dir := t.TempDir()
	// Create some dir hierarchy.
	testutil.DirectoryLayout(t, dir, []string{
		"a.c",
		"ab.c",
		"b.c",
	})

	subsystemA, subsystemB := "A", "B"
	matcher := func(path string) []interface{} {
		m := map[string][]interface{}{
			"a.c":  {subsystemA},
			"ab.c": {subsystemA, subsystemB},
			"b.c":  {subsystemB},
		}
		return m[path]
	}

	// Construct the cover object.
	cover, err := BuildPathCover(dir, matcher, nil)
	if err != nil {
		t.Fatal(err)
	}

	cm := cover.CoincidenceMatrix()
	assert.Equal(t, 2, cm.Count(subsystemA))
	assert.Equal(t, 2, cm.Count(subsystemB))
	assert.Equal(t, 1, cm.Get(subsystemA, subsystemB))

	// Test exclude regexps.
	cover, err = BuildPathCover(dir, matcher, regexp.MustCompile(`^ab\.c$`))
	if err != nil {
		t.Fatal(err)
	}

	cm = cover.CoincidenceMatrix()
	assert.Equal(t, 1, cm.Count(subsystemA))
	assert.Equal(t, 1, cm.Count(subsystemB))
	assert.Equal(t, 0, cm.Get(subsystemA, subsystemB))
}
