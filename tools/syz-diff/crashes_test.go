// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseCrashes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "crashes.json")
	crashes, err := loadBaseCrashes(file)
	require.NoError(t, err)
	assert.False(t, crashes.Has("title 1"))
	require.NoError(t, crashes.Add("title 1"))
	require.NoError(t, crashes.Add("title 2"))
	require.NoError(t, crashes.Add("title 1"))
	assert.True(t, crashes.Has("title 1"))

	loaded, err := loadBaseCrashes(file)
	require.NoError(t, err)
	assert.True(t, loaded.Has("title 1"))
	assert.True(t, loaded.Has("title 2"))
	assert.False(t, loaded.Has("title 3"))
}
