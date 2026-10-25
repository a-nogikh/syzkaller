// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildCacheDesc(t *testing.T) {
	const (
		commit  = "1111111111111111111111111111111111111111"
		cfgName = "upstream-apparmor-kasan.config"
		cc      = "clang version 20"
	)
	cfg := []byte("CONFIG_KASAN=y\n")
	patch := []byte("diff")
	desc := buildCacheDesc(commit, patch, cfgName, cfg, cc)
	assert.Equal(t, desc, buildCacheDesc(commit, patch, cfgName, cfg, cc))
	for name, other := range map[string]string{
		"commit":   buildCacheDesc("2222222222222222222222222222222222222222", patch, cfgName, cfg, cc),
		"patch":    buildCacheDesc(commit, []byte("diff2"), cfgName, cfg, cc),
		"no patch": buildCacheDesc(commit, nil, cfgName, cfg, cc),
		"config":   buildCacheDesc(commit, patch, cfgName, []byte("CONFIG_KASAN=n\n"), cc),
		"name":     buildCacheDesc(commit, patch, "upstream-kmsan.config", cfg, cc),
		"compiler": buildCacheDesc(commit, patch, cfgName, cfg, "clang version 21"),
	} {
		assert.NotEqual(t, desc, other, name)
	}
}

func TestCorpusCacheDesc(t *testing.T) {
	const url = "https://storage.googleapis.com/syzkaller/corpus/ci-upstream-kasan-gce-root-corpus.db"
	monday := time.Date(2026, time.October, 19, 0, 0, 0, 0, time.UTC)
	sunday := time.Date(2026, time.October, 25, 23, 0, 0, 0, time.UTC)
	nextMonday := time.Date(2026, time.October, 26, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, corpusCacheDesc(url, monday), corpusCacheDesc(url, sunday))
	assert.NotEqual(t, corpusCacheDesc(url, sunday), corpusCacheDesc(url, nextMonday))
	assert.NotEqual(t, corpusCacheDesc(url, monday), corpusCacheDesc(url+".other", monday))
}
