// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultFuzzTargets(t *testing.T) {
	targets := DefaultFuzzTargets()
	require.NotEmpty(t, targets)
	require.NoError(t, ValidateFuzzTargets(targets))

	hasFallback := false
	for _, target := range targets {
		if len(target.EmailLists) == 0 && len(target.PathRegexps) == 0 {
			hasFallback = true
		}
		assert.NotEmpty(t, target.Campaigns)
		for _, campaign := range target.Campaigns {
			// We are in syz-cluster/pkg/api.
			config := filepath.Join("..", "..", "..", "dashboard", "config", "linux", campaign.KernelConfig)
			assert.True(t, osutil.IsExist(config), "kernel config %q does not exist", campaign.KernelConfig)
		}
	}
	assert.True(t, hasFallback, "there must be a fallback target without email lists and path regexps")
}

func TestDefaultFuzzTargetsCopy(t *testing.T) {
	first := DefaultFuzzTargets()
	first[0].Focus = "modified"
	second := DefaultFuzzTargets()
	assert.NotEqual(t, "modified", second[0].Focus)
}

func TestValidateFuzzTargets(t *testing.T) {
	assert.ErrorContains(t, ValidateFuzzTargets([]*FuzzTriageTarget{
		{PathRegexps: []string{"[invalid("}},
	}), "invalid path regexp")
	assert.ErrorContains(t, ValidateFuzzTargets([]*FuzzTriageTarget{
		{ExcludePathRegexps: []string{"[invalid("}},
	}), "invalid path regexp")
	assert.ErrorContains(t, ValidateFuzzTargets([]*FuzzTriageTarget{
		{Campaigns: []*KernelFuzzConfig{{Track: "UBSAN"}}},
	}), "unsupported fuzzing track")
	assert.NoError(t, ValidateFuzzTargets([]*FuzzTriageTarget{
		{
			PathRegexps: []string{"^net/"},
			Campaigns:   []*KernelFuzzConfig{{Track: string(TrackKASAN)}, {Track: string(TrackKMSAN)}},
		},
	}))
}
