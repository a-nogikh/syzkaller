// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	_ "embed"
	"fmt"
	"regexp"
	"slices"

	"gopkg.in/yaml.v3"
)

//go:embed fuzz_targets.yaml
var defaultFuzzTargetsYAML []byte

// DefaultFuzzTargets returns the default rules that map patch series to fuzzing configurations.
// Every call returns a new copy, so the caller may modify the result.
func DefaultFuzzTargets() []*FuzzTriageTarget {
	targets, err := parseFuzzTargets(defaultFuzzTargetsYAML)
	if err != nil {
		// The file is embedded and is checked by tests, so it must never happen.
		panic(fmt.Sprintf("invalid fuzz_targets.yaml: %v", err))
	}
	return targets
}

func parseFuzzTargets(data []byte) ([]*FuzzTriageTarget, error) {
	var targets []*FuzzTriageTarget
	if err := yaml.Unmarshal(data, &targets); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no fuzz targets")
	}
	return targets, nil
}

// ValidateFuzzTargets checks that the path regexps compile and that the fuzzing tracks are supported.
func ValidateFuzzTargets(targets []*FuzzTriageTarget) error {
	for _, target := range targets {
		for _, r := range slices.Concat(target.PathRegexps, target.ExcludePathRegexps) {
			if _, err := regexp.Compile(r); err != nil {
				return fmt.Errorf("invalid path regexp %q: %w", r, err)
			}
		}
		for _, campaign := range target.Campaigns {
			if campaign.Track != string(TrackKASAN) && campaign.Track != string(TrackKMSAN) {
				return fmt.Errorf("unsupported fuzzing track %q, must be %q or %q",
					campaign.Track, TrackKASAN, TrackKMSAN)
			}
		}
	}
	return nil
}
