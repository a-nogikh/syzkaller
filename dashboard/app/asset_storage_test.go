// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import "testing"

func TestCoverageReportAsset(t *testing.T) {
	// Upload a build.
	// Query loadManagers(). Ensure CoverLink is empty.
	// Upload an asset.
	// Query loadManagers(). Ensure CoverLink is correct.
	// Upload an asset.
	// Query loadManagers(). Ensure CoverLink is new.
	// Forget the latest asset.
	// Query loadManagers(). Check CoverLink.
}

func TestDiskImageAsset(t *testing.T) {
	// Upload a crash. Let syzkaller report that.
	// Upload an asset. And then upload a crash with a repro.
	// Ensure there are links in the email.
	// TODO: or, maybe, just add a few lines to the corresponding test?
}

func TestBugStatusAssetDeprecation(t *testing.T) {
	// Query several times to make sure the deprecated assets array is stable?
}

func TestPeriodicalAssetDeprecation(t *testing.T) {

}

func TestBuildTimeAssetDeprecation(t *testing.T) {

}
