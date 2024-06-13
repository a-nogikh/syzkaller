// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReleasesForPatch(t *testing.T) {

	times := []time.Time{}
	base := time.Now()
	for i := 0; i < 10; i++ {
		times = append(times, base.Add(time.Duration(i)*time.Minute))
	}

	releases := []KernelRelease{
		{
			Tag:  "v6.6-rc1",
			Date: times[7],
		},
		{
			Tag:  "v6.5",
			Date: times[5],
		},
		{
			Tag:  "v6.5-rc2",
			Date: times[3],
		},
		{
			Tag:  "v6.5-rc1",
			Date: times[1],
		},
	}

	tests := []struct {
		patch      Patch
		releaseTag string
		rcTag      string
	}{
		{
			patch: Patch{Date: times[0]},
		},
		{
			patch: Patch{Date: times[1]},
			rcTag: "v6.5-rc1",
		},
		{
			patch: Patch{Date: times[4]},
			rcTag: "v6.5-rc2",
		},
		{
			patch:      Patch{Date: times[6]},
			releaseTag: "v6.5",
		},
		{
			patch:      Patch{Date: times[8]},
			releaseTag: "v6.5",
			rcTag:      "v6.6-rc1",
		},
	}

	for i, test := range tests {
		test := test
		t.Run(fmt.Sprint(i), func(tt *testing.T) {
			release, rc := releasesForPatch(releases, test.patch)
			assert.Equal(tt, release != nil, test.releaseTag != "")
			assert.Equal(tt, rc != nil, test.rcTag != "")
			if release != nil {
				assert.Equal(tt, release.Tag, test.releaseTag)
			}
			if rc != nil {
				assert.Equal(tt, rc.Tag, test.rcTag)
			}
		})
	}

}
