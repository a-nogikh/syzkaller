// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/assert"
)

func TestCreateSeries(t *testing.T) {
	first := time.Now()
	second, third, fourth := first.Add(time.Minute),
		first.Add(2*time.Minute), first.Add(3*time.Minute)

	series, patches := createSeries(&lore.Thread{
		Messages: []*email.Email{
			{
				MessageID: "id1",
				Subject:   "[PATCH v2 0/2] cover letter",
				Date:      first,
			},
			{
				MessageID: "id2",
				Subject:   "[PATCH v2 1/2] first commit",
				Date:      second,
				Patch:     "A",
			},
			{
				MessageID: "id3",
				Subject:   "[PATCH v2 2/2] second commit",
				Date:      third,
				Patch:     "B",
				Fixes: []vcs.Commit{
					{
						Hash:  "abcd",
						Title: "bad commit",
					},
				},
			},
			{
				MessageID: "id4",
				Subject:   "Re: [PATCH v2 2/2] some discussion",
				Date:      fourth,
				Patch:     "C",
			},
		},
	})
	assert.Equal(t, Series{
		Patches: []Patch{
			{
				ID:    "id2",
				Title: "first commit",
				Date:  second,
			},
			{
				ID:    "id3",
				Title: "second commit",
				Date:  third,
				Fixes: []vcs.Commit{
					{
						Hash:  "abcd",
						Title: "bad commit",
					},
				},
			},
		},
	}, series)
	assert.Equal(t, []patchInfo{
		{
			id:    "id2",
			patch: "A",
		},
		{
			id:    "id3",
			patch: "B",
		},
	}, patches)
}
