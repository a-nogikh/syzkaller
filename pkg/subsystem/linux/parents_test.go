// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"testing"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/subsystem/match"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestLoopsDoExist(t *testing.T) {
	a := &entity.Subsystem{}
	b := &entity.Subsystem{Parents: []*entity.Subsystem{a}}
	c := &entity.Subsystem{Parents: []*entity.Subsystem{b}}
	a.Parents = []*entity.Subsystem{c}
	assert.True(t, loopsExist([]*entity.Subsystem{a, b, c}))
}

func TestLoopsDoNotExist(t *testing.T) {
	a := &entity.Subsystem{}
	b := &entity.Subsystem{Parents: []*entity.Subsystem{a}}
	c := &entity.Subsystem{Parents: []*entity.Subsystem{b}}
	assert.False(t, loopsExist([]*entity.Subsystem{a, b, c}))
}

func TestTransitiveReduction(t *testing.T) {
	// (d, c), (c, b), (b, a)
	// (d, a)
	// (d, b)
	// (d, e)
	// (c, a)
	a := &entity.Subsystem{}
	b := &entity.Subsystem{Parents: []*entity.Subsystem{a}}
	c := &entity.Subsystem{Parents: []*entity.Subsystem{a, b}}
	e := &entity.Subsystem{}
	d := &entity.Subsystem{Parents: []*entity.Subsystem{a, b, c, e}}
	transitiveReduction([]*entity.Subsystem{a, b, c, d, e})

	// The result should be:
	// (d, c), (c, b), (b, a)
	// (d, e)
	assert.ElementsMatch(t, d.Parents, []*entity.Subsystem{c, e})
	assert.ElementsMatch(t, c.Parents, []*entity.Subsystem{b})
}

func TestSetParents(t *testing.T) {
	kernel := &entity.Subsystem{}
	net := &entity.Subsystem{}
	wireless := &entity.Subsystem{}
	drivers := &entity.Subsystem{}

	tree := map[string][]interface{}{
		"include/net/cfg80211.h":   {wireless},
		"net/socket.c":             {net},
		"net/nfc/core.c":           {net},
		"net/wireless/nl80211.c":   {net, wireless},
		"net/wireless/sysfs.c":     {net, wireless},
		"net/ipv4/arp.c":           {net},
		"drivers/usb/host/xhci.c":  {drivers},
		"drivers/android/binder.c": {drivers},
	}
	matcher := func(path string) []interface{} {
		return append(append([]interface{}{}, tree[path]...), kernel)
	}

	// Construct the cover object.
	repo := fsTreeFromKeys(t, tree)
	cover, err := match.BuildPathCover(repo, matcher, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Calculate parents.
	err = SetParents(cover, []*entity.Subsystem{kernel, net, wireless, drivers})
	if err != nil {
		t.Fatal(err)
	}

	// Verify parents.
	assert.ElementsMatch(t, net.Parents, []*entity.Subsystem{kernel})
	assert.ElementsMatch(t, wireless.Parents, []*entity.Subsystem{net})
	assert.ElementsMatch(t, drivers.Parents, []*entity.Subsystem{kernel})
	assert.ElementsMatch(t, kernel.Parents, []*entity.Subsystem{})
}

func fsTreeFromKeys(t *testing.T, tree map[string][]interface{}) string {
	keys := []string{}
	for key := range tree {
		keys = append(keys, key)
	}
	repo := t.TempDir()
	testutil.DirectoryLayout(t, repo, keys)
	return repo
}
