// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestLinuxSubsystemRules(t *testing.T) {
	ctx := &linuxCtx{
		repo:       prepareTestLinuxRepo(t, nil),
		rawRecords: prepareTestMaintainers(t),
	}
	err := ctx.applyCustomRules(testRules)
	if err != nil {
		t.Fatal(err)
	}
	subsystems, err := ctx.getSubsystems()
	if err != nil {
		t.Fatal(err)
	}
	// The regexps used for matching rules may change later, so let's not compare them here.
	for _, s := range subsystems {
		s.PathRules = nil
	}
	expected := []*entity.Subsystem{
		{
			Name:     "ext4",
			Syscalls: []string{"syz_mount_image$ext4"},
			Lists:    []string{"linux-ext4@vger.kernel.org"},
		},
		{
			Name:     "tmpfs",
			Syscalls: []string{"syz_mount_image$tmpfs"},
			// Even though there's a maintainer, we prefer the mailing list.
			Lists: []string{"linux-mm@kvack.org"},
		},
		{
			Name:     "freevxfs",
			Syscalls: []string{"syz_mount_image$freevxfs"},
			// There was no mailing list, so we take the maintainer.
			Maintainers: []string{"email_vxfs@email.com"},
		},
		{
			Name:  "vfs",
			Lists: []string{"linux-fsdevel@vger.kernel.org"},
		},
	}
	assert.ElementsMatch(t, subsystems, expected)
}

func TestGroupLinuxSubsystems(t *testing.T) {
	ctx := &linuxCtx{
		repo:       prepareTestLinuxRepo(t, nil),
		rawRecords: prepareTestMaintainers(t),
	}
	ctx.groupByList()
	subsystems, err := ctx.getSubsystems()
	if err != nil {
		t.Fatal(err)
	}
	// The regexps used for matching rules may change later, so let's not compare them here.
	for _, s := range subsystems {
		s.PathRules = nil
	}
	expected := []*entity.Subsystem{
		{
			// Without the rules it would have the "fs" name.
			Name:  "fs",
			Lists: []string{"linux-fsdevel@vger.kernel.org"},
		},
		{
			Name:  "ext4",
			Lists: []string{"linux-ext4@vger.kernel.org"},
		},
		{
			Name:  "mm",
			Lists: []string{"linux-mm@kvack.org"},
		},
		{
			Name:  "kernel",
			Lists: []string{"linux-kernel@vger.kernel.org"},
		},
	}
	assert.ElementsMatch(t, subsystems, expected)
}

func TestLinuxSubsystemsList(t *testing.T) {
	repo := prepareTestLinuxRepo(t, []byte(testMaintainers))
	subsystems, err := listFromRepoInner(repo, testRules)
	if err != nil {
		t.Fatal(err)
	}
	// The regexps used for matching rules may change later, so let's not compare them here.
	for _, s := range subsystems {
		s.PathRules = nil
	}
	expected := []*entity.Subsystem{
		{
			Name:     "ext4",
			Syscalls: []string{"syz_mount_image$ext4"},
			Lists:    []string{"linux-ext4@vger.kernel.org"},
		},
		{
			Name:     "tmpfs",
			Syscalls: []string{"syz_mount_image$tmpfs"},
			// Even though there's a maintainer, we prefer the mailing list.
			Lists: []string{"linux-mm@kvack.org"},
		},
		{
			Name:     "freevxfs",
			Syscalls: []string{"syz_mount_image$freevxfs"},
			// There was no mailing list, so we take the maintainer.
			Maintainers: []string{"email_vxfs@email.com"},
		},
		{
			Name:  "vfs",
			Lists: []string{"linux-fsdevel@vger.kernel.org"},
		},
		{
			Name:  "mm",
			Lists: []string{"linux-mm@kvack.org"},
		},
		{
			Name:  "kernel",
			Lists: []string{"linux-kernel@vger.kernel.org"},
		},
	}
	assert.ElementsMatch(t, subsystems, expected)
}

func prepareTestLinuxRepo(t *testing.T, maintainers []byte) string {
	repo := t.TempDir()
	testutil.DirectoryLayout(t, repo, []string{
		`fs/ext4/fsync.c`,
		`fs/ext4/mmp.c`,
		`fs/freevxfs/vxfs_olt.c`,
		`fs/file.c`,
		`fs/internal.h`,
		`include/linux/fs.h`,
		`include/linux/mm.h`,
		`include/net/ah.h`,
		`mm/memory.c`,
		`mm/shmem.c`,
	})
	err := osutil.WriteFile(filepath.Join(repo, "MAINTAINERS"), maintainers)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func prepareTestMaintainers(t *testing.T) []*maintainersRecord {
	records, err := parseLinuxMaintainers(bytes.NewReader([]byte(testMaintainers)))
	if err != nil {
		t.Fatal(err)
	}
	return records
}

var (
	testRules = []linuxSubsystemRule{
		{
			name:        "ext4",
			matchPath:   "fs/ext4",
			noMatchPath: "fs/file.c",
			syscalls:    []string{"syz_mount_image$ext4"},
		},
		{
			name:        "freevxfs",
			matchPath:   "fs/freevxfs",
			noMatchPath: "fs/file.c",
			syscalls:    []string{"syz_mount_image$freevxfs"},
		},
		{
			name:        "tmpfs",
			matchPath:   "mm/shmem.c",
			noMatchPath: "mm/memory.c",
			syscalls:    []string{"syz_mount_image$tmpfs"},
		},
		{
			name:        "vfs",
			matchPath:   "fs/file.c",
			noMatchPath: "mm/memory.c", // exclude any top level subsystems
		},
	}
	testMaintainers = `
Maintainers List
----------------

.. note:: When reading this list, please look for the most precise areas
          first. When adding to this list, please keep the entries in
          alphabetical order.

FILESYSTEMS (VFS and infrastructure)
M:	Developer <email_vfs@email.com>
L:	linux-fsdevel@vger.kernel.org
S:	Maintained
F:	fs/*
F:	include/linux/fs.h
F:	include/linux/fs_types.h
F:	include/uapi/linux/fs.h
F:	include/uapi/linux/openat2.h

EXT4 FILE SYSTEM
M:	Developer <email_ext4@email.com>
M:	Developer <email_ext4_2@email.com>
L:	linux-ext4@vger.kernel.org
S:	Maintained
W:	http://ext4.wiki.kernel.org
Q:	http://patchwork.ozlabs.org/project/linux-ext4/list/
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/tytso/ext4.git
F:	Documentation/filesystems/ext4/
F:	fs/ext4/
F:	include/trace/events/ext4.h

FREEVXFS FILESYSTEM
M:	Developer <email_vxfs@email.com>
S:	Maintained
W:	ftp://ftp.openlinux.org/pub/people/hch/vxfs
F:	fs/freevxfs/

MEMORY MANAGEMENT
M:	Developer <email_mm@email.com>
L:	linux-mm@kvack.org
S:	Maintained
W:	http://www.linux-mm.org
T:	git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
T:	quilt git://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new
F:	include/linux/gfp.h
F:	include/linux/gfp_types.h
F:	include/linux/memory_hotplug.h
F:	include/linux/mm.h
F:	include/linux/mmzone.h
F:	include/linux/pagewalk.h
F:	include/linux/vmalloc.h
F:	mm/
F:	tools/testing/selftests/vm/

TMPFS (SHMEM FILESYSTEM)
M:	Developer <email_shmem@email.com>
L:	linux-mm@kvack.org
S:	Maintained
F:	include/linux/shmem_fs.h
F:	mm/shmem.c

THE REST
M:	Developer <email_rest@email.com>
L:	linux-kernel@vger.kernel.org
S:	Buried alive in reporters
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
F:	*
F:	*/

`
)
