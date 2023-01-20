// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

type linuxSubsystemRule struct {
	// The exact short name that will be used by syzbot.
	name string
	// All raw MAINTAINERS records that cover the matchPath subtree will be grouped into one.
	matchPaths []string
	// .. but subsystems covering noMathPath will be excluded from this grouping.
	noMatchPaths []string
	// If a reproducer contains one of the calls below, the crash belongs to the subsystem.
	syscalls []string
}

var (
	linuxSubsystemRules = []linuxSubsystemRule{
		{
			name:         "adfs",
			matchPaths:   []string{"fs/adfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$adfs",
			},
		},
		{
			name:         "affs",
			matchPaths:   []string{"fs/affs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$affs",
			},
		},
		{
			name:         "befs",
			matchPaths:   []string{"fs/befs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$befs",
			},
		},
		{
			name:         "bfs",
			matchPaths:   []string{"fs/bfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$bfs",
			},
		},
		{
			name:         "btrfs",
			matchPaths:   []string{"fs/btrfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$btrfs",
			},
		},
		{
			name:         "cramfs",
			matchPaths:   []string{"fs/cramfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$cramfs",
			},
		},
		{
			name:         "efs",
			matchPaths:   []string{"fs/efs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$efs",
			},
		},
		{
			name:         "erofs",
			matchPaths:   []string{"fs/erofs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$erofs",
			},
		},
		{
			name:         "exfat",
			matchPaths:   []string{"fs/exfat"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$exfat",
			},
		},
		{
			name: "ext4",
			matchPaths: []string{
				"fs/ext4", "fs/ext2", "fs/jbd2",
			},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$ext4",
			},
		},
		{
			name:         "f2fs",
			matchPaths:   []string{"fs/f2fs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$f2fs",
			},
		},
		{
			name:         "fat",
			matchPaths:   []string{"fs/fat"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$msdos",
				"syz_mount_image$vfat",
			},
		},
		{
			name:         "gfs2",
			matchPaths:   []string{"fs/gfs2"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$gfs2",
				"syz_mount_image$gfs2meta",
			},
		},
		{
			name:         "hfs",
			matchPaths:   []string{"fs/hfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$hfs",
			},
		},
		{
			name:         "hfsplus",
			matchPaths:   []string{"fs/hfsplus"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$hfsplus",
			},
		},
		{
			name:         "hpfs",
			matchPaths:   []string{"fs/hpfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$hpfs",
			},
		},
		{
			name:         "iso9660",
			matchPaths:   []string{"fs/isofs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$iso9660",
			},
		},
		{
			name:         "jffs2",
			matchPaths:   []string{"fs/jffs2"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$jffs2",
			},
		},
		{
			name:         "jfs",
			matchPaths:   []string{"fs/jfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$jfs",
			},
		},
		{
			name:         "minix",
			matchPaths:   []string{"fs/minix"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$minix",
			},
		},
		{
			name:         "nilfs2",
			matchPaths:   []string{"fs/nilfs2"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$nilfs2",
			},
		},
		{
			name: "ntfs",
			matchPaths: []string{
				"fs/ntfs", "block/partitions/ldm.c",
			},
			noMatchPaths: []string{
				"fs/file.c", "fs/ntfs3", "block/partitions/core.c",
			},
			syscalls: []string{
				"syz_mount_image$ntfs",
			},
		},
		{
			name:         "ntfs3",
			matchPaths:   []string{"fs/ntfs3"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$ntfs3",
			},
		},
		{
			name:         "ocfs2",
			matchPaths:   []string{"fs/ocfs2"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$ocfs2",
			},
		},
		{
			name:         "omfs",
			matchPaths:   []string{"fs/omfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$omfs",
			},
		},
		{
			name:         "qnx4",
			matchPaths:   []string{"fs/qnx4"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$qnx4",
			},
		},
		{
			name:         "qnx6",
			matchPaths:   []string{"fs/qnx6"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$qnx6",
			},
		},
		{
			name:         "reiserfs",
			matchPaths:   []string{"fs/reiserfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$reiserfs",
			},
		},
		{
			name:         "romfs",
			matchPaths:   []string{"fs/romfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$romfs",
			},
		},
		{
			name:         "squashfs",
			matchPaths:   []string{"fs/squashfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$squashfs",
			},
		},
		{
			name:         "sysv",
			matchPaths:   []string{"fs/sysv"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$sysv",
			},
		},
		{
			name:         "tmpfs",
			matchPaths:   []string{"mm/shmem.c"},
			noMatchPaths: []string{"mm/memory.c"},
			syscalls: []string{
				"syz_mount_image$tmpfs",
			},
		},
		{
			name:         "ubifs",
			matchPaths:   []string{"fs/ubifs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$ubifs",
			},
		},
		{
			name:         "udf",
			matchPaths:   []string{"fs/udf"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$udf",
			},
		},
		{
			name:         "ufs",
			matchPaths:   []string{"fs/ufs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$ufs",
			},
		},
		{
			name:         "vxfs",
			matchPaths:   []string{"fs/freevxfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$vxfs",
			},
		},
		{
			name:         "xfs",
			matchPaths:   []string{"fs/xfs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$xfs",
			},
		},
		{
			name:         "zonefs",
			matchPaths:   []string{"fs/zonefs"},
			noMatchPaths: []string{"fs/file.c"},
			syscalls: []string{
				"syz_mount_image$zonefs",
			},
		},
		// Let's make sure VFS always has the correct name.
		{
			name:         "vfs",
			matchPaths:   []string{"fs/inode.c"},
			noMatchPaths: []string{"mm/memory.c"}, // exclude any top level subsystems
		},
	}
)
