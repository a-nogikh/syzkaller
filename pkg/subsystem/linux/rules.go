// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

type linuxSubsystemRule struct {
	// The exact short name that will be used by syzbot.
	name string
	// All raw MAINTAINERS records that cover the matchPath subtree will be grouped into one.
	matchPath string
	// .. but subsystems covering noMathPath will be excluded from this grouping.
	noMatchPath string
	// If a reproducer contains one of the calls below, the crash belongs to the subsystem.
	syscalls []string
}

var (
	linuxSubsystemRules = []linuxSubsystemRule{
		{
			name:        "adfs",
			matchPath:   "fs/adfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$adfs",
			},
		},
		{
			name:        "affs",
			matchPath:   "fs/affs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$affs",
			},
		},
		{
			name:        "befs",
			matchPath:   "fs/befs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$befs",
			},
		},
		{
			name:        "bfs",
			matchPath:   "fs/bfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$bfs",
			},
		},
		{
			name:        "btrfs",
			matchPath:   "fs/btrfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$btrfs",
			},
		},
		{
			name:        "cramfs",
			matchPath:   "fs/cramfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$cramfs",
			},
		},
		{
			name:        "efs",
			matchPath:   "fs/efs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$efs",
			},
		},
		{
			name:        "erofs",
			matchPath:   "fs/erofs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$erofs",
			},
		},
		{
			name:        "exfat",
			matchPath:   "fs/exfat",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$exfat",
			},
		},
		{
			name:        "ext4",
			matchPath:   "fs/ext4",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$ext4",
			},
		},
		{
			name:        "f2fs",
			matchPath:   "fs/f2fs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$f2fs",
			},
		},
		{
			name:        "fat",
			matchPath:   "fs/fat",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$msdos",
				"syz_mount_image$vfat",
			},
		},
		{
			name:        "gfs2",
			matchPath:   "fs/gfs2",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$gfs2",
				"syz_mount_image$gfs2meta",
			},
		},
		{
			name:        "hfs",
			matchPath:   "fs/hfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$hfs",
			},
		},
		{
			name:        "hfsplus",
			matchPath:   "fs/hfsplus",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$hfsplus",
			},
		},
		{
			name:        "hpfs",
			matchPath:   "fs/hpfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$hpfs",
			},
		},
		{
			name:        "iso9660",
			matchPath:   "fs/isofs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$iso9660",
			},
		},
		{
			name:        "jffs2",
			matchPath:   "fs/jffs2",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$jffs2",
			},
		},
		{
			name:        "jfs",
			matchPath:   "fs/jfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$jfs",
			},
		},
		{
			name:        "minix",
			matchPath:   "fs/minix",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$minix",
			},
		},
		{
			name:        "nilfs2",
			matchPath:   "fs/nilfs2",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$nilfs2",
			},
		},
		{
			name:        "ntfs",
			matchPath:   "fs/ntfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$ntfs",
			},
		},
		{
			name:        "ntfs3",
			matchPath:   "fs/ntfs3",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$ntfs3",
			},
		},
		{
			name:        "ocfs2",
			matchPath:   "fs/ocfs2",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$ocfs2",
			},
		},
		{
			name:        "omfs",
			matchPath:   "fs/omfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$omfs",
			},
		},
		{
			name:        "qnx4",
			matchPath:   "fs/qnx4",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$qnx4",
			},
		},
		{
			name:        "qnx6",
			matchPath:   "fs/qnx6",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$qnx6",
			},
		},
		{
			name:        "reiserfs",
			matchPath:   "fs/reiserfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$reiserfs",
			},
		},
		{
			name:        "romfs",
			matchPath:   "fs/romfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$romfs",
			},
		},
		{
			name:        "squashfs",
			matchPath:   "fs/squashfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$squashfs",
			},
		},
		{
			name:        "sysv",
			matchPath:   "fs/sysv",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$sysv",
			},
		},
		{
			name:        "tmpfs",
			matchPath:   "mm/shmem.c",
			noMatchPath: "mm/memory.c",
			syscalls: []string{
				"syz_mount_image$tmpfs",
			},
		},
		{
			name:        "ubifs",
			matchPath:   "fs/ubifs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$ubifs",
			},
		},
		{
			name:        "udf",
			matchPath:   "fs/udf",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$udf",
			},
		},
		{
			name:        "ufs",
			matchPath:   "fs/ufs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$ufs",
			},
		},
		{
			name:        "vxfs",
			matchPath:   "fs/freevxfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$vxfs",
			},
		},
		{
			name:        "xfs",
			matchPath:   "fs/xfs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$xfs",
			},
		},
		{
			name:        "zonefs",
			matchPath:   "fs/zonefs",
			noMatchPath: "fs/file.c",
			syscalls: []string{
				"syz_mount_image$zonefs",
			},
		},
		// Let's make sure VFS always has the correct name.
		{
			name:        "vfs",
			matchPath:   "fs/inode.c",
			noMatchPath: "mm/memory.c", // exclude any top level subsystems
		},
	}
)
