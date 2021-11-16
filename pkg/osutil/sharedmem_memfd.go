// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux
// +build linux

package osutil

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// CreateMemMappedFile creates a temp file with the requested size and maps it into memory.
// In the case of Linux, we just use the memfd_create syscall.
func CreateMemMappedFile(size int) (f *os.File, mem []byte, err error) {
	// The name is actually irrelevant and can even be the same for all such files.
	fd, err := unix.MemfdCreate("syz-shared-mem", 0)
	if err != nil {
		err = fmt.Errorf("failed to do memfd_create: %v", err)
		return
	}
	f = os.NewFile(uintptr(fd), fmt.Sprintf("/proc/self/fd/%d", fd))
	if err = f.Truncate(int64(size)); err != nil {
		err = fmt.Errorf("failed to truncate shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	mem, err = syscall.Mmap(fd, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		err = fmt.Errorf("failed to mmap shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	return
}

// CloseMemMappedFile destroys memory mapping created by CreateMemMappedFile.
func CloseMemMappedFile(f *os.File, mem []byte) error {
	err1 := syscall.Munmap(mem)
	err2 := f.Close()
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}
