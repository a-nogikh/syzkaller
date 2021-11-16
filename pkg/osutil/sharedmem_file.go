// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build freebsd || netbsd || openbsd || darwin
// +build freebsd netbsd openbsd darwin

package osutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
)

// CreateMemMappedFile creates a temp file with the requested size and maps it into memory.
func CreateMemMappedFile(size int) (f *os.File, mem []byte, err error) {
	f, err = ioutil.TempFile("./", "syzkaller-shm")
	if err != nil {
		err = fmt.Errorf("failed to create temp file: %v", err)
		return
	}
	if err = f.Truncate(int64(size)); err != nil {
		err = fmt.Errorf("failed to truncate shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	f.Close()
	fname := f.Name()
	f, err = os.OpenFile(f.Name(), os.O_RDWR, DefaultFilePerm)
	if err != nil {
		err = fmt.Errorf("failed to open shm file: %v", err)
		os.Remove(fname)
		return
	}
	mem, err = syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
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
	err3 := os.Remove(f.Name())
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	case err3 != nil:
		return err3
	default:
		return nil
	}
}
