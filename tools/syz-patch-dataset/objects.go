// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"encoding/gob"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

type Series struct {
	Patches []Patch
}

func (s Series) AllFixes() map[string]struct{} {
	ret := map[string]struct{}{}
	for _, patch := range s.Patches {
		for _, id := range patch.FixedBy {
			ret[id] = struct{}{}
		}
	}
	return ret
}

func filterSeries(orig map[string]Series, filter func(*Series) bool) map[string]Series {
	ret := map[string]Series{}
	for id, series := range orig {
		if filter(&series) {
			ret[id] = series
		}
	}
	return ret
}

type Patch struct {
	// Fille by stepProcessArchives().
	ID    string
	Title string
	Date  time.Time
	Fixes []vcs.Commit

	// Filled by stepKernelCommits().
	Commit  string
	FixedBy []string // IDs
}

type KernelRelease struct {
	Tag    string
	Commit string
	Date   time.Time
}

type ExperimentResult struct {
	Release    KernelRelease
	SeriesID   string
	ApplyError string
	BuildError string
	RunError   string
	BuildTime  time.Duration
	RunTime    time.Duration
	Bugs       map[string]string // Title => Report.
}

func (er ExperimentResult) Success() bool {
	return er.ApplyError == "" &&
		er.BuildError == "" &&
		er.RunError == ""
}

type Experiment struct {
	Description string
	Dataset     map[string]Series
	Results     []*ExperimentResult
}

type blobStorage struct {
	baseFolder string
}

func newBlobStorage(folder string) (*blobStorage, error) {
	if err := osutil.MkdirAll(folder); err != nil {
		return nil, err
	}
	return &blobStorage{baseFolder: folder}, nil
}

func hashString(value string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(value))
	return h.Sum32()
}

func (bs *blobStorage) idToFile(id string) string {
	const numFiles = 10000
	hash := hashString(id)
	return filepath.Join(bs.baseFolder, fmt.Sprintf("%d", hash%numFiles))
}

func (bs *blobStorage) read(id string) ([]byte, error) {
	file := bs.idToFile(id)
	obj, err := readObject[map[string][]byte](file)
	if err != nil {
		return nil, err
	}
	return obj[id], nil
}

func (bs *blobStorage) save(id string, value []byte) error {
	file := bs.idToFile(id)
	obj, err := readObject[map[string][]byte](file)
	if err != nil {
		return err
	}
	if obj == nil {
		obj = map[string][]byte{}
	}
	obj[id] = value
	return writeObject(file, obj)
}

type object[T any] struct {
	obj  T
	file string
}

func newObject[T any](file string) (*object[T], error) {
	obj, err := readObject[T](file)
	if err != nil {
		return nil, err
	}
	return &object[T]{obj, file}, nil
}

func (o *object[T]) get() T {
	return o.obj
}

func (o *object[T]) save(obj T) error {
	o.obj = obj
	return writeObject(o.file, obj)
}

func readObject[T any](file string) (T, error) {
	var ret T
	f, err := os.Open(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		return ret, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return ret, err
	}
	err = gob.NewDecoder(gz).Decode(&ret)
	if err == nil {
		err = gz.Close()
	}
	return ret, err
}

func writeObject[T any](file string, val T) error {
	tmpFile := file + ".tmp"
	writeFile := func() error {
		f, err := os.Create(tmpFile)
		if err != nil {
			return err
		}
		defer f.Close()

		gz := gzip.NewWriter(f)
		err = gob.NewEncoder(gz).Encode(val)
		if err != nil {
			f.Close()
			return err
		}
		return gz.Close()
	}
	if err := writeFile(); err != nil {
		return err
	}
	return os.Rename(tmpFile, file)
}
