// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
)

// PathCover is used to perform mass matching operations on a FS tree.
type PathCover struct {
	perPath map[string]*perPathInfo
	matcher PathMatcherFunc
}

// TODO: rewrite this file with generics once we move to Go 1.18+.
// TODO: we could also rewrite it using fs.FS, but the problem is that it'd take too much effort
// to construct a mock fs.FS object. There do not seem to be any ready solutions in the standard
// library.

type perPathInfo struct {
	query sync.Once
	list  []interface{}
}

type PathMatcherFunc func(path string) []interface{}

func BuildPathCover(root string, matcher PathMatcherFunc, excludeRe *regexp.Regexp) (*PathCover, error) {
	pc := &PathCover{
		perPath: map[string]*perPathInfo{},
		matcher: matcher,
	}
	err := filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			// No point in including the root directory.
			return nil
		}
		if !onlyIncludeRe.MatchString(relPath) ||
			(excludeRe != nil && excludeRe.MatchString(relPath)) {
			return nil
		}
		pc.perPath[relPath] = &perPathInfo{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pc, nil
}

var (
	onlyIncludeRe = regexp.MustCompile(`(?:/|\.(?:c|h|S))$`)
)

func (pc *PathCover) CoincidenceMatrix() *CoincidenceMatrix {
	cm := MakeCoincidenceMatrix()
	paths := make(chan string)
	go func() {
		for loopPath := range pc.perPath {
			paths <- loopPath
		}
		close(paths)
	}()
	for items := range pc.queryPaths(paths) {
		cm.Record(items...)
	}
	return cm
}

func (pc *PathCover) queryPaths(input <-chan string) <-chan []interface{} {
	procs := runtime.NumCPU()
	output := make(chan []interface{}, procs)
	var wg sync.WaitGroup
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range input {
				output <- pc.queryPath(req)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(output)
	}()
	return output
}

func (pc *PathCover) queryPath(path string) []interface{} {
	info := pc.perPath[path]
	if info == nil {
		return nil
	}
	info.query.Do(func() {
		info.list = pc.matcher(path)
	})
	return info.list
}
