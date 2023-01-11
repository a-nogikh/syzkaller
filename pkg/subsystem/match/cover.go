// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// PathCover is used to perform mass matching operations on a FS tree.
type PathCover struct {
	perPath map[string]*perPathInfo
	matcher PathMatcherFunc
	threads int
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

func BuildPathCover(root string, matcher PathMatcherFunc) (*PathCover, error) {
	pc := &PathCover{
		perPath: map[string]*perPathInfo{},
		matcher: matcher,
		threads: 1,
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
		if alwaysExcludeRe.MatchString(relPath) {
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
	alwaysExcludeRe = regexp.MustCompile(`\.git|Makefile|README`)
)

func (pc *PathCover) Parallel(threads int) {
	pc.threads = threads
}

// QuerySubtree returns the sum of all matching entities for all elements in the directory subtree.
// QuerySubtree assumes that `path` does not begin with a separator.
func (pc *PathCover) QuerySubtree(path string) map[interface{}]struct{} {
	// TODO: we could speed up this implementation by storing the information as a tree
	// and traversing it according to the passed `path`. Though this method is definitely not
	// on the hottest path (it will only be periodically executed by syz-ci). So, at least now,
	// complicating the code does not seem to be worth it.
	paths := make(chan string)
	go func() {
		for loopPath := range pc.perPath {
			if !strings.HasPrefix(loopPath, path) {
				continue
			}
			paths <- loopPath
		}
		close(paths)
	}()
	ret := make(map[interface{}]struct{})
	for item := range pc.queryPaths(paths) {
		// Merge sets into one.
		for _, val := range item {
			ret[val] = struct{}{}
		}
	}
	return ret
}

func (pc *PathCover) QueryPath(path string) []interface{} {
	info := pc.perPath[path]
	if info == nil {
		return nil
	}
	info.query.Do(func() {
		info.list = pc.matcher(path)
	})
	return info.list
}

func (pc *PathCover) queryPaths(input <-chan string) <-chan []interface{} {
	output := make(chan []interface{}, pc.threads)
	var wg sync.WaitGroup
	for i := 0; i < pc.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range input {
				output <- pc.QueryPath(req)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(output)
	}()
	return output
}
