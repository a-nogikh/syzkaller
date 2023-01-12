// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import "sync"

// PathCoverCache allows us not to recalculate the same queries over and over.
type PathCoverCache struct {
	cover        *PathCover
	mu           sync.Mutex
	subtreeCache map[string]map[interface{}]struct{}
}

func MakePathCoverCache(cover *PathCover) *PathCoverCache {
	return &PathCoverCache{
		cover:        cover,
		subtreeCache: make(map[string]map[interface{}]struct{}),
	}
}

func (pcc *PathCoverCache) QuerySubtree(path string) map[interface{}]struct{} {
	pcc.mu.Lock()
	ret, ok := pcc.subtreeCache[path]
	pcc.mu.Unlock()

	if ok {
		return ret
	}
	ret = pcc.cover.QuerySubtree(path)

	pcc.mu.Lock()
	pcc.subtreeCache[path] = ret
	pcc.mu.Unlock()
	return ret
}
