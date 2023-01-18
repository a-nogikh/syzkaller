// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

// CoincidenceMatrix represents a matrix that, for every A and B,
// stores the number of times A and B have coincided in the input data.
type CoincidenceMatrix struct {
	matrix map[interface{}]map[interface{}]int
}

// TODO: use generics here once we move to Go 1.18+.
func MakeCoincidenceMatrix() *CoincidenceMatrix {
	return &CoincidenceMatrix{
		matrix: make(map[interface{}]map[interface{}]int),
	}
}

func (cm *CoincidenceMatrix) Record(items ...interface{}) {
	for i := 0; i < len(items); i++ {
		for j := 0; j < len(items); j++ {
			cm.inc(items[i], items[j])
		}
	}
}

func (cm *CoincidenceMatrix) Count(a interface{}) int {
	return cm.Get(a, a)
}

func (cm *CoincidenceMatrix) Get(a, b interface{}) int {
	return cm.matrix[a][b]
}

func (cm *CoincidenceMatrix) NonEmptyPairs(cb func(a, b interface{}, val int)) {
	for a, sub := range cm.matrix {
		for b, val := range sub {
			if a == b {
				continue
			}
			cb(a, b, val)
		}
	}
}

func (cm *CoincidenceMatrix) inc(a, b interface{}) {
	subMatrix, ok := cm.matrix[a]
	if !ok {
		subMatrix = make(map[interface{}]int)
		cm.matrix[a] = subMatrix
	}
	subMatrix[b]++
}
