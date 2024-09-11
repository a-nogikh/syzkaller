// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package log

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncate(t *testing.T) {
	assert.Equal(t, []byte(`01234

<<cut 11 bytes out>>`), Truncate([]byte(`0123456789ABCDEF`), 5, 0))
	assert.Equal(t, []byte(`<<cut 11 bytes out>>

BCDEF`), Truncate([]byte(`0123456789ABCDEF`), 0, 5))
	assert.Equal(t, []byte(`0123

<<cut 9 bytes out>>

DEF`), Truncate([]byte(`0123456789ABCDEF`), 4, 3))
}
