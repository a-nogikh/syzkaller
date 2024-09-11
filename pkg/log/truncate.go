// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package log

import (
	"bytes"
	"fmt"
)

// Truncate leaves up to `begin` bytes at the beginning of log and
// up to `end` bytes at the end of the log.
func Truncate(log []byte, begin, end int) []byte {
	if begin+end >= len(log) {
		return log
	}
	var b bytes.Buffer
	b.Write(log[:begin])
	if begin > 0 {
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, "<<cut %d bytes out>>",
		len(log)-begin-end,
	)
	if end > 0 {
		b.WriteString("\n\n")
	}
	b.Write(log[len(log)-end:])
	return b.Bytes()
}
