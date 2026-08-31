// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/stretchr/testify/require"
)

// NewTestContext creates an initialized dummy Context for internal aflow and tool unit tests.
func NewTestContext(t *testing.T) *Context {
	cache, err := NewCache(t.TempDir(), 10000000)
	require.NoError(t, err)

	ctx := &Context{
		Context: t.Context(),
		cache:   cache,
		onEvent: func(*trajectory.Span) error { return nil },
		stubContext: stubContext{
			timeNow: time.Now,
		},
	}
	span := &trajectory.Span{
		Type: trajectory.SpanTool,
		Name: "test",
	}
	require.NoError(t, ctx.startSpan(span))
	return ctx
}
