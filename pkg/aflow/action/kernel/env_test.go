// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/require"
)

func TestEnvPreProvided(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	ctx.Env = &aflow.EnvConfig{
		KernelSrcDir: "/my/src",
	}

	// Test checkout.
	res, err := checkout(ctx, checkoutArgs{})
	require.NoError(t, err)
	require.Equal(t, "/my/src", res.KernelSrc)

	// Test buildKernel - should fail because we only provided source.
	_, err = buildKernel(ctx, buildArgs{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not support builds")

	// Test checkoutScratch - should unconditionally fail when kernel is pre-provided.
	_, err = checkoutScratch(ctx, checkoutScratchArgs{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "provided an external kernel source")
}
