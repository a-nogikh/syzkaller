// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package triage analyzes incoming patch series, repositories, and kernel trees
// to evaluate patch relevance and generate test target configurations.
package triage

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	_ "github.com/google/syzkaller/pkg/aflow/flow"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/gcpsecret"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

type AITriageResult struct {
	WorthFuzzing   bool
	NeedsKMSAN     bool
	KMSANReasoning string
	FocusSymbols   []string
	EnableConfigs  []string
	Reasoning      string
	Trajectory     []byte
}

const (
	aiEvaluationTimeout = time.Hour
	defaultTokenLimit   = 5 * 1000 * 1000 // 5M tokens
)

func CommitPatchForAflow(ops *GitTreeOps) error {
	if _, err := ops.Run("add", "-A"); err != nil {
		return fmt.Errorf("git add failed: %v", osutil.VerboseMessage(err))
	}
	if _, err := ops.Run("-c", "user.name=syz-cluster", "-c", "user.email=triage@syzkaller.com",
		"commit", "-m", "syz-cluster: applied patch under review"); err != nil {
		return fmt.Errorf("git commit failed: %v", osutil.VerboseMessage(err))
	}
	return nil
}

func EvaluatePatch(ctx context.Context, config *app.AppConfig, series *api.Series,
	tracer debugtracer.DebugTracer, kernelSrcDir string) (*AITriageResult, error) {
	apiKey, err := gcpsecret.Resolve(ctx, config.AI.GeminiAPIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Gemini API key: %w", err)
	}

	aiCtx, cancel := context.WithTimeout(ctx, aiEvaluationTimeout)
	defer cancel()

	cacheDir, err := os.MkdirTemp("", "aflow-cache-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create aflow cache dir: %w", err)
	}
	defer os.RemoveAll(cacheDir)

	cache, err := aflow.NewCache(cacheDir, 1024*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("failed to create aflow cache: %w", err)
	}

	tracer.Logf("starting AI patch evaluation...")
	runRes, err := aflow.RunWorkflow[ai.PatchTriageArgs, ai.PatchTriageResult](
		aiCtx,
		ai.WorkflowPatchTriage,
		apiKey,
		ai.PatchTriageArgs{
			// TODO: Set TargetArch dynamically based on the fuzzing targets for the patch.
			// For now it's irrelevant as we only fuzz amd64 anyway.
			TargetArch: "amd64",
			KernelSrc:  kernelSrcDir,
		},
		aflow.RunWithWorkdir(cacheDir),
		aflow.RunWithCache(cache),
		aflow.RunWithTokenLimit(defaultTokenLimit),
	)

	var htmlReport []byte
	if runRes != nil {
		htmlReport = runRes.TrajectoryHTML
	}
	if err != nil {
		return &AITriageResult{Trajectory: htmlReport}, err
	}

	result := runRes.Output
	tracer.Logf("AI verdict: WorthFuzzing=%v (Reason: %s)", result.WorthFuzzing, result.Reasoning)

	return &AITriageResult{
		WorthFuzzing:   result.WorthFuzzing,
		NeedsKMSAN:     result.NeedsKMSAN,
		KMSANReasoning: result.KMSANReasoning,
		FocusSymbols:   result.FocusSymbols,
		EnableConfigs:  result.EnableConfigs,
		Reasoning:      result.Reasoning,
		Trajectory:     htmlReport,
	}, nil
}
