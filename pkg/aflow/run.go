// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/backend/gemini"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	aflowhtml "github.com/google/syzkaller/pkg/aflow/trajectory/html"
	"google.golang.org/genai"
)

type RunWorkflowResult[Outputs any] struct {
	Output         Outputs
	TrajectoryHTML []byte
}

type RunWorkflowOption func(*runWorkflowConfig)

type runWorkflowConfig struct {
	workdir    string
	cache      *Cache
	tokenLimit int
}

func RunWithWorkdir(dir string) RunWorkflowOption {
	return func(c *runWorkflowConfig) {
		c.workdir = dir
	}
}

func RunWithCache(cache *Cache) RunWorkflowOption {
	return func(c *runWorkflowConfig) {
		c.cache = cache
	}
}

func RunWithTokenLimit(limit int) RunWorkflowOption {
	return func(c *runWorkflowConfig) {
		c.tokenLimit = limit
	}
}

// RunWorkflow executes a registered workflow in-place using the Gemini provider,
// collects its trajectory spans into an HTML report, and returns the strongly typed output.
// Even if an error occurs during execution, a non-nil result containing the partial
// TrajectoryHTML may be returned alongside the error.
func RunWorkflow[Inputs, Outputs any](ctx context.Context, typ ai.WorkflowType, apiKey string, inputs Inputs,
	opts ...RunWorkflowOption) (*RunWorkflowResult[Outputs], error) {
	cfg := &runWorkflowConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	workflowDesc := Flows[string(typ)]
	if workflowDesc == nil {
		return nil, fmt.Errorf("workflow %q is not registered", typ)
	}

	workdir := cfg.workdir
	if workdir == "" {
		tempDir, err := os.MkdirTemp("", "aflow-run-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp workdir: %w", err)
		}
		defer os.RemoveAll(tempDir)
		workdir = tempDir
	}

	argsBytes, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal workflow inputs: %w", err)
	}
	var initialState map[string]any
	if err := json.Unmarshal(argsBytes, &initialState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal initial workflow state: %w", err)
	}

	var spans []*trajectory.Span
	seenID := make(map[int]struct{})
	onEvent := func(span *trajectory.Span) error {
		// Aflow sends each span twice: on start and on finish.
		if _, ok := seenID[span.Seq]; ok {
			return nil
		}
		seenID[span.Seq] = struct{}{}
		spans = append(spans, span)
		return nil
	}

	provider, err := gemini.NewProvider(ctx, gemini.Config{
		ClientConfig: &genai.ClientConfig{
			APIKey: apiKey,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LLM provider: %w", err)
	}
	defer provider.Close()

	cache := cfg.cache
	if cache == nil {
		var err error
		cache, err = NewCache(filepath.Join(workdir, "cache"), 1024*1024*1024)
		if err != nil {
			return nil, fmt.Errorf("failed to create aflow cache: %w", err)
		}
	}

	outputs, err := workflowDesc.Execute(ctx, initialState, ExecuteOptions{
		Provider:   provider,
		Workdir:    workdir,
		Cache:      cache,
		OnEvent:    onEvent,
		TokenLimit: cfg.tokenLimit,
	})

	var htmlReport []byte
	buf := new(bytes.Buffer)
	if renderErr := aflowhtml.RenderReport(buf, spans); renderErr == nil {
		htmlReport = buf.Bytes()
	}

	result := &RunWorkflowResult[Outputs]{
		TrajectoryHTML: htmlReport,
	}

	if err != nil {
		return result, err
	}

	outBytes, err := json.Marshal(outputs)
	if err != nil {
		return result, fmt.Errorf("failed to marshal workflow outputs: %w", err)
	}
	if err := json.Unmarshal(outBytes, &result.Output); err != nil {
		return result, fmt.Errorf("failed to unmarshal workflow outputs: %w", err)
	}

	return result, nil
}
