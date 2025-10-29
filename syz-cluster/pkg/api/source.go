// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/syzkaller/pkg/vcs"
)

type KernelSourceClient struct {
	baseURL string
}

func NewKernelSourceClient(url string) *KernelSourceClient {
	return &KernelSourceClient{baseURL: strings.TrimRight(url, "/")}
}

var ErrRetryLater = errors.New("server is currently busy, try again a bit later")

type KernelSourceRequest struct {
	TreeName string
	Commit   string
	Patches  [][]byte
	DryRun   bool
}

// GetSource streams a .tar.gz archive of kernel sources at the particular revision.
func (client KernelSourceClient) GetSource(ctx context.Context, req *KernelSourceRequest) (io.ReadCloser, error) {
	httpReq, err := postJSONRequest(ctx, client.baseURL+"/source", req)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: requestTimeout,
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	// If the request succeeds, the content is the gzipped source code.
	if resp.StatusCode == http.StatusOK {
		return resp.Body, nil
	}
	// Otherwise, we should read off the error.
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("request failed with status %d, body read error: %w", resp.StatusCode, err)
	}
	return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
}

type HeadCommitRequest struct {
	TreeName string
	Branch   string
}

func (client KernelSourceClient) HeadCommit(ctx context.Context, req *HeadCommitRequest) (*vcs.Commit, error) {
	return postJSON[HeadCommitRequest, vcs.Commit](ctx, client.baseURL+"/head_commit", req)
}

type CommitInfoRequest struct {
	TreeName       string
	BranchOrCommit string // TODO: split?
}

func (client KernelSourceClient) CommitInfo(ctx context.Context, req *CommitInfoRequest) (*vcs.Commit, error) {
	return postJSON[CommitInfoRequest, vcs.Commit](ctx, client.baseURL+"/commit_info", req)
}
