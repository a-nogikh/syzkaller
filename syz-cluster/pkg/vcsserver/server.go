// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcsserver

import (
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

type APIServer struct {
	wdPool *workdirPool
}

func NewAPIServer(wdPool *workdirPool) *APIServer {
	// Potentially, there could be multiple checkouts, but for now
	// one should suffice.
	return &APIServer{wdPool: wdPool}
}

func (c APIServer) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/source", c.getSource)
	mux.HandleFunc("/head_commit", c.getHeadCommit)
	mux.HandleFunc("/commit_info", c.getCommitInfo)
}

func (c APIServer) getSource(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.KernelSourceRequest](w, r)
	if req == nil {
		return
	}
	wd := c.wdPool.TryGet(req.Name)
	if wd == nil {
		// TODO: return a "please retry" error.
	}
	defer c.wdPool.Release(wd)

}

// TODO: these two are essentially the same??

func (c APIServer) getHeadCommit(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.HeadCommitRequest](w, r)
	if req == nil {
		return
	}
}

func (c APIServer) getCommitInfo(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.CommitInfoRequest](w, r)
	if req == nil {
		return
	}

	// TODO: figure out how to ensure that we have polled the corresponding
	// tree at least once before we start serving operations for it.
	//
	commit, err := c.checkout.commitInfo("")

}
