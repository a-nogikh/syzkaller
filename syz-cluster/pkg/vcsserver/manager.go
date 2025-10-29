// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcsserver

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

type checkoutManager struct {
	mu       sync.Mutex
	base     *Checkout
	workdirs chan *Workdir
	trees    map[string]*treeInfo
}

type treeInfo struct {
	*api.Tree
	lastPoll time.Time
}

func newCheckoutManager(trees []*api.Tree, base *Checkout,
	workdirs []*Workdir) *workdirPool {
	allTrees := map[string]*treeInfo{}
	for _, tree := range trees {
		allTrees[tree.Name] = &treeInfo{
			Tree: tree,
		}
	}
	wds := make(chan *Workdir, len(workdirs))
	for _, wd := range workdirs {
		wds <- wd
	}
	return &workdirPool{
		base:     base,
		workdirs: wds,
		allTrees: allTrees,
	}
}

func (cm *workdirPool) TryGet(ctx context.Context, name string) *Checkout {
	cm.mu.Lock()
	tree := cm.allTress[name]
	available := tree != nil && !tree.LastUpdate.IsZero()
	cm.mu.Unlock()
	if !available {
		return nil
	}
	select {
	case <-ctx.Done():
	case wd := <-cm.workdirs:
		return wd
	}
	return nil
}

func (cm *workdirPool) Return(wd *Workdir) {
	cm.workdirs <- wd
}

func (cm *workdirPool) lockAll(ctx context.Context, cb func() error) error {
	var wds []*Workdir
	var err error
	// Collect all.
	for i := 0; i < cap(cm.workdirs); i++ {
		select {
		case wd := <-cm.workdirs:

			wds = append(wds, <-cm.workdirs)
		case err = <-ctx.Done():
			break ret
		}
	}
	err = cb()
	// Return all
ret:
	for _, wd := range wds {
		cm.workdirs <- wd
	}
	return err
}

func (cm *workdirPool) Poll(ctx context.Context, name string) error {
	w.mu.Lock()
	tree := w.trees[name].Tree
	w.mu.Unlock()
	// Lock all workdirs since polling one may case git operation errors
	// on all of them.
	err := cm.lockAll(ctx, func() error {
		return w.base.poll(name, tree.URL, tree.Branch)
	})
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.trees[name].lastPoll = time.Now()
	w.mu.Unlock()
	return nil
}

type VCSManagerConfig struct {
	Trees    []*api.Tree
	BaseDir  string
	Workdirs int
}

type VCSManager struct {
	Config      *VCSManagerConfig
	WorkdirPool *workdirPool
}

func SetupVCSManager(cfg *VCSManagerConfig) *VCSManager {
	base, err := newCheckout(filepath.Join(m.BaseDir, "base"))
	if err != nil {
		return fmt.Errorf("base checkout failed: %w", err)
	}
	var wds []*Workdir
	for i := 0; i < m.Workdirs; i++ {
		wd, err := base.spawn(filepath.Join(m.BaseDir, fmt.Sprint(i)))
		if err != nil {
			return fmt.Errorf("failed to spawn workdir %d: %w", i, err)
		}
		wds = append(wds, err)
	}
	wdPool := newWorkdirPool(m.Trees, base, wds)
	return &VCSManager{
		Config:      cfg,
		WorkdirPool: wdPool,
	}
}

func (m *VCSManager) PollAll(ctx context.Context) error {
	for _, tree := range m.Config.Trees {
		err := m.WorkdirPool.Poll(ctx, tree.Name)
		if err != nil {
			return fmt.Errorf("polling %s failed: %w", tree.Name, err)
		}
	}
	return nil
}

func (m *VCSManager) Loop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(m.Config.PullPeriod):
		}

		err := m.PollAll(ctx)
		if errors.Is(err, context.Canceled) {
			return err
		} else if err != nil {
			app.Errorf("%s", err)
		}
	}
}
