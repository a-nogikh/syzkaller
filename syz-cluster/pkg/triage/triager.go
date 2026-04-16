// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

type Triager struct {
	debugtracer.DebugTracer
	Client *api.Client
	Ops    *GitTreeOps
}

func (triager *Triager) GetVerdict(ctx context.Context, sessionID string) (*api.TriageResult, error) {
	sessionInfo, err := triager.Client.GetSessionInfo(ctx, sessionID)
	if err != nil {
		// TODO: the workflow step must be retried.
		return nil, fmt.Errorf("failed to query series: %w", err)
	}
	series := sessionInfo.Series
	treesResp, err := triager.Client.GetTrees(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query trees: %w", err)
	}
	if sessionInfo.Job != nil {
		return triager.prepareJobTask(series, sessionInfo.Job, treesResp.Trees)
	}
	fuzzConfigs := MergeKernelFuzzConfigs(SelectFuzzConfigs(series, treesResp.FuzzTargets))
	if len(fuzzConfigs) == 0 {
		return &api.TriageResult{
			SkipReason: "no suitable fuzz configs found",
		}, nil
	}
	ret := &api.TriageResult{}
	for _, campaign := range fuzzConfigs {
		fuzzTask, err := triager.prepareFuzzingTask(ctx, series, treesResp.Trees, campaign)
		var skipErr *SkipTriageError
		if errors.As(err, &skipErr) {
			ret.SkipReason = skipErr.Reason.Error()
			continue
		} else if err != nil {
			return nil, err
		}
		ret.Targets = append(ret.Targets, fuzzTask)
	}
	if len(ret.Targets) > 0 {
		// If we have prepared at least one fuzzing task, the series was not skipped.
		ret.SkipReason = ""
	}
	return ret, nil
}

func (triager *Triager) prepareFuzzingTask(ctx context.Context, series *api.Series, trees []*api.Tree,
	target *MergedFuzzConfig) (*api.TestTarget, error) {
	var result *TreeSelectResult
	var err error
	if series.BaseCommitHint != "" {
		result, err = triager.selectFromBaseCommitHint(series.BaseCommitHint, trees)
		if err != nil {
			return nil, fmt.Errorf("selection by base-commit failed: %w", err)
		}
	}
	if result == nil {
		result, err = triager.selectFromBlobs(series, trees)
		if err != nil {
			return nil, fmt.Errorf("selection by blob failed: %w", err)
		}
	}
	if result == nil {
		result, err = triager.selectFromList(ctx, series, trees, target)
		if err != nil {
			return nil, fmt.Errorf("selection from the list failed: %w", err)
		}
	}
	if result != nil {
		triager.Logf("continuing with %v in %v", result.Commit, result.Tree.Name)
		base := api.BuildRequest{
			TreeName:   result.Tree.Name,
			TreeURL:    result.Tree.URL,
			ConfigName: target.KernelConfig,
			CommitHash: result.Commit,
			Arch:       result.Arch,
		}
		testTarget := &api.TestTarget{
			Base:    base,
			Patched: base,
			Track:   target.Track,
			Fuzz:    target.FuzzConfig,
		}
		testTarget.Patched.SeriesID = series.ID
		retestFindings, err := triager.Client.ListPreviousFindings(ctx, &api.ListPreviousFindingsReq{
			SeriesID: series.ID,
			Arch:     result.Arch,
			Config:   target.KernelConfig,
		})
		if err != nil {
			// This is sad, but not critical.
			triager.Logf("failed to query previous findings: %v", err)
		} else if len(retestFindings) > 0 {
			triager.Logf("scheduling retest for %d findings", len(retestFindings))
			testTarget.Retest = &api.RetestTask{
				Findings: retestFindings,
			}
		}
		return testTarget, nil
	}
	return nil, SkipError("no base commit found")
}

func (triager *Triager) prepareJobTask(
	series *api.Series, job *api.Job, trees []*api.Tree,
) (*api.TriageResult, error) {
	var targets []*api.TestTarget
	for i, task := range job.FindingGroups {
		foundTree := FindTreeByName(trees, task.Build.TreeName)
		if foundTree == nil {
			return &api.TriageResult{
				SkipReason: fmt.Sprintf("tree %q is no longer known", task.Build.TreeName),
			}, nil
		}
		triager.Logf("continuing with job's original tree %q", task.Build.TreeName)
		testTarget := &api.TestTarget{
			Track: fmt.Sprintf("build %d", i),
		}
		testTarget.Patched = api.BuildRequest{
			TreeName:   task.Build.TreeName,
			TreeURL:    task.Build.TreeURL,
			ConfigName: task.Build.ConfigName,
			CommitHash: task.Build.CommitHash,
			Arch:       task.Build.Arch,
			SeriesID:   series.ID,
			JobID:      job.ID,
		}
		if len(task.FindingIDs) > 0 {
			testTarget.Retest = &api.RetestTask{
				Findings: task.FindingIDs,
			}
		}
		targets = append(targets, testTarget)
	}
	if len(targets) == 0 {
		return &api.TriageResult{
			SkipReason: "job has no testing tasks available",
		}, nil
	}
	return &api.TriageResult{
		Targets: targets,
	}, nil
}

type TreeSelectResult struct {
	Tree   *api.Tree
	Commit string
	Arch   string
}

// For now, only amd64 fuzzing is supported.
const fuzzArch = "amd64"

func (triager *Triager) selectFromBlobs(series *api.Series, trees []*api.Tree) (*TreeSelectResult, error) {
	triager.Logf("attempting to guess the base commit by blob hashes")
	var diff []byte
	for _, patch := range series.Patches {
		diff = append(diff, patch.Body...)
		diff = append(diff, '\n')
	}
	baseList, err := triager.Ops.BaseForDiff(diff, triager.DebugTracer)
	if err != nil {
		return nil, err
	}
	tree, commit := FromBaseCommits(series, baseList, trees)
	if tree == nil {
		triager.Logf("no candidate base commit is found")
		return nil, nil
	}
	return &TreeSelectResult{
		Tree:   tree,
		Commit: commit,
		Arch:   fuzzArch,
	}, nil
}

func (triager *Triager) selectFromBaseCommitHint(commit string, trees []*api.Tree) (*TreeSelectResult, error) {
	triager.Logf("attempting to use the base commit %s provided by author", commit)
	commitExists, _ := triager.Ops.Git.CommitExists(commit)
	if !commitExists {
		triager.Logf("commit doesn't exist")
		return nil, nil
	}
	const cutOffDays = 60
	branchList, err := triager.Ops.BranchesThatContain(commit, time.Now().Add(-time.Hour*24*cutOffDays))
	if err != nil {
		return nil, fmt.Errorf("failed to query branches: %w", err)
	}
	for _, branch := range branchList {
		treeIndex, _ := FindTree(trees, branch.Branch)
		if treeIndex != -1 {
			return &TreeSelectResult{
				Tree:   trees[treeIndex],
				Commit: commit,
				Arch:   fuzzArch,
			}, nil
		}
	}
	return nil, nil
}

func (triager *Triager) selectFromList(ctx context.Context, series *api.Series, trees []*api.Tree,
	target *MergedFuzzConfig) (*TreeSelectResult, error) {
	selectedTrees := SelectTrees(series, trees)
	if len(selectedTrees) == 0 {
		return nil, SkipError("no suitable base kernel trees found")
	}
	var skipErr error
	for _, tree := range selectedTrees {
		triager.Logf("considering tree %q", tree.Name)
		lastBuild, err := triager.Client.LastBuild(ctx, &api.LastBuildReq{
			Arch:       fuzzArch,
			ConfigName: target.KernelConfig,
			TreeName:   tree.Name,
			Status:     api.BuildSuccess,
		})
		if err != nil {
			// TODO: the workflow step must be retried.
			return nil, fmt.Errorf("failed to query the last build for %q: %w", tree.Name, err)
		}
		triager.Logf("%q's last build: %q", tree.Name, lastBuild)
		selector := NewCommitSelector(triager.Ops, triager.DebugTracer)
		result, err := selector.Select(series, tree, lastBuild)
		if err != nil {
			// TODO: the workflow step must be retried.
			return nil, fmt.Errorf("failed to run the commit selector for %q: %w", tree.Name, err)
		} else if result.Commit == "" {
			// If we fail to find a suitable commit for all the trees, return an error just about the first one.
			if skipErr == nil {
				skipErr = SkipError("failed to find a base commit: " + result.Reason)
			}
			triager.Logf("failed to find a base commit for %q", tree.Name)
			continue
		}
		triager.Logf("result: %s", result.Commit)
		return &TreeSelectResult{
			Tree:   tree,
			Commit: result.Commit,
			Arch:   fuzzArch,
		}, nil
	}
	return nil, skipErr
}

type SkipTriageError struct {
	Reason error
}

func SkipError(reason string) *SkipTriageError {
	return &SkipTriageError{Reason: errors.New(reason)}
}

func (e *SkipTriageError) Error() string {
	return fmt.Sprintf("series must be skipped: %s", e.Reason)
}

func (e *SkipTriageError) Unwrap() error {
	return e.Reason
}
