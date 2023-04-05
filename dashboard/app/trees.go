// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
)

// To think.
// 1. Distinguish cases when the target kernel just doens't compile/boot and when we managed
// to run a repro and thus triggered a crash.
// 2. In how many cases do we truly need to fetch the job itself?

type pollTreeJobResult interface{}

// pollResultPending is returned when we wait some job to finish.
type pollResultPending struct{}

// pollResultWait is returned when we know the next time the process could be repeated.
type pollResultWait time.Duration

// pollResultSkip means that there are no poll jobs we could run at the moment.
// It's impossible to say when it changes, so it's better not to repeat polling soon.
type pollResultSkip struct{}

type pollResultError error

type pollResultDone struct {
	Crashed bool
}

type bugTreeContext struct {
	c          context.Context
	reproCrash *Crash
	crashes    []*Crash
	crashKeys  []*db.Key
	bugKey     *db.Key
	bug        *Bug
	noNewJobs  bool
}

func (ctx *bugTreeContext) pollBugTreeJobs() (PollTreeJobResult, error) {
	// Determine the crash we'd stick to.
	err := ctx.loadCrashes()
	if err != nil {
		return pollResultError(err)
	}
	if ctx.reproCrash == nil {
		// There are no crashes we could further work with.
		// TODO: consider looking at the recent repro retest results.
		return pollResultSkip{}
	}

	// TODO: ensure mainline/lts are run at least once (or until they're compiled/booted).

	jobs := []func() PollTreeJobResult{
		ctx.onceOnInflow,
		ctx.downstreamLabel,
		ctx.missingBackportLabel,
		ctx.nextLabel,
	}
	var minWait *time.Time
	for _, f := range jobs {
		result := f()
		switch v := result.(type) {
		case pollResultPending, pollResultError:
			// Wait for the job result to continue.
			return result, nil
		case pollResultWait:
			t := v.(time.Duration)
			if minWait == nil || *minWait > t {
				minWait = &t
			}
		}
	}
	if minWait != nil {
		return pollResultWait(minWait)
	}
	return pollResultSkip{}
}

func (ctx *bugTreeContext) onceOnInflow() PollTreeJobResult {
	// Ensure we have attempted to run once on all trees from which patches flow to us.
	// If build failed, retry every X months until succeeds (X is big).

	// TODO: consider running all in parallel and merging the result.
	for _, repo := range ctx.inflowRepos() {
		result := ctx.runRepro(repo, firstAny{}, runOnHEAD{})
		_, ok := result.(pollResultDone)
		if !ok {
			return result
		}
	}
	return pollResultSkip{}
}

func (ctx *bugTreeContext) downstreamLabel() PollTreeJobResult {
	// TODO: do we need to rerun the code if we already have the label?
	// TODO: alternatively, fetch the needed repo and run once.

	// Find the earliest upstream link.
	flow, repo := ctx.findFirstRepo(dashapi.RepoUpstream)
	if repo == nil {
		return pollResultSkip{}
	}
	runOn := runReproOn(runOnHEAD{})
	if flow == dashapi.MergeCommits {
		runOn = runOnMergeBase{}
	}
	result := ctx.runRepro(repo, firstAny{}, runOn)
	info, ok := result.(pollResultDone)
	if !ok {
		return result
	}
	if info.Crashed {
		// TODO: assign upstream label.
		return pollResultSkip{}
	}

	// We are to assign the "downstream" label.
	// To reduce the number of false positives, run the reproducer on the original commit.
	// We could have made changes to executor/execution enviroment that have made it
	// impossible to reproduce the crash at all.
	result = ctx.runRepro(ctx.kernelRepo, noLaterAny(info.BuildTime),
		runOnCommit(ctx.origCommit))
	info, ok = result.(pollResultDone)
	if !ok {
		return result
	}
	if info.Crashed {
		// TODO: assign downstream label.
	}
	return pollResultSkip{}
}

func (ctx *bugTreeContext) missingBackportLabel() (PollTreeJobResult, error) {
	// TODO: do we need to rerun the code if we already have the label?
	if !ctx.bug.Tags.Upstream.Value {
		// Backports can only be missing for upstream bugs.
		return pollResultSkip{}
	}
	for _, repo := range ctx.inflowRepos(dashapi.RepoUpstream) {
		result := ctx.runRepro(repo, firstOK{}, runOnHEAD{})
		_, ok := result.(pollResultDone)
		if !ok {
			return result
		}
	}

	// TODO: could we have reached here if there was no merge base?
	// It seems that in the other case we need to retest on the exact upstream commit
	// where we first(last) detected a crash.

	// We are about to assign the "missing backport" label.
	// To reduce the number of backports, just in case run once more on the merge base.
	result := ctx.runDirectLink(dashapi.RepoUpstream, noLaterAny(info.BuildTime), runOnMergeBase{})
	info, ok = result.(pollResultDone)
	if !ok {
		return result
	}
	if info.Crashed {
		// TODO: assign "missing backport" label.
		// TODO: consider adding a bisection job.
	}
	return pollResultSkip{}
}

func (ctx *bugTreeContext) nextLabel() (PollTreeJobResult, error) {
	// Test next label.
	// List branches whose next is the current crash'es branch.
	// If there are none, give up.
	// Ensure reproducer is run there.
	// [handle errors]
	// If we are to assign next, re-run the reproducer on the original crash.
}

// Returns time till maxAge is reached.
type expectedRunResult interface{}
type firstOK struct{}
type firstCrash struct{}
type firstAny struct{}
type noLaterAny time.Time

type runReproOn interface{}
type runOnCommit string
type runOnHEAD struct{}
type runOnMergeBase struct{}

func (ctx *bugTreeContext) runRepro(repo KernelRepo, expect expectedRunResult,
	runOn runReproOn) (PollTreeJobResult, error) {
	// 1. Find or create a BugTreeTest entry.
	// 2. Examine existing jobs.
	// 3. If needed, create new jobs and wait until they are finished.
	// In case of build/test error, only retry in case of runOnHEAD.
}

func (ctx *bugTreeContext) loadCrashes() error {
	var err error
	const bugTreeCrashes = 10
	ctx.crashes, ctx.crashKeys, err = queryCrashesForBug(ctx.c, ctx.bugKey, bugTreeCrashes)
	if err != nil {
		return err
	}
	if len(ctx.crashes) == 0 {
		// No sense to continue.
		return nil
	}
	// First look at the crash from previous tests.
	if len(ctx.bug.TreeTests) > 0 {
		crashID := ctx.bug.TreeTests[len(ctx.bug.TreeTests)-1].CrashID
		crashKey := db.NewKey(c, "Crash", "", crashID, ctx.bugKey)
		crash := new(Crash)
		if err := db.Get(c, crashKey, crash); err != nil {
			return nil, nil, fmt.Errorf("failed to get crash: %v", err)
		}
		ok, err := ctx.isCrashRelevant(crash)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			ctx.reproCrash = crash
			return nil
		}
	}
	// Query the most relevant crash with repro.
	if ctx.isCrashRelevant(ctx.crashes[0]) {
		ctx.reproCrash = crash
	}
	return nil
}

func (ctx *bugTreeContext) isCrashRelevant(crash *Crash) (bool, error) {
	// Do we actually need that given that we retest crashes anyway?
	// Query the last manager build.
	// Compare repo and branch. And config?
}

func (cfg *Config) findLinkedRepos(url, branch string, role dahsapi.RepoRole) []KernelRepo {

}
