// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportFixedBugs(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// Check that crashes are correctly serialized in multiple chunks.
	defer func(old int) { exportCrashChunk = old }(exportCrashChunk)
	exportCrashChunk = 1

	// The first reporting of the namespace is non-public, the last one is public.
	const ns = "access-public"
	client := c.makeClient(clientPublic, keyPublic, true)
	build := testBuild(1)
	client.UploadBuild(build)

	// The bug to be fixed, it has a repro.
	crashFixed := testCrashWithRepro(build, 1)
	client.ReportCrash(crashFixed)
	repFixed := c.globalClient.pollBug()
	// A crash without repro must not be exported.
	client.ReportCrash(testCrash(build, 1))

	// A non-public duplicate must not be exported.
	client.ReportCrash(testCrashWithRepro(build, 2))
	repDupPrivate := c.globalClient.pollBug()
	c.globalClient.updateBug(repDupPrivate.ID, dashapi.BugStatusDup, repFixed.ID)

	c.globalClient.updateBug(repFixed.ID, dashapi.BugStatusUpstream, "")
	repFixed = c.globalClient.pollBug()

	// A public duplicate has a repro.
	crashDup := testCrashWithRepro(build, 3)
	crashDup.ReproC = nil
	client.ReportCrash(crashDup)
	repDup := c.globalClient.pollBug()
	c.globalClient.updateBug(repDup.ID, dashapi.BugStatusUpstream, "")
	repDup = c.globalClient.pollBug()
	c.globalClient.updateBug(repDup.ID, dashapi.BugStatusDup, repFixed.ID)

	// A fixed bug without a repro.
	client.ReportCrash(testCrash(build, 4))
	repNoRepro := c.globalClient.pollBug()

	// An open bug with a repro.
	client.ReportCrash(testCrashWithRepro(build, 5))
	c.globalClient.pollBug()

	// One more fixed bug with a repro.
	client.ReportCrash(testCrashWithRepro(build, 6))
	repFixed2 := c.globalClient.pollBug()

	buildFixing := testBuild(2)
	buildFixing.Manager = build.Manager
	for _, rep := range []*dashapi.BugReport{repFixed, repNoRepro, repFixed2} {
		reply, err := c.globalClient.ReportingUpdate(&dashapi.BugUpdate{
			ID:         rep.ID,
			Status:     dashapi.BugStatusOpen,
			FixCommits: []string{"fix for " + rep.Title},
		})
		require.NoError(t, err)
		require.True(t, reply.OK)
		buildFixing.Commits = append(buildFixing.Commits, "fix for "+rep.Title)
	}
	client.UploadBuild(buildFixing)

	var buf bytes.Buffer
	stats, err := exportFixedBugs(c.ctx, ns, &buf, 2)
	require.NoError(t, err)
	assert.Empty(t, stats.Failed)
	assert.Equal(t, 2, stats.Bugs)
	assert.Equal(t, 3, stats.Crashes)

	bugs := readExportedBugs(t, &buf)
	require.Len(t, bugs, 2)
	slices.SortFunc(bugs, func(a, b *exportBug) int { return strings.Compare(a.Title, b.Title) })
	assert.Equal(t, "title6", bugs[1].Title)
	assert.Len(t, bugs[1].Crashes, 1)

	bug := bugs[0]
	assert.Equal(t, "title1", bug.Title)
	assert.Equal(t, []exportCommit{{Title: "fix for title1"}}, bug.FixCommits)
	assert.Nil(t, bug.CauseBisection)
	require.Len(t, bug.Dups, 1)
	assert.Equal(t, "title3", bug.Dups[0].Title)

	require.Len(t, bug.Crashes, 2)
	crash := bug.Crashes[0]
	assert.NotZero(t, crash.ID)
	assert.Equal(t, bug.ID, crash.BugID)
	assert.Equal(t, "title1", crash.Title)
	assert.Equal(t, "report1", crash.Report)
	assert.Equal(t, "repo1", crash.KernelRepo)
	assert.Equal(t, "branch1", crash.KernelBranch)
	assert.Equal(t, build.KernelCommit, crash.KernelCommit)
	assert.Equal(t, "config1", crash.KernelConfig)
	assert.Equal(t, "syzkaller_commit1", crash.SyzkallerCommit)
	assert.Equal(t, "repro opts 1", crash.ReproOpts)
	assert.Equal(t, "syncfs(1)", crash.SyzRepro)
	assert.Equal(t, "int main() { return 1; }", crash.CRepro)

	crash = bug.Crashes[1]
	assert.Equal(t, bug.Dups[0].ID, crash.BugID)
	assert.Equal(t, "title3", crash.Title)
	assert.Equal(t, "syncfs(3)", crash.SyzRepro)
	assert.Empty(t, crash.CRepro)
}

func TestExportFixedBugsRequestValidation(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	for _, url := range []string{
		"/export_fixed_bugs?bucket=bucket",
		"/export_fixed_bugs?ns=non-existent&bucket=bucket",
		// Non-public namespace.
		"/export_fixed_bugs?ns=test1&bucket=bucket",
		"/export_fixed_bugs?ns=access-public",
		"/export_fixed_bugs?ns=access-public&bucket=bucket/../other",
	} {
		_, err := c.GET(url)
		var httpErr *HTTPError
		require.ErrorAs(t, err, &httpErr, url)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code, url)
	}
}

func readExportedBugs(t *testing.T, r io.Reader) []*exportBug {
	// The output consists of several gzip members, which must be read as a single stream.
	var bugs []*exportBug
	gz, err := gzip.NewReader(r)
	require.NoError(t, err)
	scanner := bufio.NewScanner(gz)
	scanner.Buffer(nil, 1<<20)
	for scanner.Scan() {
		bug := new(exportBug)
		require.NoError(t, json.Unmarshal(scanner.Bytes(), bug))
		bugs = append(bugs, bug)
	}
	require.NoError(t, scanner.Err())
	return bugs
}
