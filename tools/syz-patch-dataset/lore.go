// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/tool"
	"golang.org/x/sync/errgroup"
)

func stepProcessArchives(dir string, state *state) {
	series, patches := parseArchives(dir)
	err := state.series.save(series)
	if err != nil {
		log.Fatal(err)
	}
	for i, patch := range patches {
		if i%10000 == 0 {
			log.Printf("saving %d/%d", i, len(patches))
		}
		err := state.patchStorage.save(patch.id, []byte(patch.patch))
		if err != nil {
			log.Fatal(err)
		}
	}
}

func parseArchives(dir string) (map[string]Series, []patchInfo) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		tool.Failf("failed to read directory: %v", err)
	}
	threads := runtime.NumCPU()
	messages := make(chan *lore.EmailReader, threads*4)
	wg := sync.WaitGroup{}
	g, _ := errgroup.WithContext(context.Background())

	// Generate per-email jobs.
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		log.Printf("reading %s", path)
		wg.Add(1)
		g.Go(func() error {
			defer wg.Done()
			return lore.ReadArchive(path, messages)
		})
	}

	// Set up some worker threads.
	var repoEmails []*email.Email
	var mu sync.Mutex

	var num atomic.Int64
	for i := 0; i < threads; i++ {
		g.Go(func() error {
			for rawMsg := range messages {
				if val := num.Add(1); val%20000 == 0 {
					fmt.Printf("processed %d\n", val)
				}

				body, err := rawMsg.Extract()
				if err != nil {
					continue
				}
				msg, err := email.Parse(bytes.NewReader(body), nil, nil, nil)
				if err != nil {
					continue
				}

				// Keep memory consumption low.
				msg.Body = ""

				mu.Lock()
				repoEmails = append(repoEmails, msg)
				mu.Unlock()
			}
			return nil
		})
	}

	// Once all jobs are generated, close the processing channel.
	wg.Wait()
	close(messages)
	if err := g.Wait(); err != nil {
		tool.Failf("%s", err)
	}
	log.Printf("collected %d messages", len(repoEmails))
	list := lore.Threads(repoEmails)
	log.Printf("collected %d email threads", len(list))

	ret := map[string]Series{}
	var allPatches []patchInfo

	for _, d := range list {
		if d.Type != dashapi.DiscussionPatch {
			continue
		}
		series, patches := createSeries(d)
		if len(series.Patches) == 0 {
			continue
		}
		allPatches = append(allPatches, patches...)

		//		log.Printf("discussion ID=%s BugID=%s Type=%s Subject=%s Messages=%d",
		//		d.MessageID, d.BugIDs, d.Type, d.Subject, len(d.Messages))
		//log.Printf("Info: %v", series)
		ret[d.MessageID] = series
	}
	log.Printf("%d threads are new patches", len(ret))
	return ret, allPatches
}

var patchTitleRe = regexp.MustCompile(`^\[PATCH(?:\s+[vV]\d+\s+)?\s*(?:(\d+)/(\d+))?\]\s+(.*)`)

type patchInfo struct {
	id    string
	patch string
}

func createSeries(thread *lore.Thread) (Series, []patchInfo) {
	var series Series
	slices.SortFunc(thread.Messages, func(a, b *email.Email) int {
		return a.Date.Compare(b.Date)
	})

	var patches []patchInfo
	var expectPatches int
	for i, msg := range thread.Messages {
		match := patchTitleRe.FindStringSubmatch(msg.Subject)
		if match == nil {
			break
		}
		seq, err := strconv.Atoi(match[1])
		if err != nil {
			break
		}
		if i == 0 && seq > 1 {
			// Broken in-reply-to links.
			break
		}
		of, err := strconv.Atoi(match[2])
		if err != nil {
			break
		}
		expectPatches = of
		if msg.Patch == "" {
			continue
		}
		series.Patches = append(series.Patches, Patch{
			ID:    msg.MessageID,
			Title: match[3],
			Date:  msg.Date,
			Fixes: msg.Fixes,
		})
		patches = append(patches, patchInfo{
			id:    msg.MessageID,
			patch: msg.Patch,
		})
	}
	if len(series.Patches) != expectPatches {
		return Series{}, nil
	}
	return series, patches
}
