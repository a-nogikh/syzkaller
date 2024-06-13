// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

func stepKernelCommits(state *state) {
	series := state.series.get()

	titleToPatch := map[string]*Patch{}
	for _, serie := range series {
		for i, patch := range serie.Patches {
			patch.FixedBy = nil
			patch.Commit = ""

			prev := titleToPatch[patch.Title]
			if prev != nil && patch.Date.Before(prev.Date) {
				continue
			}
			titleToPatch[patch.Title] = &serie.Patches[i]
		}
	}

	log.Printf("Loading all kernel commits")

	all, err := state.kernel.ListCommitHashes("HEAD")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Loading per-commit info")
	threads := 32

	var found atomic.Int64
	commits := make(chan string, threads)
	go func() {
		for i, hash := range all {
			if i%10000 == 0 {
				log.Printf("%d(%d)/%d", i, found.Load(), len(all))
			}
			commits <- hash
		}
		close(commits)
	}()

	var mu sync.Mutex
	hashToPatch := map[string]*Patch{}

	g, _ := errgroup.WithContext(context.Background())
	for i := 0; i < threads; i++ {
		g.Go(func() error {
			for hash := range commits {
				commit, err := state.kernel.GetCommit(hash)
				if err != nil {
					return err
				}
				if commit != nil {
					mu.Lock()
					patch := titleToPatch[commit.Title]
					if patch != nil {
						found.Add(1)
						patch.Commit = commit.Hash
						hashToPatch[commit.Hash] = patch
					}
					mu.Unlock()
				}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}

	// TODO: we barely match any commit by the hash and match ~50% of the fixes by the title. Why?

	log.Printf("Query fixes")
	var processedFixes, foundByHash, foundByTitle int
	for _, serie := range series {
		for _, patch := range serie.Patches {
			for _, fix := range patch.Fixes {
				processedFixes++
				if processedFixes%100 == 0 {
					log.Printf("processed %d, matched by hash %d, by title %d",
						processedFixes, foundByHash, foundByTitle)
				}

				if fixedPatch := titleToPatch[fix.Title]; fixedPatch != nil {
					foundByTitle++
					fixedPatch.FixedBy = append(fixedPatch.FixedBy, patch.ID)
					continue
				}

				commit, err := state.kernel.GetCommit(fix.Hash)
				if err != nil {
					// Some fixes refer to the commits that never reached mainline.
					// So let's ignore errors.
					continue
				}

				if fixedPatch := hashToPatch[commit.Hash]; fixedPatch != nil {
					foundByHash++
					fixedPatch.FixedBy = append(fixedPatch.FixedBy, patch.ID)
				}
			}
		}
	}

	err = state.series.save(series)
	if err != nil {
		log.Fatal(err)
	}
}
