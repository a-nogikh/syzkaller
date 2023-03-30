// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"bytes"
	"fmt"
	"net/mail"
	"sync"

	"github.com/google/syzkaller/pkg/vcs"
)

type Worker func()

// ReadArchive queries the parsed messages from a single LKML message archive.
func ReadArchive(dir string, workQueue chan<- Worker, messages chan<- *mail.Message) ([]error, error) {
	repo := vcs.NewLKMLRepo(dir)
	commits, err := repo.ListCommitHashes("HEAD")
	if err != nil {
		return nil, fmt.Errorf("failed to get recent commits: %w", err)
	}
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		errors []error
	)
	for _, iterCommit := range commits {
		commit := iterCommit
		wg.Add(1)
		workQueue <- func() {
			defer wg.Done()
			// Messages are stored as revisions of the "m" object.
			data, err := repo.Object("m", commit)
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				errors = append(errors,
					fmt.Errorf("failed to call Object(): %w", err))
				return
			}
			msg, err := mail.ReadMessage(bytes.NewReader(data))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errors = append(errors,
					fmt.Errorf("failed to read message: %w", err))
				return
			}
			messages <- msg
		}
	}
	wg.Wait()
	return errors, nil
}
