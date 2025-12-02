// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/syzkaller/dashboard/api"
	"github.com/google/syzkaller/pkg/gcs"
	"golang.org/x/sync/errgroup"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

func handleExportBugs(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	for ns, nsConfig := range getConfig(c).Namespaces {
		if nsConfig.BugArchiveExportPath == "" {
			continue
		}
		log.Infof(c, "exporting bugs for %q", ns)
		err := uploadBugsJSONL(c, ns, nsConfig.BugArchiveExportPath)
		if err != nil {
			log.Errorf(c, "failed to export %q bugs: %v", ns, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}

func handleExportUpstreamBugs(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	err := uploadBugsJSONL(c, "upstream", "syzkaller/bugs/upstream.jsonl.gz")
	if err != nil {
		log.Errorf(c, "failed to export %q bugs: %v", "upstream", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

const (
	// With 16 threads, it takes 6-7 minutes to export 26k bugs
	// from the upstream namespace. 32 threads do not accelerate it.
	exportQueryThreads = 32
	exportAccessLevel  = AccessPublic
)

func uploadBugsJSONL(c context.Context, ns, path string) error {
	stream := make(chan *api.Bug, exportQueryThreads)
	eg, ctx := errgroup.WithContext(c)
	eg.Go(func() error {
		defer close(stream)
		return queryBugInfos(ctx, ns, stream)
	})
	eg.Go(func() error {
		return uploadJSONL(ctx, path, stream)
	})
	return eg.Wait()
}

func queryBugInfos(c context.Context, ns string, stream chan<- *api.Bug) error {
	bugs, _, err := loadAllBugs(c, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns)
	})
	if err != nil {
		return fmt.Errorf("failed to load bugs: %w", err)
	}
	log.Infof(c, "loaded %d bugs", len(bugs))
	eg, ctx := errgroup.WithContext(c)
	eg.SetLimit(exportQueryThreads)
	for _, bug := range bugs {
		if exportAccessLevel < bug.sanitizeAccess(ctx, exportAccessLevel) {
			continue
		}
		eg.Go(func() error {
			details, err := loadBugDetails(ctx, bug, exportAccessLevel)
			if err != nil {
				return err
			}
			select {
			case stream <- getExtAPIDescrForBug(details):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}
	return eg.Wait()
}

func uploadJSONL(c context.Context, path string, stream <-chan *api.Bug) error {
	client, err := gcs.NewClient(c)
	if err != nil {
		return fmt.Errorf("failed create a gcs client: %w", err)
	}
	wc, err := client.FileWriter(path, "application/gzip", "")
	if err != nil {
		return fmt.Errorf("file writer ext failed: %w", err)
	}
	gzWriter := gzip.NewWriter(wc)
	enc := json.NewEncoder(gzWriter)
	count := 0
	for bug := range stream {
		err := enc.Encode(bug)
		if err != nil {
			return fmt.Errorf("failed to encode bug ID=%s: %w", bug.ID, err)
		}
		count++
	}
	log.Infof(c, "%d bugs exported", count)
	// Save the file only if the context has not been canceled by now.
	if ctxErr := c.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.Canceled) {
			return nil
		}
		return ctxErr
	}
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("unable to close writer: %w", err)
	}
	return client.Publish(path)
}
