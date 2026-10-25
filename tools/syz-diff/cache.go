// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
)

const (
	imageURL = "https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz"
	// Bump it to invalidate all cached kernel builds (e.g. if the way we build kernels changes).
	buildRecipeVersion = 1
)

// artifactCache wraps aflow.Cache and tracks all used entries so that they can be released at once.
type artifactCache struct {
	cache *aflow.Cache
	dirs  []string
}

func newArtifactCache(dir string, size uint64) (*artifactCache, error) {
	cache, err := aflow.NewCache(dir, size)
	if err != nil {
		return nil, err
	}
	return &artifactCache{cache: cache}, nil
}

// get returns the cached dir of the given type, populating it first, if it's not cached yet.
func (c *artifactCache) get(typ, desc string, populate func(dir string) error) (string, error) {
	cached := true
	dir, err := c.cache.Create(typ, desc, func(dir string) error {
		cached = false
		return populate(dir)
	})
	if err != nil {
		return "", err
	}
	if cached {
		log.Logf(0, "using cached %v: %v", typ, dir)
	}
	c.dirs = append(c.dirs, dir)
	return dir, nil
}

func (c *artifactCache) release() {
	for _, dir := range c.dirs {
		c.cache.Release(dir)
	}
	c.dirs = nil
}

// image returns the path to the userspace image file.
func (c *artifactCache) image(ctx context.Context) (string, error) {
	return c.download(ctx, "image", imageURL, imageURL, "image", true)
}

// corpus returns the path to the downloaded corpus file.
// The corpus is re-downloaded once a week, so that the runs within the week are comparable.
func (c *artifactCache) corpus(ctx context.Context, url string) (string, error) {
	return c.download(ctx, "corpus", corpusCacheDesc(url, time.Now()), url, "corpus.db", false)
}

func corpusCacheDesc(url string, now time.Time) string {
	year, week := now.ISOWeek()
	return fmt.Sprintf("%v %v-W%02d", url, year, week)
}

func (c *artifactCache) download(ctx context.Context, typ, desc, url, name string, gunzip bool) (string, error) {
	dir, err := c.get(typ, desc, func(dir string) error {
		log.Logf(0, "downloading %v", url)
		return download(ctx, url, filepath.Join(dir, name), gunzip)
	})
	if err != nil {
		return "", fmt.Errorf("failed to download the %v: %w", typ, err)
	}
	return filepath.Join(dir, name), nil
}

// buildCacheDesc describes the kernel build cache entry.
// Note that it does not depend on the syzkaller revision.
func buildCacheDesc(commit string, patch []byte, configName string, config []byte, compiler string) string {
	desc := struct {
		Recipe     int
		Commit     string
		Patch      string
		ConfigName string
		Config     string
		Compiler   string
	}{
		Recipe:     buildRecipeVersion,
		Commit:     commit,
		ConfigName: configName,
		Config:     hash.String(config),
		Compiler:   compiler,
	}
	if len(patch) != 0 {
		desc.Patch = hash.String(patch)
	}
	data, err := json.Marshal(desc)
	if err != nil {
		panic(err)
	}
	return string(data)
}

const downloadTimeout = 30 * time.Minute

func download(ctx context.Context, url, file string, gunzip bool) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%v: status %v", url, resp.Status)
	}
	body := io.Reader(resp.Body)
	if gunzip {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer gz.Close()
		body = gz
	}
	out, err := os.Create(file)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, body); err != nil {
		return err
	}
	return out.Close()
}
