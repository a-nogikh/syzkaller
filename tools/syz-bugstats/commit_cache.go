package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

type commitSearchCache struct {
	cacheFolder string
	repoFolder  string // we'll append this to generate filename hash
	repo        vcs.Repo
}

func makeCommitSearchCache(repo, cacheFolder string) (*commitSearchCache, error) {
	// TODO: make OS and repo type adjustable.
	vcs, err := vcs.NewRepo(targets.Linux, "gce", *flagKernelRepo)
	if err != nil {
		return nil, err
	}
	cachePath := filepath.Join(cacheFolder, "title")
	err = osutil.MkdirAll(cachePath)
	if err != nil {
		return nil, err
	}
	return &commitSearchCache{repoFolder: repo, repo: vcs, cacheFolder: cachePath}, nil
}

func (cache *commitSearchCache) getFileName(title string) string {
	hasher := sha1.New()
	hasher.Write([]byte(fmt.Sprintf("%s%s", cache.repoFolder, title)))
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return filepath.Join(cache.cacheFolder, sha)
}

func (cache *commitSearchCache) queryCache(title string) (string, error) {
	content, err := os.ReadFile(cache.getFileName(title))
	if err != nil {
		return "", err
	}
	return string(content), err
}

func (cache *commitSearchCache) saveCache(title, commit string) error {
	return osutil.WriteFile(cache.getFileName(title), []byte(commit))
}

func (cache *commitSearchCache) multiQuery(titles []string) (map[string]string, error) {
	nonExisting := []string{}
	// No need to parallelize here - we don't parse JSONs, everything is fast.
	ret := map[string]string{}
	empty := 0
	for _, title := range titles {
		commit, err := cache.queryCache(title)
		if err == nil {
			if commit != "" {
				ret[title] = commit
			} else {
				empty++
			}
		} else {
			nonExisting = append(nonExisting, title)
		}
	}
	// TODO: split in parts and query in parallel.
	log.Printf("cached %d, empty %d, but still need to query %d commits; total %d", len(ret), empty, len(nonExisting), len(titles))
	if len(nonExisting) > 0 {
		commits, missing, err := cache.repo.GetCommitsByTitles(nonExisting)
		if err != nil {
			return nil, err
		}
		for _, commit := range commits {
			err = cache.saveCache(commit.Title, commit.Hash)
			if err != nil {
				return nil, err
			}
			ret[commit.Title] = commit.Hash
		}
		for _, title := range missing {
			cache.saveCache(title, "")
		}
	}
	return ret, nil
}
