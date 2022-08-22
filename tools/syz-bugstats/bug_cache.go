package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/osutil"
)

type bugCache struct {
	cacheFolder string
	dash        *dashapi.Dashboard
}

func makeBugCache(cacheFolder string, dash *dashapi.Dashboard) (*bugCache, error) {
	cachePath := filepath.Join(cacheFolder, "bugs")
	err := osutil.MkdirAll(cachePath)
	if err != nil {
		return nil, err
	}
	return &bugCache{cacheFolder: cachePath, dash: dash}, nil
}

func (cache *bugCache) getFileName(bugID string) string {
	return filepath.Join(cache.cacheFolder, bugID)
}

func (cache *bugCache) queryCache(bugID string) (*dashapi.BugReport, error) {
	content, err := os.ReadFile(cache.getFileName(bugID))
	if err != nil {
		return nil, err
	}
	ret := &dashapi.BugReport{}
	err = json.Unmarshal(content, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (cache *bugCache) saveCache(bugID string, report *dashapi.BugReport) error {
	content, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return osutil.WriteFile(cache.getFileName(bugID), content)
}

func (cache *bugCache) cachedIDs() ([]string, error) {
	files, err := ioutil.ReadDir(cache.cacheFolder)
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, file := range files {
		ret = append(ret, file.Name())
	}
	return ret, nil
}

func (cache *bugCache) queryMulti(ids []string, filter func(*dashapi.BugReport) bool) (map[string]*dashapi.BugReport, error) {
	nonExisting := []string{}
	ret := map[string]*dashapi.BugReport{}

	toHandle := make(chan string)
	mu := sync.Mutex{}
	processResult := func(id string, report *dashapi.BugReport, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			if filter == nil || filter(report) {
				ret[id] = report
			}
		} else {
			nonExisting = append(nonExisting, id)
		}
	}
	requestBug := func(id string) error {
		bug, err := cache.dash.LoadBug(id)
		if err != nil {
			return err
		}
		err = cache.saveCache(id, bug)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if filter == nil || filter(bug) {
			ret[id] = bug
		}
		return nil
	}

	var wg sync.WaitGroup
	const threads = 32
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range toHandle {
				report, err := cache.queryCache(id)
				processResult(id, report, err)
			}
		}()
	}
	const reportingStep = 200
	for pos, id := range ids {
		if pos%reportingStep == 0 {
			log.Printf("loaded %d/%d", pos, len(ids))
		}
		toHandle <- id
	}
	close(toHandle)
	wg.Wait()

	const requestThreads = 8
	toRequest := make(chan string)
	errors := make(chan error, requestThreads)
	for i := 0; i < requestThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range toRequest {
				errors <- requestBug(id)
			}
		}()
	}
	for pos, id := range nonExisting {
		if pos%reportingStep == 0 {
			log.Printf("requested %d/%d", pos, len(nonExisting))
		}
		toRequest <- id
		err := <-errors
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}
