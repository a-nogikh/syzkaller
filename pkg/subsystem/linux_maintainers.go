// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// MaintainersFile represents a parsed MAINTAINERS file.
type MaintainersFile struct {
	records []*MaintainersRecord
}

// MaintainersRecord represents a single entry in the MAINTAINERS file.
type MaintainersRecord struct {
	Name    string
	include []*regexp.Regexp
	exclude []*regexp.Regexp
	lists   []string
}

// MaintainersFetcher can be used to access the cached version of MAINTAINERS.
type MaintainersFetcher struct {
	url         string
	nextFetch   time.Time
	lastFile    *MaintainersFile
	fetchPeriod time.Duration
	logError    func(msg string)
}

const maintainersFetchPeriod = time.Hour * 24

func NewMaintainersFetcher(url string, logger func(msg string)) *MaintainersFetcher {
	return &MaintainersFetcher{
		url:         url,
		fetchPeriod: maintainersFetchPeriod,
		logError:    logger,
	}
}

func (mf *MaintainersFetcher) Fetch() (*MaintainersFile, error) {
	err := mf.tryUpdateFile()
	if err != nil && mf.logError != nil {
		mf.logError(fmt.Sprintf("MAINTAINERS query error: %s", err))
	}
	if mf.lastFile == nil {
		return nil, fmt.Errorf("no MAINTAINERS file was obtained")
	}
	return mf.lastFile, nil
}

func (mf *MaintainersFetcher) tryUpdateFile() error {
	if time.Now().Before(mf.nextFetch) {
		return nil
	}
	err := mf.updateFile()
	if err != nil && mf.lastFile == nil {
		// If we don't have the file yet, try to fetch it more often.
		const retryErrorPeriod = time.Hour * 2
		mf.nextFetch = time.Now().Add(retryErrorPeriod)
	} else {
		mf.nextFetch = time.Now().Add(mf.fetchPeriod)
	}
	return err
}

func (mf *MaintainersFetcher) updateFile() error {
	resp, err := http.Get(mf.url)
	if err != nil {

		return err
	}
	defer resp.Body.Close()
	mf.lastFetch = time.Now()
	newFile, err := ParseLinuxMaintainers(resp.Body)
	if err != nil {
		return err
	}
	mf.lastFile = newFile
	return nil
}

func (mf *MaintainersFile) Find(file string) []*MaintainersRecord {
	ret := []*MaintainersRecord{}
	for _, record := range mf.records {
		if record.match(file) {
			ret = append(ret, record)
		}
	}
	return ret
}

func (record *MaintainersRecord) match(file string) bool {
	for _, p := range record.exclude {
		if p.MatchString(file) {
			return false
		}
	}
	for _, p := range record.include {
		if p.MatchString(file) {
			return true
		}
	}
	return false
}

func ParseLinuxMaintainers(content io.Reader) (*MaintainersFile, error) {
	scanner := bufio.NewScanner(content)
	// First skip the headers.
	for scanner.Scan() {
		line := scanner.Text()
		if line == "Maintainers List" {
			// Also skip ------.
			scanner.Scan()
			break
		}
	}
	ret := &MaintainersFile{}
	for skipComments(scanner) {
		line := strings.TrimSpace(scanner.Text())
		record := &MaintainersRecord{Name: line}
		ret.records = append(ret.records, record)
		for scanner.Scan() {
			property := scanner.Text()
			if property == "" {
				break
			}
			err := applyProperty(property, record)
			if err != nil {
				return nil, fmt.Errorf("failed to apply %#v: %w", property, err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

func skipComments(scanner *bufio.Scanner) bool {
main:
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		} else if strings.HasPrefix(line, ".") {
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue main
				}
			}
			return false
		} else {
			return true
		}
	}
	return false
}

func applyProperty(line string, record *MaintainersRecord) error {
	pos := strings.Index(line, ":")
	if pos < 0 {
		return fmt.Errorf("invalid property format: no ':'")
	}
	t, value := line[:pos], strings.TrimSpace(line[pos+1:])
	switch t {
	case "F":
		r, err := wilcardToRegexp(value)
		if err != nil {
			return err
		}
		record.include = append(record.include, r)
	case "X":
		r, err := wilcardToRegexp(value)
		if err != nil {
			return err
		}
		record.exclude = append(record.exclude, r)
	case "N":
		r, err := regexp.Compile(value)
		if err != nil {
			return err
		}
		record.include = append(record.exclude, r)
	case "L":
		if strings.Contains(value, "<") {
			pos := strings.Index(value, "<")
			value = value[pos+1:]
			pos = strings.Index(value, ">")
			if pos < 0 {
				return fmt.Errorf("no >")
			}
			value = value[:pos]
		} else if strings.Contains(value, " ") {
			pos := strings.Index(value, " ")
			if pos >= 0 {
				value = value[:pos]
			}
		} else if strings.Contains(value, "\t") {
			pos := strings.Index(value, "\t")
			if pos >= 0 {
				value = value[:pos]
			}
		}
		record.lists = append(record.lists, value)
	}
	return nil
}
