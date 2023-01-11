// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"bufio"
	"fmt"
	"io"
	"net/mail"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/subsystem/entity"
)

// maintainersRecord represents a single raw record in the MAINTAINERS file.
type maintainersRecord struct {
	name            string
	includePatterns []string
	excludePatterns []string
	regexps         []string
	lists           []string
	maintainers     []string
}

func parseLinuxMaintainers(content io.Reader) ([]*maintainersRecord, error) {
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
	ret := []*maintainersRecord{}
	for skipComments(scanner) {
		line := strings.TrimSpace(scanner.Text())
		record := &maintainersRecord{name: line}
		ret = append(ret, record)
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

func applyProperty(line string, record *maintainersRecord) error {
	pos := strings.Index(line, ":")
	if pos < 0 {
		return fmt.Errorf("invalid property format: no ':'")
	}
	t, value := line[:pos], strings.TrimSpace(line[pos+1:])
	switch t {
	case "F":
		record.includePatterns = append(record.includePatterns, value)
	case "X":
		record.excludePatterns = append(record.excludePatterns, value)
	case "N":
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("invalid regexp: %s", value)
		}
		record.regexps = append(record.regexps, value)
	case "M":
		value, err := parseEmail(value)
		if err != nil {
			return err
		}
		record.maintainers = append(record.maintainers, value)
	case "L":
		value, err := parseEmail(value)
		if err != nil {
			return err
		}
		record.lists = append(record.lists, value)
	}
	return nil
}

func parseEmail(value string) (string, error) {
	// Sometimes there happen extra symbols at the end of the line,
	// let's make this parser more error tolerant.
	pos := strings.LastIndexAny(value, ">)")
	if pos >= 0 {
		value = value[:pos+1]
	}
	addr, err := mail.ParseAddress(value)
	if err != nil {
		return "", err
	}
	return addr.Address, nil
}

func (r maintainersRecord) ToPathRule() entity.PathRule {
	inclRe := strings.Builder{}
	for i, wildcard := range r.includePatterns {
		if i > 0 {
			inclRe.WriteByte('|')
		}
		wildcardToRegexp(wildcard, &inclRe)
	}
	for _, rg := range r.regexps {
		if inclRe.Len() > 0 {
			inclRe.WriteByte('|')
		}
		inclRe.WriteString(rg)
	}
	exclRe := strings.Builder{}
	for i, wildcard := range r.excludePatterns {
		if i > 0 {
			exclRe.WriteByte('|')
		}
		wildcardToRegexp(wildcard, &exclRe)
	}
	return entity.PathRule{
		IncludeRegexp: inclRe.String(),
		ExcludeRegexp: exclRe.String(),
	}
}

var (
	escapedSeparator = regexp.QuoteMeta(fmt.Sprintf("%c", filepath.Separator))
	wildcardReplace  = map[byte]string{
		'*': `(?:[^` + escapedSeparator + `]*)`,
		'?': `(?:.)`,
		'/': escapedSeparator,
	}
)

func wildcardToRegexp(wildcard string, store *strings.Builder) {
	store.WriteByte('^')
	tokenStart := 0
	for i, c := range wildcard {
		replace, exists := wildcardReplace[byte(c)]
		if !exists {
			continue
		}
		store.WriteString(regexp.QuoteMeta(wildcard[tokenStart:i]))
		tokenStart = i + 1
		if c == '/' && i == len(wildcard)-1 {
			// The pattern ends with /, which means we need to also match
			// the whole subtree.
			store.WriteString(
				`(?:` + escapedSeparator + `.*)?`,
			)
		} else {
			store.WriteString(replace)
		}
	}
	if tokenStart < len(wildcard) {
		store.WriteString(regexp.QuoteMeta(wildcard[tokenStart:]))
	}
	store.WriteByte('$')
}
