package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"time"
)

type lkmlEventType int

const (
	BugReport lkmlEventType = iota
	ReproReport
	BisectCause
	BisectFix
	PatchTest
	Unknown
)

type lkmlEvent struct {
	title            string
	date             time.Time
	eventType        lkmlEventType
	mentionsReproC   bool
	mentionsReproSyz bool
}

type lkmlEventGroup struct {
	events        []*lkmlEvent
	firstReport   time.Time
	firstRepro    time.Time
	separateRepro bool
	causeBisected bool
}

func groupLKML(events []*lkmlEvent) map[string]*lkmlEventGroup {
	saveLeast := func(field *time.Time, curr time.Time) {
		if field.IsZero() || field.After(curr) {
			*field = curr
		}
	}
	ret := map[string]*lkmlEventGroup{}
	for _, event := range events {
		group := ret[event.title]
		if group == nil {
			group = &lkmlEventGroup{}
			ret[event.title] = group
		}
		if event.eventType == BisectCause {
			group.causeBisected = true
		}
		if event.eventType == BugReport || event.eventType == ReproReport {
			saveLeast(&group.firstReport, event.date)
			if event.mentionsReproSyz {
				saveLeast(&group.firstRepro, event.date)
			}
		}
		if event.eventType == ReproReport {
			group.separateRepro = true
		}
		group.events = append(group.events, event)
	}
	return ret
}

func parseLKML(file string) ([]*lkmlEvent, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ret := []*lkmlEvent{}
	reader := csv.NewReader(f)
	for {
		raw, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		record, err := parseLKMLElement(raw)
		if err != nil {
			return nil, err
		}
		ret = append(ret, record)
	}
	return ret, nil
}

func parseLKMLElement(fields []string) (*lkmlEvent, error) {
	if len(fields) != 6 {
		return nil, fmt.Errorf("expected 6 fields, got %d", len(fields))
	}
	const dateFormat = "Mon, 2 Jan 2006 15:04:05 -0700"
	date, err := time.Parse(dateFormat, fields[0])
	if err != nil {
		return nil, err
	}
	ret := &lkmlEvent{
		date:             date,
		title:            fields[1],
		mentionsReproC:   fields[3] == "true",
		mentionsReproSyz: fields[4] == "true",
	}
	switch fields[2] {
	case "test_patch":
		ret.eventType = PatchTest
	case "bisect_cause":
		ret.eventType = BisectCause
	case "bisect_fix":
		ret.eventType = BisectFix
	case "report_repro":
		ret.eventType = ReproReport
	case "report_bug":
		ret.eventType = BugReport
	case "unknown":
		ret.eventType = Unknown
	default:
		return nil, fmt.Errorf("unknown type: %s", fields[2])
	}
	return ret, nil
}
