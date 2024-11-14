// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"time"

	"cloud.google.com/go/spanner"
)

type Series struct {
	ID    string   `spanner:"ID"`
	Title string   `spanner:"Title"`
	Link  string   `spanner:"Link"`
	Cc    []string `spanner:"Cc"`
}

type Patch struct {
	ID       string `spanner:"ID"`
	SeriesID string `spanner:"SeriesID"`
	Title    string `spanner:"Title"`
	Link     string `spanner:"Link"`
	BodyURI  string `spanner:"Link"`
}

const (
	BuildSuccess    string = "success"
	BuildFailed     string = "failed" // failed due to a compilation error
	BuildError      string = "error"  // failed due to a problem on our side
	BuildInProgress string = "in_progress"
)

// TODO: how are we going to deduplicate base tree builds? We must know the commit hash?
type Build struct {
	ID         string             `spanner:"ID"`
	SeriesID   spanner.NullString `spanner:"SeriesID"`
	Repo       string             `spanner:"Repo"`
	CommitHash string             `spanner:"CommitHash"`
	Status     string             `spanner:"Status"`
}

type Session struct {
	ID             string           `spanner:"ID"`
	SeriesID       string           `spanner:"SeriesID"`
	BaseBuildID    string           `spanner:"BaseBuildID"`
	PatchedBuildID string           `spanner:"PatchedBuildID"`
	StartedAt      spanner.NullTime `spanner:"StartedAt"`
	FinishedAt     spanner.NullTime `spanner:"FinishedAt"`
}

const (
	TestPassed     string = "passed"
	TestFailed     string = "failed"
	TestError      string = "error"
	TestInProgress string = "in_progress"
)

type SessionTest struct {
	SessionID  string           `spanner:"SessionID"`
	Name       string           `spanner:"Name"`
	JobKey     string           `spanner:"JobKey"`
	StartedAt  time.Time        `spanner:"StartedAt"`
	FinishedAt spanner.NullTime `spanner:"FinishedAt"`
	Result     string           `spanner:"Result"`
}

type Crash struct {
	ID            string `spanner:"ID"`
	SessionID     string `spanner:"SessionID"`
	TestName      string `spanner:"TestName"`
	Title         string `spanner:"Title"`
	ReportURI     string `spanner:"ReportURI"`
	ConsoleLogURI string `spanner:"ConsoleLogURI"`
}
