package syzbotstats

import "time"

type BugStatSummary struct {
	Title           string
	IDs             []string
	ReleasedTime    time.Time
	ReproTime       time.Time
	CauseBisectTime time.Time
	ResolvedTime    time.Time
	Status          BugStatus
	Subsystems      []string

	// Various stat data.
	Strace     bool
	Assets     bool
	HitsPerDay float64
}

type BugStatus string

const (
	BugFixed           BugStatus = "fixed"
	BugInvalidated     BugStatus = "invalidated"
	BugAutoInvalidated BugStatus = "auto-invalidated"
	BugDup             BugStatus = "dup"
	BugPending         BugStatus = "pending"
)
