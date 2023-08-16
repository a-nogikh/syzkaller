package syzbotstats

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBugStateFixed(t *testing.T) {
	summary := BugStatSummary{
		ReleasedTime:    time.Date(2009, time.January, 1, 0, 0, 0, 0, time.UTC),
		ReproTime:       time.Date(2009, time.January, 5, 0, 0, 0, 0, time.UTC),
		CauseBisectTime: time.Date(2009, time.January, 15, 0, 0, 0, 0, time.UTC),
		ResolvedTime:    time.Date(2009, time.March, 10, 0, 0, 0, 0, time.UTC),
		Status:          BugFixed,
		Strace:          true,
	}

	now := time.Date(2009, time.May, 1, 0, 0, 0, 0, time.UTC)
	states := GetBugStates(summary, now)
	assert.Equal(t, []BugState{
		{
			Time:        summary.ReleasedTime,
			Repro:       false,
			CauseBisect: false,
			Duration:    time.Hour * 24 * 4,
		},
		{
			Time:        summary.ReproTime,
			Repro:       true,
			CauseBisect: false,
			Duration:    time.Hour * 24 * 10,
			Strace:      true,
		},
		{
			Time:        summary.CauseBisectTime,
			Repro:       true,
			CauseBisect: true,
			Duration:    summary.ResolvedTime.Sub(summary.CauseBisectTime),
			Strace:      true,
		},
	}, states)
}

func TestBugStatePending(t *testing.T) {
	summary := BugStatSummary{
		ReleasedTime: time.Date(2009, time.January, 1, 0, 0, 0, 0, time.UTC),
		ReproTime:    time.Date(2009, time.January, 5, 0, 0, 0, 0, time.UTC),
		Status:       BugPending,
		Strace:       true,
	}

	now := time.Date(2009, time.May, 1, 0, 0, 0, 0, time.UTC)
	states := GetBugStates(summary, now)
	assert.Equal(t, []BugState{
		{
			Time:        summary.ReleasedTime,
			Repro:       false,
			CauseBisect: false,
			Duration:    time.Hour * 24 * 4,
		},
		{
			Time:        summary.ReproTime,
			Repro:       true,
			CauseBisect: false,
			Duration:    now.Sub(summary.ReproTime),
			Strace:      true,
		},
	}, states)
}

func TestBugStateFixedSoon(t *testing.T) {
	summary := BugStatSummary{
		ReleasedTime:    time.Date(2009, time.January, 1, 0, 0, 0, 0, time.UTC),
		ReproTime:       time.Date(2009, time.January, 10, 0, 0, 0, 0, time.UTC),
		CauseBisectTime: time.Date(2009, time.January, 20, 0, 0, 0, 0, time.UTC),
		ResolvedTime:    time.Date(2009, time.January, 5, 0, 0, 0, 0, time.UTC),
		Status:          BugFixed,
		Strace:          true,
	}

	now := time.Date(2009, time.May, 1, 0, 0, 0, 0, time.UTC)
	states := GetBugStates(summary, now)
	assert.Equal(t, []BugState{
		{
			Time:        summary.ReleasedTime,
			Repro:       false,
			CauseBisect: false,
			Duration:    time.Hour * 24 * 4,
		},
	}, states)
}

func TestBugStateReminders(t *testing.T) {
	reminder1 := time.Date(2009, time.February, 1, 0, 0, 0, 0, time.UTC)
	reminder2 := time.Date(2009, time.March, 1, 0, 0, 0, 0, time.UTC)
	summary := BugStatSummary{
		ReleasedTime: time.Date(2009, time.January, 1, 0, 0, 0, 0, time.UTC),
		Status:       BugPending,
		Strace:       true,
		ReminderTimes: []time.Time{
			reminder1,
			reminder2,
		},
	}

	now := time.Date(2009, time.May, 1, 0, 0, 0, 0, time.UTC)
	states := GetBugStates(summary, now)
	assert.Equal(t, []BugState{
		{
			Time:        summary.ReleasedTime,
			Repro:       false,
			CauseBisect: false,
			Duration:    reminder1.Sub(summary.ReleasedTime),
		},
		{
			Time:        reminder1,
			Repro:       false,
			CauseBisect: false,
			Reminders:   1,
			Duration:    reminder2.Sub(reminder1),
		},
		{
			Time:        reminder2,
			Repro:       false,
			CauseBisect: false,
			Reminders:   2,
			Duration:    now.Sub(reminder2),
		},
	}, states)
}
