// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseSingle(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	const execLog = `getpid()
gettid()	
`
	entries := target.ParseLog([]byte(execLog), NonStrict)
	if len(entries) != 1 {
		t.Fatalf("got %v programs, want 1", len(entries))
	}
	ent := entries[0]
	if ent.Start != 0 {
		t.Fatalf("start offset %v, want 0", ent.Start)
	}
	if ent.End != len(execLog) {
		t.Fatalf("end offset %v, want %v", ent.End, len(execLog))
	}
	if ent.Proc != 0 {
		t.Fatalf("proc %v, want 0", ent.Proc)
	}
	if ent.P.RequiredFeatures().FaultInjection {
		t.Fatalf("fault injection enabled")
	}
	want := "getpid-gettid"
	got := ent.P.String()
	if got != want {
		t.Fatalf("bad program: %s, want %s", got, want)
	}
}

func TestParseMulti(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	entries := target.ParseLog([]byte(execLogNew), NonStrict)
	validateProgs(t, entries, len(execLogNew))
	if entries[0].ID != -1 ||
		entries[1].ID != 70 ||
		entries[2].ID != 75 ||
		entries[3].ID != 80 ||
		entries[4].ID != 85 {
		t.Fatalf("bad IDs")
	}
	require.False(t, entries[0].HasTime)
	require.Equal(t, time.Duration(0), entries[0].Time)
	require.True(t, entries[1].HasTime)
	require.Equal(t, 15133581935*time.Nanosecond, entries[1].Time)
	require.True(t, entries[4].HasTime)
	require.Equal(t, 12133581935*time.Nanosecond, entries[4].Time)
}

func TestParseMultiLegacy(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	entries := target.ParseLog([]byte(execLogOld), NonStrict)
	validateProgs(t, entries, len(execLogOld))
	for _, ent := range entries {
		require.Equal(t, -1, ent.ID)
		require.False(t, ent.HasTime)
		require.Equal(t, time.Duration(0), ent.Time)
	}
}

func TestParseLogTimings(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("test", "64")
	require.NoError(t, err)

	tests := []struct {
		name     string
		log      string
		wantHas  []bool
		wantTime []time.Duration
	}{
		{
			name: "RelativeSimple",
			log: `
15.5s ago: executing program 1 (id=70):
test$res0()
2.5s ago: executing program 2 (id=71):
test$res0()
0s ago: executing program 1 (id=72):
test$res0()
`,
			wantHas:  []bool{true, true, true},
			wantTime: []time.Duration{15500 * time.Millisecond, 2500 * time.Millisecond, 0},
		},
		{
			name: "RelativeCompound",
			log: `
38m31.024071087s ago: executing program 1 (id=70):
test$res0()
1h2m3s ago: executing program 2 (id=71):
test$res0()
0s ago: executing program 1 (id=72):
test$res0()
`,
			wantHas: []bool{true, true, true},
			wantTime: []time.Duration{
				38*time.Minute + 31024071087*time.Nanosecond,
				1*time.Hour + 2*time.Minute + 3*time.Second,
				0,
			},
		},
		{
			name: "LegacyAndNoTimings",
			log: `
executing program 1:
test$res0()
2015/12/21 12:18:05 executing program 2:
test$res0()
`,
			wantHas:  []bool{false, false},
			wantTime: []time.Duration{0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := target.ParseLog([]byte(tt.log), NonStrict)
			require.Len(t, entries, len(tt.wantHas))
			for i, ent := range entries {
				require.Equal(t, tt.wantHas[i], ent.HasTime)
				require.Equal(t, tt.wantTime[i], ent.Time)
			}
		})
	}
}

func validateProgs(t *testing.T, entries []*LogEntry, logLen int) {
	for i, ent := range entries {
		t.Logf("program #%v: %v", i, ent.P)
	}
	if len(entries) != 5 {
		t.Fatalf("got %v programs, want 5", len(entries))
	}
	off := 0
	for _, ent := range entries {
		if off > ent.Start || ent.Start > ent.End || ent.End > logLen {
			t.Fatalf("bad offsets")
		}
		off = ent.End
	}
	if entries[0].Proc != 0 ||
		entries[1].Proc != 1 ||
		entries[2].Proc != 2 ||
		entries[3].Proc != 33 ||
		entries[4].Proc != 9 {
		t.Fatalf("bad procs")
	}
	for i, ent := range entries {
		if ent.P.RequiredFeatures().FaultInjection {
			t.Fatalf("prog %v has fault injection enabled", i)
		}
	}
	if s := entries[0].P.String(); s != "getpid-gettid" {
		t.Fatalf("bad program 0: %s", s)
	}
	if s := entries[1].P.String(); s != "getpid-gettid-munlockall" {
		t.Fatalf("bad program 0: %s", s)
	}
	if s := entries[2].P.String(); s != "getpid-gettid" {
		t.Fatalf("bad program 1: %s", s)
	}
	if s := entries[3].P.String(); s != "gettid-getpid" {
		t.Fatalf("bad program 2: %s", s)
	}
	if s := entries[4].P.String(); s != "munlockall" {
		t.Fatalf("bad program 3: %s", s)
	}
}

const execLogNew = `
getpid()
gettid()
15.133581935s ago: executing program 1 (id=70):
getpid()
[ 2351.935478] Modules linked in:
gettid()
munlockall()
14.133581935s ago: executing program 2 (id=75):
[ 2351.935478] Modules linked in:
getpid()
gettid()
13.133581935s ago: executing program 33 (id=80):
gettid()
getpid()
[ 2351.935478] Modules linked in:
12.133581935s ago: executing program 9 (id=85):
munlockall()
`

// Logs before the introduction of rpcserver.LastExecuting.
const execLogOld = `
getpid()
gettid()
2015/12/21 12:18:05 executing program 1:
getpid()
[ 2351.935478] Modules linked in:
gettid()
munlockall()
2015/12/21 12:18:05 executing program 2:
[ 2351.935478] Modules linked in:
getpid()
gettid()
2015/12/21 12:18:05 executing program 33:
gettid()
getpid()
[ 2351.935478] Modules linked in:
2015/12/21 12:18:05 executing program 9:
munlockall()
`

func TestParseFault(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	const execLog = `2015/12/21 12:18:05 executing program 1 (fault-call:1 fault-nth:55):
gettid()
getpid()
`
	entries := target.ParseLog([]byte(execLog), NonStrict)
	if len(entries) != 1 {
		t.Fatalf("got %v programs, want 1", len(entries))
	}
	ent := entries[0]
	faultCall := ent.P.Calls[1]
	normalCall := ent.P.Calls[0]
	if faultCall.Props.FailNth != 56 {
		// We want 56 (not 55!) because the number is now not 0-based.
		t.Fatalf("fault nth on the 2nd call: got %v, want 56", faultCall.Props.FailNth)
	}
	if normalCall.Props.FailNth != 0 {
		t.Fatalf("fault nth on the 1st call: got %v, want 0", normalCall.Props.FailNth)
	}
	want := "gettid-getpid"
	got := ent.P.String()
	if got != want {
		t.Fatalf("bad program: %s, want %s", got, want)
	}
}
