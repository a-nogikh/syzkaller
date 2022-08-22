package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
)

type Stats interface {
	Record(input *statsInput)
	Collect() interface{}
}

type statsFilterStruct struct {
	nested  Stats
	filters []func(input *statsInput) bool
}

func statsFilter(nested Stats, filters ...func(input *statsInput) bool) Stats {
	return &statsFilterStruct{nested: nested, filters: filters}
}

func (sf *statsFilterStruct) Record(input *statsInput) {
	for _, filter := range sf.filters {
		if !filter(input) {
			return
		}
	}
	sf.nested.Record(input)
}

func (sf *statsFilterStruct) Collect() interface{} {
	return sf.nested.Collect()
}

type statsInput struct {
	result *fixCommitResult
	group  *lkmlEventGroup
}

type bugState int

const (
	stateOpen bugState = iota
	stateDecisionMade
	stateInvalid
)

func (si *statsInput) foundAt() time.Time {
	return si.result.bug.BuildTime
}

func (si *statsInput) reportedAt() time.Time {
	if si.group == nil {
		return time.Time{}
	}
	return si.group.firstReport
}

func (si *statsInput) fixedAt() time.Time {
	if si.result.commitObj != nil {
		return si.result.commitObj.CommitDate
	}
	bug := si.result.bug
	if bug.BugStatus == dashapi.BugStatusFixed {
		return bug.CloseTime
	}
	return time.Time{}
}

func (si *statsInput) stateAt(date time.Time) bugState {
	// Should we take the fixing commit time or the bug closing time??
	bug := si.result.bug
	closeTime := bug.CloseTime
	closeStatus := stateDecisionMade
	if at := si.fixedAt(); !at.IsZero() {
		closeTime = at
	} else if bug.BugStatus == dashapi.BugStatusInvalid {
		if bug.AutoClosed {
			closeStatus = stateInvalid
		}
	}
	if closeTime.IsZero() || date.Before(closeTime) {
		return stateOpen
	}
	return closeStatus
}

type statElement struct {
	closed     int
	total      int
	closedIn60 int
	totalIn60  int
}

func (se *statElement) Record(input *statsInput) {
	checkAt := input.reportedAt().Add(time.Hour * 24 * 100)
	switch input.stateAt(checkAt) {
	case stateDecisionMade:
		se.closedIn60++
		se.totalIn60++
	case stateOpen:
		se.totalIn60++
	}
	switch input.stateAt(time.Now()) {
	case stateInvalid:
		return
	case stateDecisionMade:
		se.closed++
	}
	se.total++
}

func (se *statElement) DefaultOutput() []string {
	if se == nil {
		return []string{"-", "-", "-"}
	}
	return []string{
		fmt.Sprintf("%d", se.totalIn60),
		fmt.Sprintf("%d", se.closedIn60),
		fmt.Sprintf("%.2f", float64(se.closedIn60)/float64(se.totalIn60)*100.0),
	}
}

type PerType struct {
	total    int
	rest     *statElement
	typeStat map[string]*statElement
}

var typePrefixes = []string{
	"INFO", "WARNING", "BUG", "general protection fault", "memory leak",
	"KASAN", "KMSAN", "possible deadlock", "divide error", "panic", "UBSAN",
	"kernel BUG",
}

func newPerType() *PerType {
	return &PerType{
		typeStat: map[string]*statElement{},
		rest:     &statElement{},
	}
}

func (s *PerType) Record(input *statsInput) {
	found := false
	for _, prefix := range typePrefixes {
		if strings.HasPrefix(input.result.bug.Title, prefix) {
			if s.typeStat[prefix] == nil {
				s.typeStat[prefix] = &statElement{}
			}
			s.typeStat[prefix].Record(input)
			found = true
			break
		}
	}
	s.total++
	if !found {
		s.rest.Record(input)
	}
}

func (s *PerType) Collect() interface{} {
	table := [][]string{[]string{"Type", "Total", "Solved in 60 days", "%"}}
	record := func(prefix string, info *statElement) {
		table = append(table, append([]string{prefix}, info.DefaultOutput()...))
	}
	for prefix, info := range s.typeStat {
		record(prefix, info)
	}
	record("THE REST", s.rest)
	return table
}

type PerHour struct {
	hours map[int]*statElement
}

func newPerHour() *PerHour {
	return &PerHour{hours: map[int]*statElement{}}
}

func (s *PerHour) Record(input *statsInput) {
	hour := input.reportedAt().Hour()
	if s.hours[hour] == nil {
		s.hours[hour] = &statElement{}
	}
	s.hours[hour].Record(input)
}

func (s *PerHour) Collect() interface{} {
	table := [][]string{[]string{"Type", "Total", "Solved in 60 days", "%"}}
	for hour := 0; hour < 24; hour++ {
		info := s.hours[hour]
		if info == nil {
			continue
		}
		table = append(table, append([]string{
			fmt.Sprintf("%d", hour),
		}, info.DefaultOutput()...))
	}
	return table
}

type PerRepro struct {
	with    statElement
	without statElement
}

func (s *PerRepro) Record(input *statsInput) {
	if input.result.bug.ReproSyz != nil {
		s.with.Record(input)
	} else {
		s.without.Record(input)
	}
}

func (s *PerRepro) Collect() interface{} {
	table := [][]string{
		[]string{"Repro", "Total", "Solved in 60 days", "%"},
		append([]string{"Yes"}, s.with.DefaultOutput()...),
		append([]string{"No"}, s.without.DefaultOutput()...),
	}
	return table
}

type ClosedGraph struct {
	never       int
	immediately int
	daysOpen    []int
	daysTotal   int
}

func newClosedGraph(days int) Stats {
	return &ClosedGraph{daysTotal: days}
}

func (s *ClosedGraph) Record(input *statsInput) {
	bug := input.result.bug
	closeTime := bug.CloseTime
	if bug.BugStatus == dashapi.BugStatusInvalid {
		if bug.AutoClosed {
			s.never++
			return
		}
	} else if at := input.fixedAt(); !at.IsZero() {
		closeTime = at
	}
	if closeTime.IsZero() {
		s.never++
	} else if input.reportedAt().After(closeTime) {
		s.immediately++
	} else {
		hours := closeTime.Sub(input.reportedAt()).Hours()
		if hours < 0 {
			fmt.Printf("closed at %v, reported at %v", closeTime, input.reportedAt())
			panic("")
		}
		days := int(math.Floor(hours / 24.0))
		s.daysOpen = append(s.daysOpen, days)
	}
}

func (s *ClosedGraph) Collect() interface{} {
	buckets := make([]int, s.daysTotal)
	for _, days := range s.daysOpen {
		if days >= len(buckets) {
			continue
		}
		buckets[days]++
	}

	total := len(s.daysOpen) + s.never + s.immediately
	acc := s.immediately

	table := [][]string{[]string{"Day", "Total", "Fixed", "Share"}}
	for d, fixed := range buckets {
		acc += fixed
		table = append(table, []string{
			fmt.Sprintf("%d", d+1),
			fmt.Sprintf("%d", total),
			fmt.Sprintf("%d", acc),
			fmt.Sprintf("%.2f", float64(acc)/float64(total)*100.0),
		})
	}
	return table
}

type perYearStat struct {
	found       int
	reported    int
	fixed       int
	invalidated int
}

type perYear struct {
	years map[int]*perYearStat
}

func newPerYear() Stats {
	return &perYear{years: map[int]*perYearStat{}}
}

func (s *perYear) Record(input *statsInput) {
	year := input.foundAt().Year()
	stat := s.years[year]
	if stat == nil {
		stat = &perYearStat{}
		s.years[year] = stat
	}
	stat.found++
	if at := input.fixedAt(); !at.IsZero() {
		stat.fixed++
	}
	if at := input.reportedAt(); !at.IsZero() {
		stat.reported++
	}
}

func (s *perYear) Collect() interface{} {
	table := [][]string{[]string{"Year", "Found", "Reported", "Fixed"}}
	for year := 2000; year <= time.Now().Year(); year++ {
		stat := s.years[year]
		if stat == nil {
			continue
		}
		table = append(table, []string{
			fmt.Sprintf("%d", year),
			fmt.Sprintf("%d", stat.found),
			fmt.Sprintf("%d", stat.reported),
			fmt.Sprintf("%d", stat.fixed),
		})
	}
	return table
}

type reproStat struct {
	total int
	ok    int
}

func (rs reproStat) Add(other reproStat) reproStat {
	return reproStat{
		total: rs.total + other.total,
		ok:    rs.ok + other.ok,
	}
}

func (rs reproStat) Sub(other reproStat) reproStat {
	return reproStat{
		total: rs.total - other.total,
		ok:    rs.ok - other.ok,
	}
}

type slidingShare struct {
	perDay   map[time.Time]reproStat
	okFilter func(*statsInput) bool
}

func newSlidingShare(okFilter func(*statsInput) bool) Stats {
	return &slidingShare{
		perDay:   map[time.Time]reproStat{},
		okFilter: okFilter,
	}
}

func newSlidingReproRate() Stats {
	return newSlidingShare(func(input *statsInput) bool {
		return input.result.bug.ReproSyz != nil
	})
}

func (s *slidingShare) Record(input *statsInput) {
	add := reproStat{total: 1}
	if s.okFilter(input) {
		add.ok = 1
	}
	date := input.foundAt().Truncate(24 * time.Hour)
	s.perDay[date] = s.perDay[date].Add(add)
}

func (s *slidingShare) Collect() interface{} {
	type item struct {
		date time.Time
		stat reproStat
	}
	ordered := []item{}
	for day, stat := range s.perDay {
		ordered = append(ordered, item{date: day, stat: stat})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].date.Before(ordered[j].date) })

	const windowSize = 100 * time.Hour * 24
	current := reproStat{}
	table := [][]string{[]string{"Day", "Total", "Ok", "Share"}}
	nextRemove := 0
	for i, obj := range ordered {
		current = current.Add(obj.stat)
		for nextRemove < len(ordered) &&
			obj.date.Sub(ordered[nextRemove].date) > windowSize {
			current = current.Sub(ordered[nextRemove].stat)
			nextRemove++
		}
		if i%7 != 6 {
			continue
		}
		table = append(table, []string{
			obj.date.Format("2006-01-02"),
			fmt.Sprintf("%d", current.total),
			fmt.Sprintf("%d", current.ok),
			fmt.Sprintf("%.2f", float64(current.ok)/float64(current.total)*100.0),
		})
	}
	return table
}

type currReproStats struct {
	reproSyz int
	reproC   int
	noRepro  int
}

func (s *currReproStats) Record(input *statsInput) {
	bug := input.result.bug
	if bug.ReproC != nil {
		s.reproC++
	} else if bug.ReproSyz != nil {
		s.reproSyz++
	} else {
		s.noRepro++
	}
}

func (s *currReproStats) Collect() interface{} {
	return [][]string{
		[]string{"Type", "Count"},
		[]string{"With C repro", fmt.Sprintf("%d", s.reproC)},
		[]string{"With syz repro", fmt.Sprintf("%d", s.reproSyz)},
		[]string{"No repro", fmt.Sprintf("%d", s.noRepro)},
	}
}

type currBisectStats struct {
	forFixes     bool
	success      int
	inconclusive int
	notAttempted int
}

func (s *currBisectStats) Record(input *statsInput) {
	info := input.result.bug.BisectCause
	if s.forFixes {
		info = input.result.bug.BisectFix
	}
	if info == nil {
		s.notAttempted++
	} else if info.Commit != nil {
		s.success++
	} else {
		s.inconclusive++
	}
}

func (s *currBisectStats) Collect() interface{} {
	return [][]string{
		[]string{"Type", "Count"},
		[]string{"Success", fmt.Sprintf("%d", s.success)},
		[]string{"Inconclusive", fmt.Sprintf("%d", s.inconclusive)},
		[]string{"No attempted", fmt.Sprintf("%d", s.notAttempted)},
	}
}
