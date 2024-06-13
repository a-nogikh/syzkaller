// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import "log"

func filterFixedSeries(state *state) map[string]Series {
	series := state.series.get()
	log.Printf("orig: %d series", len(series))

	// 2022 bugs.
	byDate := filterSeries(series, func(s *Series) bool {
		if len(s.Patches) == 0 {
			return false
		}
		patch := s.Patches[0]
		return patch.Date.Year() == 2022 && patch.Date.Month() <= 6
	})

	log.Printf("2022: %d series", len(byDate))

	fixed := filterSeries(byDate, func(s *Series) bool {
		for _, patch := range s.Patches {
			if len(patch.FixedBy) > 0 {
				return true
			}
		}
		return false
	})

	log.Printf("have fixing commits: %d series", len(fixed))

	take := 512
	ret := map[string]Series{}
	for id, series := range fixed {
		take--
		if take < 0 {
			break
		}

		ret[id] = series
	}
	return ret
}

func seriesStatistics(state *state) {
	series := state.series.get()
	byDate := filterSeries(series, func(s *Series) bool {
		if len(s.Patches) == 0 {
			return false
		}
		patch := s.Patches[0]
		return patch.Date.Year() == 2023
	})

	log.Printf("In 2023, there were %d new series per day", len(byDate)/365)
}
