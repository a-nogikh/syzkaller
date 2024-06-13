// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/gorilla/handlers"
)

//go:embed templates
var templateFs embed.FS
var templates = pages.CreateFromFS(templateFs, "templates/*.html")

func serveHTTP(state *state, exp Experiment) {

	bk := blobKeeper{}

	mux := http.NewServeMux()
	mux.HandleFunc("/view", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id != "" {
			w.Write([]byte(bk.get(id)))
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := viewFromExperiment(exp, state, &bk)
		executeTemplate(w, templates, "experiment.html", data)
	})

	listener, err := net.Listen("tcp", *flagHTTP)
	if err != nil {
		log.Fatalf("failed to listen on %s", *flagHTTP)
	}

	err = http.Serve(listener, handlers.CompressHandler(mux))
	if err != nil {
		log.Fatalf("failed to listen on %v: %v", *flagHTTP, err)
	}
}

func executeTemplate(w http.ResponseWriter, templ *template.Template, name string, data interface{}) {
	buf := new(bytes.Buffer)
	if err := templ.ExecuteTemplate(buf, name, data); err != nil {
		log.Printf("failed to execute template: %v", err)
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

func viewFromExperiment(exp Experiment, state *state, bk *blobKeeper) MainPageView {
	var ret MainPageView
	for _, item := range exp.Results {
		if item.SeriesID == "" {
			continue
		}
		result := exp.getResults(item.Release, "")
		if len(result) != 1 {
			log.Fatalf("no results for %+v", item.Release)
		}
		ret.Records = append(ret.Records, recordView(item, result[0], state, bk))
		if item.ApplyError != "" {
			ret.ApplyErrors++
		}
	}
	ret.Total = len(ret.Records)
	return ret
}

func resultToStatus(row *ExperimentResult) string {
	if row.ApplyError != "" {
		return "git apply error"
	} else if row.BuildError != "" {
		return "build error"
	} else if row.RunError != "" {
		return "run error"
	}
	return fmt.Sprintf("success (%d bugs)", len(row.Bugs))
}

func recordView(row, baseRow *ExperimentResult, state *state, bk *blobKeeper) RecordView {
	var onlyInSeries, onlyInBase []Link
	var fixedBy []Link

	series := state.series.get()
	if info, ok := series[row.SeriesID]; ok {
		for id := range info.AllFixes() {
			fixedBy = append(fixedBy, makeSeriesLink(id))
		}
	}

	if row.Success() {
		for title, blob := range row.Bugs {
			if _, ok := baseRow.Bugs[title]; !ok {
				onlyInSeries = append(onlyInSeries, makeBlobLink(title, blob, bk))
			}
		}
		for title, blob := range baseRow.Bugs {
			if _, ok := row.Bugs[title]; !ok {
				onlyInBase = append(onlyInBase, makeBlobLink(title, blob, bk))
			}
		}
	}
	return RecordView{
		Series:       makeSeriesLink(row.SeriesID),
		SeriesStatus: resultToStatus(row),
		OnlyInSeries: onlyInSeries,
		Base:         row.Release.Tag,
		BaseStatus:   resultToStatus(baseRow),
		OnlyInBase:   onlyInBase,
		FixedBy:      fixedBy,
	}
}

type blobKeeper struct {
	blobs map[string]string
}

func (bk *blobKeeper) save(blob string) string {
	if bk.blobs == nil {
		bk.blobs = map[string]string{}
	}
	id := fmt.Sprint(hashString(blob))
	bk.blobs[id] = blob
	return id
}

func (bk *blobKeeper) get(id string) string {
	return bk.blobs[id]
}

type MainPageView struct {
	Total       int
	ApplyErrors int
	Records     []RecordView
}

type Link struct {
	Name string
	Link string
}

func makeSeriesLink(id string) Link {
	return Link{
		Name: id,
		Link: fmt.Sprintf("http://lore.kernel.org/all/%v", strings.Trim(id, "<>")),
	}
}

func makeBlobLink(name, blob string, bk *blobKeeper) Link {
	return Link{
		Name: name,
		Link: fmt.Sprintf("/view?id=%v", bk.save(blob)),
	}
}

type RecordView struct {
	Series       Link
	FixedBy      []Link
	SeriesURL    string
	SeriesStatus string
	OnlyInSeries []Link
	Base         string
	BaseStatus   string
	OnlyInBase   []Link
}
