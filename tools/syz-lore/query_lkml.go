// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"log"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"golang.org/x/sync/errgroup"
)

// The syz-lore tool can parse Lore archives and extract syzbot-related conversations from there.

var (
	flagArchives  = flag.String("archives", "", "path to the folder with git archives")
	flagDashboard = flag.String("dashboard", "https://syzkaller.appspot.com", "dashboard address")
	flagAPIClient = flag.String("client", "", "the name of the API client")
	flagAPIKey    = flag.String("key", "", "api key")
	flagVerbose   = flag.Bool("v", false, "print more debug info")
)

func main() {
	defer tool.Init()()
	if !osutil.IsDir(*flagArchives) {
		tool.Failf("the arhives parameter must be a valid directory")
	}
	dash, err := dashapi.New(*flagAPIClient, *flagDashboard, *flagAPIKey)
	if err != nil {
		tool.Failf("dashapi failed: %v", err)
	}
	threads := processArchives(*flagArchives)
	for i, thread := range threads {
		messages := []dashapi.DiscussionMessage{}
		for _, m := range thread.Messages {
			messages = append(messages, dashapi.DiscussionMessage{
				ID: m.ID,
				External: !strings.Contains(m.From, "syzbot") &&
					!strings.Contains(m.From, "syzkaller"),
				Time: m.Date,
			})
		}
		discType := dashapi.DiscussionReport
		if strings.Contains(thread.Subject, "PATCH") {
			discType = dashapi.DiscussionPatch
		}
		log.Printf("saving %d/%d", i+1, len(threads))
		err := dash.SaveDiscussion(&dashapi.SaveDiscussionReq{
			Discussion: &dashapi.Discussion{
				ID:       thread.MessageID,
				Source:   dashapi.DiscussionLore,
				Type:     discType,
				Subject:  thread.Subject,
				BugIDs:   thread.BugIDs,
				Messages: messages,
			},
		})
		if err != nil {
			tool.Failf("dashapi failed: %v", err)
		}
	}
}

func processArchives(dir string) []*lore.Thread {
	entries, err := os.ReadDir(dir)
	if err != nil {
		tool.Failf("failed to read directory: %v", err)
	}
	threads := runtime.NumCPU()
	jobs := make(chan lore.Worker)
	messages := make(chan *mail.Message, threads*2)
	g, _ := errgroup.WithContext(context.Background())
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		g.Go(func() error {
			log.Printf("reading %s", path)
			_, err := lore.ReadArchive(path, jobs, messages)
			return err
		})
	}
	parsed := lore.MakeCollection(regexp.MustCompile(`syzbot\+(.*?)@|syzkaller\.appspot\.com\/bug\?extid=([0-9a-f]+)`))
	go func() {
		for msg := range messages {
			parsed.Record(msg)
		}
	}()
	// Set up some worker threads.
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for worker := range jobs {
				worker()
			}
		}()
	}
	if err := g.Wait(); err != nil {
		tool.Failf("failed to read archives: %s", err)
	}
	close(jobs)
	close(messages)
	wg.Wait()

	list := parsed.Threads()
	log.Printf("collected %d email threads", len(list))

	ret := []*lore.Thread{}
	for _, d := range list {
		if d.BugIDs == nil {
			continue
		}
		ret = append(ret, d)
		if *flagVerbose {
			log.Printf("discussion ID=%s BugID=%s Subject=%s Messages=%d",
				d.MessageID, d.BugIDs, d.Subject, len(d.Messages))
		}
	}
	log.Printf("%d threads are related to syzbot", len(ret))
	return ret
}
