// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

type newDiscussionMessage struct {
	id        string
	subject   string
	msgSource dashapi.DiscussionSource
	msgType   dashapi.DiscussionType
	bugID     string
	inReplyTo string
	external  bool
	time      time.Time
}

// saveDiscussionMessage is meant to be called after each received E-mail message,
// for which we know the BugID.
func saveDiscussionMessage(c context.Context, msg *newDiscussionMessage) error {
	discUpdate := &dashapi.Discussion{
		Source: msg.msgSource,
		Type:   msg.msgType,
		BugIDs: []string{msg.bugID},
	}
	if msg.inReplyTo != "" {
		d, err := discussionByMessageID(c, msg.msgSource, msg.inReplyTo)
		if err == nil {
			discUpdate.ID = d.ID
			discUpdate.Type = dashapi.DiscussionType(d.Type)
		}
		// If the original discussion is not in the DB, it means we
		// were likely only mentioned in some further discussion.
		// Remember then only the sub-thread visible to us.
	}
	if discUpdate.ID == "" {
		// Use the current message as the discussion's head.
		discUpdate.ID = msg.id
		discUpdate.Subject = msg.subject
	}
	discUpdate.Messages = append(discUpdate.Messages, dashapi.DiscussionMessage{
		ID:       msg.id,
		Time:     msg.time,
		External: msg.external,
	})
	return mergeDiscussion(c, discUpdate)
}

// mergeDiscussion either creates a new discussion or updates the existing one.
// It is assumed that the input is valid.
func mergeDiscussion(c context.Context, update *dashapi.Discussion) error {
	// First update the discussion itself.
	d := new(Discussion)
	tx := func(c context.Context) error {
		err := db.Get(c, discussionKey(c, string(update.Source), update.ID), d)
		if err != nil && err != db.ErrNoSuchEntity {
			return fmt.Errorf("failed to query Discussion: %w", err)
		} else if err == db.ErrNoSuchEntity {
			d.ID = update.ID
			d.Source = string(update.Source)
			d.Type = string(update.Type)
			d.Subject = update.Subject
		}
		d.BugIDs = unique(append(d.BugIDs, update.BugIDs...))
		d.addMessages(update.Messages)
		if len(d.Messages) == 0 {
			return fmt.Errorf("discussion with no messages")
		}
		_, err = db.Put(c, d.key(c), d)
		if err != nil {
			return fmt.Errorf("failed to put Discussion: %w", err)
		}
		return nil
	}
	err := db.RunInTransaction(c, tx, &db.TransactionOptions{Attempts: 10})
	if err != nil {
		return err
	}
	// Update bug reporting entries in separate transactions.
	// It's bad, but not critical if the program is killed somewhere in between.
	for _, id := range d.BugIDs {
		// datastore does not let us do non-ancestor queries inside a transaction,
		// so we have to first query the bug key, and then query the bug again.
		_, bugKey, err := findBugByReportingID(c, id)
		if err != nil {
			return fmt.Errorf("failed to find bug: %w", err)
		}
		err = db.RunInTransaction(c, func(c context.Context) error {
			bug := new(Bug)
			if err := db.Get(c, bugKey, bug); err != nil {
				return fmt.Errorf("failed to get bug: %w", err)
			}
			rep, _ := bugReportingByID(bug, id)
			rep.updateDiscussionInfo(d)
			_, err = db.Put(c, bugKey, bug)
			if err != nil {
				return fmt.Errorf("failed to put bug: %w", err)
			}
			return nil
		}, &db.TransactionOptions{Attempts: 10})
		if err != nil {
			log.Errorf(c, "failed to update discussions in BugReport: %v", err)
		}
	}
	return nil
}

func unique(items []string) []string {
	dup := map[string]struct{}{}
	ret := []string{}
	for _, item := range items {
		if _, ok := dup[item]; ok {
			continue
		}
		dup[item] = struct{}{}
		ret = append(ret, item)
	}
	return ret
}

func (b *BugReporting) discussions() []*BugReportingDiscussion {
	ret := []*BugReportingDiscussion{}
	if b.DiscussionsJSON == nil || json.Unmarshal(b.DiscussionsJSON, &ret) != nil {
		// In case of error let's just pretend there exist no discussions.
		return nil
	}
	return ret
}

func (b *BugReporting) updateDiscussionInfo(d *Discussion) error {
	var info *BugReportingDiscussion
	discussions := b.discussions()
	for _, obj := range discussions {
		if obj.Source == d.Source && obj.ID == d.ID {
			info = obj
			break
		}
	}
	if info == nil {
		discussions = append(discussions, &BugReportingDiscussion{
			ID:      d.ID,
			Source:  d.Source,
			Type:    d.Type,
			Subject: d.Subject,
		})
		info = discussions[len(discussions)-1]
	}
	info.ExternalMessages = d.ExternalMessages
	info.AllMessages = d.AllMessages
	info.LastMessage = d.Messages[len(d.Messages)-1].Time
	// Now we need to pack the data.
	var err error
	b.DiscussionsJSON, err = json.Marshal(discussions)
	return err
}

func (d *Discussion) messageIDs() map[string]struct{} {
	ret := map[string]struct{}{}
	for _, m := range d.Messages {
		ret[m.ID] = struct{}{}
	}
	return ret
}

const maxMessagesInDiscussion = 1500

func (d *Discussion) addMessages(messages []dashapi.DiscussionMessage) {
	existingIDs := d.messageIDs()
	for _, m := range messages {
		if _, ok := existingIDs[m.ID]; ok {
			continue
		}
		existingIDs[m.ID] = struct{}{}
		d.AllMessages++
		if m.External {
			d.ExternalMessages++
		}
		d.Messages = append(d.Messages, DiscussionMessage{
			ID:       m.ID,
			External: m.External,
			Time:     m.Time,
		})
	}
	sort.Slice(d.Messages, func(i, j int) bool {
		return d.Messages[i].Time.Before(d.Messages[j].Time)
	})
	if len(d.Messages) > maxMessagesInDiscussion {
		d.Messages = d.Messages[len(d.Messages)-maxMessagesInDiscussion:]
	}
}

func discussionURL(source dashapi.DiscussionSource, id string) string {
	switch source {
	case dashapi.DiscussionLore:
		return fmt.Sprintf("https://lore.kernel.org/all/%s/T/",
			strings.Trim(id, "<>"))
	}
	return ""
}

func discussionByMessageID(c context.Context, source dashapi.DiscussionSource,
	msgID string) (*Discussion, error) {
	var discussions []*Discussion
	keys, err := db.NewQuery("Discussion").
		Filter("Source=", source).
		Filter("Messages.ID=", msgID).
		Limit(2).
		GetAll(c, &discussions)
	if err != nil {
		return nil, err
	} else if len(keys) == 0 {
		return nil, db.ErrNoSuchEntity
	} else if len(keys) == 2 {
		return nil, fmt.Errorf("message %s is present in several discussions", msgID)
	}
	return discussions[0], nil
}
