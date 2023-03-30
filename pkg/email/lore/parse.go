// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"io"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

type Thread struct {
	Subject   string
	MessageID string
	BugIDs    []string
	Messages  []*Message
}

type Message struct {
	ID        string
	BugIDs    []string
	Subject   string
	Date      time.Time
	From      string
	InReplyTo string
}

type Collection struct {
	messages   map[string]*Message
	bugPattern *regexp.Regexp
}

func MakeCollection(bugPattern *regexp.Regexp) *Collection {
	return &Collection{
		messages:   map[string]*Message{},
		bugPattern: bugPattern,
	}
}

func (c *Collection) Record(msg *mail.Message) {
	date, err := mail.ParseDate(msg.Header.Get("Date"))
	if err != nil {
		// Let's just silently ignore parsing errors.
		// The archive is big and there will definitely be problematic messages.
		return
	}
	msgID := msg.Header.Get("Message-ID")
	if msgID == "" {
		return
	}
	var bugIDs []string
	if c.bugPattern != nil {
		body, err := io.ReadAll(msg.Body)
		if err != nil {
			return
		}
		// Combine some headers and body.
		var sb strings.Builder
		sb.WriteString(msg.Header.Get("From"))
		sb.WriteString("\n")
		sb.WriteString(msg.Header.Get("To"))
		sb.WriteString("\n")
		sb.WriteString(msg.Header.Get("Cc"))
		sb.WriteString("\n")
		sb.Write(body)

		matches := c.bugPattern.FindAllStringSubmatch(sb.String(), -1)
		for _, match := range matches {
			// Take all non-empty group matches.
			for i := 1; i < len(match); i++ {
				if match[i] == "" {
					continue
				}
				bugIDs = append(bugIDs, match[i])
			}
		}
	}
	c.messages[msgID] = &Message{
		ID:        msgID,
		BugIDs:    bugIDs,
		Subject:   msg.Header.Get("Subject"),
		Date:      date,
		From:      msg.Header.Get("From"),
		InReplyTo: msg.Header.Get("In-Reply-To"),
	}
}

func (c *Collection) Threads() []*Thread {
	threads := map[string]*Thread{}
	threadsList := []*Thread{}
	// Detect threads, i.e. messages without In-Reply-To.
	for _, msg := range c.messages {
		if msg.InReplyTo == "" {
			thread := &Thread{
				MessageID: msg.ID,
				Subject:   msg.Subject,
			}
			threads[msg.ID] = thread
			threadsList = append(threadsList, thread)
		}
	}
	// Assign messages to threads.
	for _, msg := range c.messages {
		base := c.first(msg)
		if base == nil {
			continue
		}
		thread := threads[base.ID]
		thread.BugIDs = append(thread.BugIDs, msg.BugIDs...)
		thread.Messages = append(threads[base.ID].Messages, msg)
	}
	// Deduplicate BugIDs lists.
	for _, thread := range threads {
		if len(thread.BugIDs) == 0 {
			continue
		}
		unique := map[string]struct{}{}
		newList := []string{}
		for _, id := range thread.BugIDs {
			if _, ok := unique[id]; !ok {
				newList = append(newList, id)
			}
			unique[id] = struct{}{}
		}
		thread.BugIDs = newList
	}
	return threadsList
}

// first finds the firt message of an email thread.
func (c *Collection) first(msg *Message) *Message {
	visited := map[*Message]struct{}{}
	for {
		// There have been a few cases when we'd otherwise get an infinite loop.
		if _, ok := visited[msg]; ok {
			return nil
		}
		visited[msg] = struct{}{}
		if msg.InReplyTo == "" {
			return msg
		}
		msg = c.messages[msg.InReplyTo]
		if msg == nil {
			// Probably we just didn't load the message.
			return nil
		}
	}
}
