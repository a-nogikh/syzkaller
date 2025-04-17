// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// NOTE: This app assumes that only one copy of it is runnning at the same time.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/report"
	"golang.org/x/sync/errgroup"
)

// TODO: we must reply directly to the original patch series emails!

// TODO: UUIDs are too long to be used in email addresses. We need something shorter.

// TODO: add extra sanity checks that would prevent flooding the mailing lists:
// - this pod may crash and be restarted by K8S: this complicates accounting,
// - the send operation might return an error, yet an email would be actually sent: back off on errors?

func main() {
	ctx := context.Background()
	cfg, err := app.Config()
	if err != nil {
		app.Fatalf("failed to load config: %v", err)
	}
	if cfg.EmailReporting == nil {
		app.Fatalf("reporting is not configured: %v", err)
	}
	handler := &Handler{
		ownEmail:     "name@domain.com",
		emailClient:  nil, // TODO: fill
		apiClient:    app.DefaultReporterClient(),
		reportConfig: cfg.EmailReporting,
	}
	handler.Loop(ctx)
}

type EmailToSend struct {
	Sender    string
	To        []string
	Cc        []string
	Subject   string
	InReplyTo string
	Body      []byte
}

type EmailClient interface {
	Send(context.Context, *EmailToSend) error
	// Poll and delete the next received message.
	Poll(context.Context) ([]byte, error)
}

type Handler struct {
	ownEmail     string
	emailClient  EmailClient
	apiClient    *api.ReporterClient
	reportConfig *report.Config
}

func (h *Handler) Loop(baseCtx context.Context) error {
	g, ctx := errgroup.WithContext(baseCtx)
	g.Go(func() error {
		h.newReportsLoop(ctx)
		return nil
	})
	g.Go(func() error {
		h.pollEmailsLoop(ctx)
		return nil
	})
	return g.Wait()
}

func (h *Handler) newReportsLoop(ctx context.Context) {
	const pollPeriod = 30 * time.Second
	for {
		h.pollAndReport(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollPeriod):
		}
	}
}

func (h *Handler) pollAndReport(ctx context.Context) {
	reply, err := h.apiClient.GetNextReport(ctx)
	if err != nil {
		app.Errorf("failed to poll the next report: %v", err)
		return
	}
	if reply.Report == nil {
		return
	}
	rep := reply.Report
	log.Printf("report %q is to be sent", rep.ID)

	// First confirm it - it's better to not actually send than send multiple times.
	err = h.apiClient.ConfirmReport(ctx, rep.ID)
	if err != nil {
		app.Errorf("failed to confirm the report %q: %v", rep.ID, err)
		return
	}

	// Construct and send the message.
	body, err := report.Render(rep, h.reportConfig)
	if err != nil {
		// This should never be happening..
		app.Errorf("failed to render the template for %q: %v", rep.ID, err)
		return
	}
	err = h.emailClient.Send(ctx, &EmailToSend{
		Sender:  "", // TODO: fill
		To:      []string{},
		Cc:      rep.Cc,
		Subject: "", // TODO: add some report.Subject() method.
		Body:    body,
	})
	if err != nil {
		app.Errorf("failed to send the report for %q: %v", rep.ID, err)
		return
	}

	// Now that the report is sent, update the link to the email discussion.
	err = h.apiClient.UpdateReport(ctx, rep.ID, &api.UpdateReportReq{
		Link: "", // TODO: where to take it from?
	})
	if err != nil {
		app.Errorf("failed to update the report %q: %v", rep.ID, err)
	}
}

func (h *Handler) pollEmailsLoop(ctx context.Context) {
	const pollPeriod = 30 * time.Second
	for {
		msg, err := h.emailClient.Poll(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			app.Errorf("failed to poll new emails: %v", err)
		} else if msg != nil {
			h.handleIncomingEmail(ctx, msg)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollPeriod):
		}
	}
}

func (h *Handler) handleIncomingEmail(ctx context.Context, raw []byte) {
	msg, err := email.Parse(bytes.NewReader(raw), []string{h.ownEmail}, nil, nil)
	if err != nil {
		log.Printf("failed to parse an incoming email: %s", err)
		return
	}
	if len(msg.BugIDs) == 0 {
		log.Printf("msg %q: no report ID, skipping", msg.MessageID)
		return
	}
	reportID := msg.BugIDs[0]
	log.Printf("received email %q for report %q", msg.MessageID, reportID)

	var reply string
	for _, command := range msg.Commands {
		switch command.Command {
		case email.CmdUpstream:
			err = h.apiClient.UpstreamReport(ctx, reportID, &api.UpstreamReportReq{
				User: msg.Author,
			})
			if err != nil {
				reply = fmt.Sprintf("Failed to process the command. Contact %s.",
					h.reportConfig.SupportEmail)
			}
			// Reply nothing on success.
		default:
			reply = "Unknown command"
		}
	}
	if reply == "" {
		return
	}

	err = h.emailClient.Send(ctx, &EmailToSend{
		Sender:    "", // TODO
		To:        []string{msg.Author},
		Cc:        []string{}, // TODO
		Subject:   "Re: " + msg.Subject,
		InReplyTo: msg.MessageID,
		Body:      []byte(email.FormReply(msg, reply)),
	})
	if err != nil {
		app.Errorf("failed to reply to %q: %v", msg.MessageID, err)
	}
}
