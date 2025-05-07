// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/uuid"
)

// TODO: how can we test it?
// Using some STMP server library is probably an overkill?

type smtpSender struct {
	cfg      *app.EmailConfig
	host     string
	port     int
	user     string
	password string
}

func newSender(ctx context.Context, cfg *app.EmailConfig, secretManager app.SecretManager) (*smtpSender, error) {
	values := map[app.SecretKey]string{}
	for _, key := range []app.SecretKey{
		app.SecretSMTPHost, app.SecretSMTPPort, app.SecretSMTPUser, app.SecretSMTPPassword,
	} {
		val, err := secretManager.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("failed to query %v: %w", val, err)
		}
	}
	port, err := strconv.Atoi(values[app.SecretSMTPPort])
	if err != nil {
		return nil, fmt.Errorf("failed to parse SMTP port: not a valid integer")
	}
	return &smtpSender{
		cfg:      cfg,
		host:     values[app.SecretSMTPHost],
		port:     port,
		user:     values[app.SecretSMTPUser],
		password: values[app.SecretSMTPPassword],
	}, nil
}

// Send constructs a raw email from EmailToSend and sends it over SMTP.
func (sender *smtpSender) Send(ctx context.Context, item *EmailToSend) (string, error) {
	msgID := fmt.Sprintf("<%s@%s>", uuid.NewString(), sender.host)
	msg := rawEmail(sender.cfg, item, msgID)
	auth := smtp.PlainAuth("", sender.host, sender.password, sender.host)
	smtpAddr := fmt.Sprintf("%s:%d", sender.host, sender.port)
	return msgID, smtp.SendMail(smtpAddr, auth, sender.cfg.Sender, item.recipients(), msg)
}

func (item *EmailToSend) recipients() []string {
	var ret []string
	ret = append(ret, item.To...)
	ret = append(ret, item.Cc...)
	return unique(ret)
}

func unique(list []string) []string {
	var ret []string
	seen := map[string]struct{}{}
	for _, str := range list {
		if _, ok := seen[str]; ok {
			continue
		}
		seen[str] = struct{}{}
		ret = append(ret, str)
	}
	return ret
}

func rawEmail(cfg *app.EmailConfig, item *EmailToSend, id string) []byte {
	var msg bytes.Buffer

	fmt.Fprintf(&msg, "From: %s <%s>\r\n", cfg.Name, cfg.Sender)
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(item.To, ", "))
	if len(item.Cc) > 0 {
		fmt.Fprintf(&msg, "Cc: %s\r\n", strings.Join(item.Cc, ", "))
	}
	fmt.Fprintf(&msg, "Subject: %s\r\n", item.Subject)
	if item.InReplyTo != "" {
		inReplyTo := item.InReplyTo
		if inReplyTo[0] != '<' {
			inReplyTo = "<" + inReplyTo + ">"
		}
		fmt.Fprintf(&msg, "In-Reply-To: %s\r\n", inReplyTo)
	}
	if id != "" {
		if id[0] != '<' {
			id = "<" + id + ">"
		}
		fmt.Fprintf(&msg, "Message-ID: %s\r\n", id)
	}
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	msg.Write(item.Body)
	return msg.Bytes()
}
