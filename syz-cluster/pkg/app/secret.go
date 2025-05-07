// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package app

import (
	"context"
	"fmt"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type SecretKey string

const (
	SecretSMTPHost     SecretKey = "smtp_host"
	SecretSMTPPort     SecretKey = "smtp_port"
	SecretSMTPUser     SecretKey = "smtp_user"
	SecretSMTPPassword SecretKey = "smtp_password"
)

type SecretManager interface {
	Get(context.Context, SecretKey) (string, error)
}

// GCPSecretManager lazily queries and caches the secret values.
// TODO: should we be refreshing the values once in a while?
type GCPSecretManager struct {
	client      *secretmanager.Client
	projectName string
	values      sync.Map
}

type secretRecord struct {
	mu     sync.Mutex
	val    string
	loaded bool
}

func NewGCPSecretManager(ctx context.Context, projectName string) (*GCPSecretManager, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &GCPSecretManager{
		client:      client,
		projectName: projectName,
	}, nil
}

func (sm *GCPSecretManager) Get(ctx context.Context, key SecretKey) (string, error) {
	recordObj, _ := sm.values.LoadOrStore(key, &secretRecord{})
	record := recordObj.(*secretRecord)
	record.mu.Lock()
	defer record.mu.Unlock()

	if record.loaded {
		return record.val, nil
	}

	result, err := sm.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", sm.projectName, key),
	})
	if err != nil {
		return "", err
	}
	record.val = string(result.Payload.Data)
	record.loaded = true
	return record.val, nil
}
