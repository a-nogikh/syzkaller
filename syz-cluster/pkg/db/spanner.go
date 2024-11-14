// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"cloud.google.com/go/spanner"
	database "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	instance "cloud.google.com/go/spanner/admin/instance/apiv1"
	"cloud.google.com/go/spanner/admin/instance/apiv1/instancepb"
	"google.golang.org/grpc/codes"
)

type ParsedURI struct {
	ProjectPrefix  string // projects/<project>
	InstancePrefix string // projects/<project>/instances/<instance>
	Instance       string
	Database       string
	Full           string
}

func ParseURI(uri string) (ParsedURI, error) {
	ret := ParsedURI{Full: uri}
	matches := regexp.MustCompile(`projects/(.*)/instances/(.*)/databases/(.*)`).FindStringSubmatch(uri)
	if matches == nil || len(matches) != 4 {
		return ret, fmt.Errorf("failed to parse", uri)
	}
	ret.ProjectPrefix = "projects/" + matches[1]
	ret.InstancePrefix = ret.ProjectPrefix + "/instances/" + matches[2]
	ret.Instance = matches[2]
	ret.Database = matches[3]
	return ret, nil
}

func CreateSpannerInstance(ctx context.Context, uri ParsedURI) error {
	client, err := instance.NewInstanceAdminClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.GetInstance(ctx, &instancepb.GetInstanceRequest{
		Name: uri.InstancePrefix,
	})
	if err != nil && spanner.ErrCode(err) == codes.NotFound {
		log.Printf("Creating a Spanner instance")
		_, err = client.CreateInstance(ctx, &instancepb.CreateInstanceRequest{
			Parent:     uri.ProjectPrefix,
			InstanceId: uri.Instance,
		})
		return err
	}
	return err
}

func CreateSpannerDB(ctx context.Context, uri ParsedURI) error {
	client, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.GetDatabase(ctx, &databasepb.GetDatabaseRequest{Name: uri.Full})
	if err != nil && spanner.ErrCode(err) == codes.NotFound {
		log.Printf("Creating a Spanner DB")
		op, err := client.CreateDatabase(ctx, &databasepb.CreateDatabaseRequest{
			Parent:          uri.InstancePrefix,
			CreateStatement: "CREATE DATABASE `" + uri.Database + "`",
			ExtraStatements: []string{},
		})
		if err != nil {
			return err
		}
		_, err = op.Wait(ctx)
		return err
	}
	return err
}
