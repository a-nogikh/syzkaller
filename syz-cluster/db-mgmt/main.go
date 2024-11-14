// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"cloud.google.com/go/spanner"
	"github.com/golang-migrate/migrate/v4"
	migrate_spanner "github.com/golang-migrate/migrate/v4/database/spanner"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"google.golang.org/api/iterator"
)

const spannerURI = "projects/my-project/instances/my-instance/databases/my-db"

func migrateSchema(ctx context.Context, uri db.ParsedURI, migrations string) error {
	s := &migrate_spanner.Spanner{}
	// spanner://projects/{projectId}/instances/{instanceId}/databases/{databaseName}
	driver, err := s.Open("spanner://" + uri.Full + "?x-clean-statements=true") // Clean statements to allow multiple statements per file
	if err != nil {
		return err
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file://"+migrations,
		"spanner", driver)
	if err != nil {
		return err
	}
	return m.Up()
}

func runSQL(ctx context.Context, uri db.ParsedURI) error {
	client, err := spanner.NewClient(ctx, uri.Full)
	if err != nil {
		return err
	}
	defer client.Close()
	command, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	stmt := spanner.Statement{SQL: string(command)}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()

	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		var cols []string
		for _, col := range row.ColumnNames() {
			cols = append(cols, col)
		}
		fmt.Println(cols)

		for i := 0; i < len(cols); i++ {
			fmt.Printf("\t%s", row.ColumnValue(i))
		}
		fmt.Printf("\n")
	}
	return nil
}

func main() {
	ctx := context.Background()
	uri, err := db.ParseURI(spannerURI)
	if err != nil {
		log.Fatal(err)
	}
	if os.Getenv("SPANNER_EMULATOR_HOST") != "" {
		// There's no sense to do it in Production.
		log.Printf("Check if there's a Spanner instance")
		err = db.CreateSpannerInstance(ctx, uri)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("Check if DB is present")
	err = db.CreateSpannerDB(ctx, uri)
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			if len(os.Args) != 3 {
				log.Fatalf("migrate <path-to-migrations-folder>")
			}
			log.Printf("Run schema migrations")
			err = migrateSchema(ctx, uri, os.Args[2])
		case "run":
			err = runSQL(ctx, uri)
		default:
			log.Fatalf("Unknown command: %s", os.Args[1])
		}
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("Finished!")
}
