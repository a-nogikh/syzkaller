// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"google.golang.org/genai"
)

func main() {
	ctx := context.Background()

	var client *genai.Client
	var err error

	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project != "" {
		location := os.Getenv("GOOGLE_CLOUD_REGION")
		if location == "" {
			location = "us-central1"
		}
		log.Printf("Using Vertex AI (Project: %s, Region: %s)", project, location)
		client, err = genai.NewClient(ctx, &genai.ClientConfig{
			Backend:  genai.BackendVertexAI,
			Project:  project,
			Location: location,
		})
	} else if os.Getenv("GOOGLE_API_KEY") != "" {
		log.Printf("Using Gemini Developer API")
		client, err = genai.NewClient(ctx, nil)
	} else {
		log.Fatalf("Please set GOOGLE_CLOUD_PROJECT (for Vertex) or GOOGLE_API_KEY (for Gemini)")
	}

	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	log.Printf("Fetching models...")
	
	count := 0
	for m, err := range client.Models.All(ctx) {
		if err != nil {
			log.Fatalf("Error iterating models: %v", err)
		}
		
		// Let's only print gemini models to avoid cluttering the output
		if !strings.Contains(m.Name, "gemini") {
			continue
		}

		data := map[string]any{
			"Name":             m.Name,
			"MaxTemperature":   m.MaxTemperature,
			"InputTokenLimit":  m.InputTokenLimit,
			"OutputTokenLimit": m.OutputTokenLimit,
			"Thinking":         m.Thinking,
			"SupportedActions": m.SupportedActions,
		}
		
		b, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(b))
		count++
	}
	
	log.Printf("Found %d gemini models.", count)
}
