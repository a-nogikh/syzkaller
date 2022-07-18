// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"fmt"
	"strings"
)

type Config struct {
	Debug    bool                `json:"debug"`
	UploadTo string              `json:"upload_to"`
	Assets   map[Type]TypeConfig `json:"assets"`
}

type TypeConfig struct {
	Always bool `json:"always"`
	Never  bool `json:"never"`
	// TODO: in future there'll also be `OnlyOn` and `NeverOn`, but so far we don't really need that.
	// TODO: here will also go compression settings, should we ever want to make it configurable.
}

func (tc *TypeConfig) Validate() error {
	if tc.Always == tc.Never {
		return fmt.Errorf("always == never")
	}
	return nil
}

func (c *Config) IsEnabled(assetType Type) bool {
	cfg, ok := c.Assets[assetType]
	if !ok {
		return false
	}
	return cfg.Always
}

func (c *Config) IsEmpty() bool {
	return c == nil || len(c.Assets) == 0
}

func (c *Config) Validate() error {
	for assetType, cfg := range c.Assets {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid config for %s: %w", assetType, err)
		}
	}
	if c.UploadTo == "" && len(c.Assets) != 0 {
		return fmt.Errorf("assets are specified, but upload_to is empty")
	}
	allowedFormats := []string{"gs://", "test://"}
	if c.UploadTo != "" {
		any := false
		for _, prefix := range allowedFormats {
			if strings.HasPrefix(c.UploadTo, prefix) {
				any = true
			}
		}
		if !any {
			return fmt.Errorf("the only supported upload destination is gs:// now")
		}
	}
	return nil
}
