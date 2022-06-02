// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assets

import "fmt"

type AssetTypeConfig struct {
	Always bool `json:"always"`
	Never  bool `json:"never"`
	// TODO: in future there'll also be `OnlyOn` and `NeverOn`, but so far we don't really need that.
	// TODO: here will also go compression settings, should we ever want to make it configurable.
}

type Config struct {
	GcsBucket string                     `json:"gcs_bucket"`
	Assets    map[string]AssetTypeConfig `json:"assets"`
}

func (c *Config) IsEnabled(assetType string) bool {
	cfg, ok := c.Assets[assetType]
	if !ok {
		return false
	}
	return cfg.Always
}

func (c *Config) IsEmpty() bool {
	return len(c.Assets) == 0
}

func (c *Config) Validate() error {
	for assetType, cfg := range c.Assets {
		if cfg.Always == cfg.Never {
			return fmt.Errorf("invalid config for %s: always == never", assetType)
		}
	}
	if len(c.GcsBucket) == 0 && len(c.Assets) != 0 {
		return fmt.Errorf("assets are specified, but gcs_bucket is empty")
	}
	return nil
}
