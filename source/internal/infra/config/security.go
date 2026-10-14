// Copyright The MatrixHub Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"path/filepath"
	"time"
)

// SecurityConfig describes local analysis limits. Production execution requires
// the separate, network-less scanner from deploy/security-scanner.
type SecurityConfig struct {
	Enabled         bool          `yaml:"enabled"`
	Mode            string        `yaml:"mode"`
	BlockSeverity   string        `yaml:"blockSeverity"`
	SocketPath      string        `yaml:"socketPath"`
	StagingRoot     string        `yaml:"stagingRoot"`
	MaxFileBytes    int64         `yaml:"maxFileBytes"`
	MaxTaskBytes    int64         `yaml:"maxTaskBytes"`
	MaxStagingBytes int64         `yaml:"maxStagingBytes"`
	MaxFiles        int           `yaml:"maxFiles"`
	Timeout         time.Duration `yaml:"timeout"`
	Lease           time.Duration `yaml:"lease"`
	PollInterval    time.Duration `yaml:"pollInterval"`
	Concurrency     int           `yaml:"concurrency"`
	MaxAttempts     int           `yaml:"maxAttempts"`
}

func (c *SecurityConfig) DefaultAndValidate(dataDir string) error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.Mode == "" {
		c.Mode = "enforce"
	}
	if c.BlockSeverity == "" {
		c.BlockSeverity = "high"
	}
	if c.Mode != "enforce" && c.Mode != "audit" {
		return fmt.Errorf("security.mode must be enforce or audit")
	}
	switch c.BlockSeverity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("security.blockSeverity is invalid")
	}
	if c.SocketPath == "" {
		c.SocketPath = "/run/matrix-security/scanner.sock"
	}
	if !filepath.IsAbs(c.SocketPath) {
		return fmt.Errorf("security.socketPath must be absolute")
	}
	if c.StagingRoot == "" {
		c.StagingRoot = filepath.Join(dataDir, "security", "artifacts")
	}
	if c.MaxFileBytes == 0 {
		c.MaxFileBytes = 64 << 20
	}
	if c.MaxTaskBytes == 0 {
		c.MaxTaskBytes = 256 << 20
	}
	if c.MaxStagingBytes == 0 {
		c.MaxStagingBytes = 2 << 30
	}
	if c.MaxFiles == 0 {
		c.MaxFiles = 1000
	}
	if c.Timeout == 0 {
		c.Timeout = 2 * time.Minute
	}
	if c.Lease == 0 {
		c.Lease = c.Timeout + 30*time.Second
	}
	if c.PollInterval == 0 {
		c.PollInterval = time.Second
	}
	if c.Concurrency == 0 {
		c.Concurrency = 1
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 3
	}
	if c.MaxFileBytes <= 0 || c.MaxTaskBytes < c.MaxFileBytes || c.MaxStagingBytes < c.MaxTaskBytes || c.MaxFiles < 1 || c.MaxFiles > 10000 {
		return fmt.Errorf("security byte and file limits are inconsistent")
	}
	if c.Timeout <= 0 || c.Lease <= c.Timeout || c.PollInterval <= 0 || c.Concurrency < 1 || c.Concurrency > 16 || c.MaxAttempts < 1 || c.MaxAttempts > 10 {
		return fmt.Errorf("security execution limits are invalid")
	}
	return nil
}
