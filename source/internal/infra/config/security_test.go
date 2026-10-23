// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecurityBatchConfigurationKeepsBoundedDefaults(t *testing.T) {
	root := t.TempDir()
	cfg := SecurityConfig{Enabled: true, SocketPath: filepath.Join(root, "scanner.sock")}
	require.NoError(t, cfg.DefaultAndValidate(root))
	require.Equal(t, 32, cfg.BatchFiles)
	require.Equal(t, int64(256<<20), cfg.BatchBytes)
	cfg.BatchFiles, cfg.BatchBytes = 4, 5<<30
	require.NoError(t, cfg.DefaultAndValidate(root))
}

func TestSecurityBatchConfigurationRejectsUnboundedValues(t *testing.T) {
	root := t.TempDir()
	for _, limits := range []struct {
		files int
		bytes int64
	}{{-1, 1}, {33, 1}, {1, -1}, {1, 5<<30 + 1}} {
		cfg := SecurityConfig{Enabled: true, SocketPath: filepath.Join(root, "scanner.sock"), BatchFiles: limits.files, BatchBytes: limits.bytes}
		require.ErrorContains(t, cfg.DefaultAndValidate(root), "batch limits")
	}
}
