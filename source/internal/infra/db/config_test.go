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

package db

import (
	"net/url"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultSQLiteDSN(t *testing.T) {
	dataDir := t.TempDir()

	dsn, err := DefaultSQLiteDSN(dataDir)
	require.NoError(t, err)

	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, "file", parsed.Scheme)
	require.Empty(t, parsed.Host)
	require.Equal(t, filepath.Join(dataDir, "matrixhub.db"), sqliteURIPathToNative(parsed.Path, runtime.GOOS))
	require.Equal(t, "5000", parsed.Query().Get("_busy_timeout"))
	require.Equal(t, "on", parsed.Query().Get("_foreign_keys"))
	require.Equal(t, "WAL", parsed.Query().Get("_journal_mode"))
	require.Equal(t, "FULL", parsed.Query().Get("_synchronous"))
	require.Equal(t, "immediate", parsed.Query().Get("_txlock"))
}

func TestFileURIPathWindows(t *testing.T) {
	uri := (&url.URL{Scheme: "file", Path: fileURIPath(`C:\竞赛 data\model#1%.db`, "windows")}).String()
	require.Equal(t, "file:///C:/%E7%AB%9E%E8%B5%9B%20data/model%231%25.db", uri)
	parsed, err := url.Parse(uri)
	require.NoError(t, err)
	require.Empty(t, parsed.Host)
	require.Empty(t, parsed.RawQuery)
	require.Empty(t, parsed.Fragment)
	require.Equal(t, `C:\竞赛 data\model#1%.db`, sqliteURIPathToNative(parsed.Path, "windows"))
}

func TestFileURIPathsRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name, path, goos, wantURI, wantNative string
	}{
		{"drive", `C:\data\model.db`, "windows", "file:///C:/data/model.db", `C:\data\model.db`},
		{"drive slash", "D:/data/model.db", "windows", "file:///D:/data/model.db", `D:\data\model.db`},
		{"UNC", `\\server\share\model.db`, "windows", "file:////server/share/model.db", `\\server\share\model.db`},
		{"unix spaces", "/data with spaces/model.db", "linux", "file:///data%20with%20spaces/model.db", "/data with spaces/model.db"},
	} {
		t.Run(test.name, func(t *testing.T) {
			uri := (&url.URL{Scheme: "file", Path: fileURIPath(test.path, test.goos)}).String()
			require.Equal(t, test.wantURI, uri)
			parsed, err := url.Parse(uri)
			require.NoError(t, err)
			require.Empty(t, parsed.Host)
			require.Equal(t, test.wantNative, sqliteURIPathToNative(parsed.Path, test.goos))
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "supported mysql config",
			config: Config{
				Driver:       DriverMySQL,
				DSN:          "matrixhub:password@tcp(localhost:3306)/matrixhub",
				MaxOpenConns: 10,
				MaxIdleConns: 2,
			},
		},
		{
			name: "unsupported driver",
			config: Config{
				Driver: "oracle",
				DSN:    "unused",
			},
			wantErr: "unsupported database driver",
		},
		{
			name: "missing dsn",
			config: Config{
				Driver: DriverPostgres,
			},
			wantErr: "database DSN is required",
		},
		{
			name: "sqlite has multiple open connections",
			config: Config{
				Driver:       DriverSQLite,
				DSN:          "file:test.db",
				MaxOpenConns: 2,
				MaxIdleConns: 1,
			},
			wantErr: "sqlite requires maxOpenConns to be 1",
		},
		{
			name: "migration path is required",
			config: Config{
				Driver:       DriverSQLite,
				DSN:          "file:test.db",
				MaxOpenConns: 1,
				MaxIdleConns: 1,
				Migrate:      true,
			},
			wantErr: "sqlPath is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSQLiteConfigApplyDefaults(t *testing.T) {
	config := Config{Driver: DriverSQLite}

	config.applyDefaults()

	require.Equal(t, 1, config.MaxOpenConns)
	require.Equal(t, 1, config.MaxIdleConns)
}
