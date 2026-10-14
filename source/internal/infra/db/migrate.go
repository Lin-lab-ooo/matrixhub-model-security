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
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"

	"github.com/matrixhub-ai/matrixhub/internal/infra/log"
)

func shouldMigrate(db *gorm.DB, sqlPath string, migrationsTable string) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	if sqlPath, err = filepath.Abs(sqlPath); err != nil {
		return err
	}
	dialector := db.Name()
	sqlPath = migrationSourceURL(filepath.Join(sqlPath, dialector))

	var session *migrate.Migrate
	switch dialector {
	case "mysql":
		session, err = newMysqlMigrateSession(sqlDB, sqlPath, migrationsTable)
	case "postgres":
		session, err = newPostgresMigrateSession(sqlDB, sqlPath, migrationsTable)
	case "sqlite":
		session, err = newSQLiteMigrateSession(sqlDB, sqlPath, migrationsTable)
	default:
		return fmt.Errorf("migration not support database: %s", dialector)
	}
	if err != nil {
		return err
	}

	log.Infof("migrate sql path: %s", sqlPath)
	if err := session.Up(); err != nil {
		if err == migrate.ErrNoChange {
			log.Info("database has migrated to latest version, nothing changed")
			return nil
		}
		return fmt.Errorf("migrate failed: %w", err)
	}

	version, dirty, err := session.Version()
	log.Infow("database migrated successfully", "version", version, "dirty", dirty, "err", err)
	return nil
}

func newSQLiteMigrateSession(db *sql.DB, sqlPath string, migrationsTable string) (*migrate.Migrate, error) {
	driver, err := sqlite3.WithInstance(db, &sqlite3.Config{
		MigrationsTable: migrationsTable,
	})
	if err != nil {
		return nil, err
	}

	m, err := newLocalMigrationSession(sqlPath, "sqlite3", driver)
	if err != nil {
		return nil, fmt.Errorf("create sqlite migration session: %w", err)
	}
	return m, nil
}

func newPostgresMigrateSession(db *sql.DB, sqlPath string, migrationsTable string) (*migrate.Migrate, error) {
	driver, err := postgres.WithInstance(db, &postgres.Config{
		MigrationsTable: migrationsTable,
	})
	if err != nil {
		return nil, err
	}

	m, err := newLocalMigrationSession(sqlPath, "postgres", driver)
	if err != nil {
		return nil, fmt.Errorf("create postgres migration session: %w", err)
	}
	return m, nil
}

func newMysqlMigrateSession(db *sql.DB, sqlPath string, migrationsTable string) (*migrate.Migrate, error) {
	driver, err := mysql.WithInstance(db, &mysql.Config{
		MigrationsTable: migrationsTable,
	})
	if err != nil {
		return nil, err
	}

	m, err := newLocalMigrationSession(sqlPath, "mysql", driver)
	if err != nil {
		return nil, fmt.Errorf("create mysql migration session: %w", err)
	}
	return m, nil
}

func migrationSourceURL(path string) string {
	return (&url.URL{Scheme: "file", Path: fileURIPath(path, runtime.GOOS)}).String()
}

// The file source driver preserves /C:/ URI paths on Windows. Resolve the URI
// to a native path before opening the filesystem so all supported platforms use
// the same escaped file URI, including directories containing spaces or '#'.
func newLocalMigrationSession(sourceURL, databaseName string, driver database.Driver) (*migrate.Migrate, error) {
	parsed, err := url.Parse(sourceURL)
	if err != nil {
		return nil, fmt.Errorf("parse migration source URL: %w", err)
	}
	if parsed.Scheme != "file" || (parsed.Host != "" && parsed.Host != "localhost") ||
		parsed.Path == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("migration source must be a local file URI")
	}
	path := sqliteURIPathToNative(parsed.Path, runtime.GOOS)
	source, err := iofs.New(os.DirFS(path), ".")
	if err != nil {
		return nil, fmt.Errorf("open migration source: %w", err)
	}
	return migrate.NewWithInstance("file", source, databaseName, driver)
}
