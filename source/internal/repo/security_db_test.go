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

package repo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mysqldsn "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

const testSecurityGeneration = "rules-v1"
const testSecurityCommit = "1111111111111111111111111111111111111111"

func securityTestStore(t *testing.T) (*SecurityStore, *gorm.DB) {
	t.Helper()
	if dsn := os.Getenv("MATRIX_SECURITY_TEST_MYSQL_DSN"); dsn != "" {
		return securityMySQLTestStore(t, dsn)
	}
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "security.db")+"?_foreign_keys=on&_busy_timeout=5000"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	for _, name := range []string{"0_init.up.sql", "1_add_model_synced_at.up.sql", "2_security_scans.up.sql", "3_security_reviews.up.sql"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", "sql", "sqlite", name))
		require.NoError(t, err)
		require.NoError(t, db.Exec(string(data)).Error)
	}
	for _, project := range []string{"alpha", "beta"} {
		require.NoError(t, db.Exec("INSERT INTO projects(name,type) VALUES (?,0)", project).Error)
		require.NoError(t, db.Exec("INSERT INTO models(name,project_id,size,default_branch,parameter_count,readme_content) SELECT 'm',id,0,'main',0,'' FROM projects WHERE name=?", project).Error)
	}
	return NewSecurityStore(db), db
}

// Every test gets an isolated database on the explicit local test daemon.
// No existing schema is changed or reused.
func securityMySQLTestStore(t *testing.T, dsn string) (*SecurityStore, *gorm.DB) {
	t.Helper()
	cfg, err := mysqldsn.ParseDSN(dsn)
	require.NoError(t, err)
	cfg.DBName = ""
	cfg.MultiStatements = true
	cfg.ParseTime = true
	admin, err := gorm.Open(mysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	databaseName := fmt.Sprintf("matrix_security_test_%d", time.Now().UnixNano())
	require.NoError(t, admin.Exec("CREATE DATABASE "+databaseName+" CHARACTER SET utf8mb4").Error)
	cfg.DBName = databaseName
	database, err := gorm.Open(mysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := database.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(10)
	t.Cleanup(func() {
		require.NoError(t, sqlDB.Close())
		require.NoError(t, admin.Exec("DROP DATABASE "+databaseName).Error)
		adminDB, closeErr := admin.DB()
		require.NoError(t, closeErr)
		require.NoError(t, adminDB.Close())
	})
	for _, name := range []string{"0_init.up.sql", "1_add_model_synced_at.up.sql", "2_security_scans.up.sql", "3_security_reviews.up.sql"} {
		data, readErr := os.ReadFile(filepath.Join("..", "..", "db", "migrations", "sql", "mysql", name))
		require.NoError(t, readErr)
		require.NoError(t, database.Exec(string(data)).Error)
	}
	for _, project := range []string{"alpha", "beta"} {
		require.NoError(t, database.Exec("INSERT INTO projects(name,type) VALUES (?,0)", project).Error)
		require.NoError(t, database.Exec("INSERT INTO models(name,project_id,size,default_branch,parameter_count,readme_content) SELECT 'm',id,0,'main',0,'' FROM projects WHERE name=?", project).Error)
	}
	return NewSecurityStore(database), database
}
func enqueueSecurityTask(t *testing.T, store *SecurityStore, repo string) *security.Task {
	t.Helper()
	now := time.Now()
	task, err := store.Enqueue(context.Background(), &security.Task{Repo: repo, Revision: testSecurityCommit, Generation: testSecurityGeneration, State: security.Pending, CreatedAt: now, UpdatedAt: now}, false)
	require.NoError(t, err)
	return task
}
func claimSecurityTask(t *testing.T, store *SecurityStore) *security.Task {
	t.Helper()
	task, err := store.Claim(context.Background(), testSecurityGeneration, time.Now(), time.Minute, 3)
	require.NoError(t, err)
	require.NotNil(t, task)
	return task
}
func completeSecurityReport(task *security.Task) *security.Report {
	return &security.Report{
		ReportID: fmt.Sprintf("%d-%d", task.ID, task.Attempt), TaskID: task.ID, Attempt: task.Attempt,
		Repo: task.Repo, Revision: task.Revision, Generation: task.Generation, State: security.Pass,
		Complete: true, ExpectedFiles: 1, FinishedAt: time.Now(),
		Files: []security.FileReport{{
			SourceFile: security.SourceFile{Path: "config.json", BlobID: strings.Repeat("a", 40), Size: 3},
			Artifact:   security.Artifact{ID: "task/file.blob", Digest: strings.Repeat("a", 64), Size: 3, Type: "json:.json"},
			Analysis:   security.Analysis{Generation: task.Generation, Complete: true, Engines: map[string]string{"clamav": "1", "picklescan": "1"}},
		}},
	}
}
func TestSecurityExpiredWorkerCannotPublish(t *testing.T) {
	store, db := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	first := claimSecurityTask(t, store)
	require.NoError(t, db.Model(&securityTaskRow{}).Where("id = ?", first.ID).Update("lease_until", time.Now().Add(-time.Second)).Error)
	second := claimSecurityTask(t, store)
	require.NotEqual(t, first.Token, second.Token)
	require.Equal(t, first.Attempt+1, second.Attempt)
	accepted, err := store.Finish(context.Background(), first, completeSecurityReport(first))
	require.NoError(t, err)
	require.False(t, accepted)
	_, r, err := store.Get(context.Background(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Nil(t, r)
	accepted, err = store.Finish(context.Background(), second, completeSecurityReport(second))
	require.NoError(t, err)
	require.True(t, accepted)
}
func TestSecurityForceRescanCannotBypassQueueCapacity(t *testing.T) {
	store, db := securityTestStore(t)
	task := enqueueSecurityTask(t, store, "alpha/m")
	require.NoError(t, db.Model(&securityTaskRow{}).Where("id = ?", task.ID).Update("state", "fail").Error)
	identity, err := store.scope(t.Context(), db, "alpha/m")
	require.NoError(t, err)
	rows := make([]securityTaskRow, 1000)
	for i := range rows {
		rows[i] = securityTaskRow{Scope: identity, Repo: "alpha/m", Revision: fmt.Sprintf("%040x", i+100), Generation: testSecurityGeneration, State: "pending", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	}
	require.NoError(t, db.CreateInBatches(rows, 100).Error)
	_, err = store.Enqueue(t.Context(), task, true)
	require.ErrorContains(t, err, "capacity")
	current, _, err := store.Get(t.Context(), task.Repo, task.Revision, task.Generation)
	require.NoError(t, err)
	require.Equal(t, security.Fail, current.State)
	// Replacing an already queued task consumes no extra slot.
	_, err = store.Enqueue(t.Context(), &security.Task{Repo: "alpha/m", Revision: rows[0].Revision, Generation: testSecurityGeneration, UpdatedAt: time.Now()}, true)
	require.NoError(t, err)
}
func TestSecurityForceRescanPreservesHistoricalReport(t *testing.T) {
	store, _ := securityTestStore(t)
	task := enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	old := completeSecurityReport(claim)
	accepted, err := store.Finish(context.Background(), claim, old)
	require.NoError(t, err)
	require.True(t, accepted)
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()
	_, err = store.Enqueue(context.Background(), task, true)
	require.NoError(t, err)
	pending, r, err := store.Get(context.Background(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Equal(t, security.Pending, pending.State)
	require.Nil(t, r)
	historical, err := store.Historical(context.Background(), "alpha/m", old.ReportID)
	require.NoError(t, err)
	require.Equal(t, old.ReportID, historical.ReportID)
	next := claimSecurityTask(t, store)
	require.Greater(t, next.Attempt, claim.Attempt)
	newReport := completeSecurityReport(next)
	newReport.State = security.Block
	newReport.Files[0].Findings = []security.Finding{{Engine: "clamav", Rule: "EICAR", Severity: "high"}}
	accepted, err = store.Finish(context.Background(), next, newReport)
	require.NoError(t, err)
	require.True(t, accepted)
	historical, err = store.Historical(context.Background(), "alpha/m", old.ReportID)
	require.NoError(t, err)
	require.Equal(t, security.Pass, historical.State)
}
func TestSecurityCancelledTaskRejectsLateCompletion(t *testing.T) {
	store, _ := securityTestStore(t)
	task := enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	ok, err := store.Cancel(context.Background(), task.ID, "alpha/m")
	require.NoError(t, err)
	require.True(t, ok)
	accepted, err := store.Finish(context.Background(), claim, completeSecurityReport(claim))
	require.NoError(t, err)
	require.False(t, accepted)
	_, report, err := store.Get(context.Background(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Nil(t, report)
}
func TestSecurityRecreatedNamespaceCannotInheritEvidence(t *testing.T) {
	store, db := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	r := completeSecurityReport(claim)
	accepted, err := store.Finish(context.Background(), claim, r)
	require.NoError(t, err)
	require.True(t, accepted)
	require.NoError(t, store.SetPolicy(context.Background(), &security.Policy{Repo: "alpha/m", Mode: "audit", BlockSeverity: "high", UpdatedAt: time.Now()}, securityPolicyAudit("alpha/m")))
	require.NoError(t, store.AppendAudit(context.Background(), &security.Audit{Repo: "alpha/m", Actor: "previous-owner", Action: "download", CreatedAt: time.Now()}))
	require.NoError(t, db.Exec("DELETE FROM projects WHERE name='alpha'").Error)
	require.NoError(t, db.Exec("INSERT INTO projects(name,type) VALUES ('alpha',0)").Error)
	require.NoError(t, db.Exec("INSERT INTO models(name,project_id,size,default_branch,parameter_count,readme_content) SELECT 'm',id,0,'main',0,'' FROM projects WHERE name='alpha'").Error)
	task, report, err := store.Get(context.Background(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Nil(t, task)
	require.Nil(t, report)
	_, err = store.Historical(context.Background(), "alpha/m", r.ReportID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	cached, err := store.Cached(context.Background(), "alpha/m", r.Files[0].Artifact, testSecurityGeneration)
	require.NoError(t, err)
	require.Nil(t, cached)
	p, err := store.Policy(context.Background(), "alpha/m")
	require.NoError(t, err)
	require.Nil(t, p)
	events, err := store.Audits(context.Background(), "alpha/m", 50, 0)
	require.NoError(t, err)
	require.Empty(t, events)
}
func TestSecurityCacheSeparatesScopeContextAndRules(t *testing.T) {
	store, _ := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	r := completeSecurityReport(claim)
	ok, err := store.Finish(context.Background(), claim, r)
	require.NoError(t, err)
	require.True(t, ok)
	cached, err := store.Cached(context.Background(), "alpha/m", r.Files[0].Artifact, testSecurityGeneration)
	require.NoError(t, err)
	require.NotNil(t, cached)
	changedType := r.Files[0].Artifact
	changedType.Type = "pickle:.pkl"
	for _, test := range []struct {
		repo, gen string
		artifact  security.Artifact
	}{
		{"beta/m", testSecurityGeneration, r.Files[0].Artifact},
		{"alpha/m", "rules-v2", r.Files[0].Artifact},
		{"alpha/m", testSecurityGeneration, changedType},
	} {
		miss, err := store.Cached(context.Background(), test.repo, test.artifact, test.gen)
		require.NoError(t, err)
		require.Nil(t, miss)
	}
}
func TestSecurityConcurrentClaimHasSingleOwner(t *testing.T) {
	store, _ := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	var wg sync.WaitGroup
	var mu sync.Mutex
	owners := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task, err := store.Claim(context.Background(), testSecurityGeneration, time.Now(), time.Minute, 3)
			require.NoError(t, err)
			if task != nil {
				mu.Lock()
				owners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 1, owners)
}
func TestSecurityIncompleteCoverageCannotCommitApproval(t *testing.T) {
	store, _ := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	r := completeSecurityReport(claim)
	r.ExpectedFiles = 2
	accepted, err := store.Finish(context.Background(), claim, r)
	require.Error(t, err)
	require.False(t, accepted)
	_, report, err := store.Get(context.Background(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Nil(t, report)
	cached, err := store.Cached(context.Background(), "alpha/m", r.Files[0].Artifact, testSecurityGeneration)
	require.NoError(t, err)
	require.Nil(t, cached)
}
func TestSecurityPartialFailedScanIsNotReusable(t *testing.T) {
	store, _ := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	r := completeSecurityReport(claim)
	r.Complete = false
	r.State = security.Fail
	r.Error = "scanner timeout"
	accepted, err := store.Finish(context.Background(), claim, r)
	require.NoError(t, err)
	require.True(t, accepted)
	cached, err := store.Cached(context.Background(), "alpha/m", r.Files[0].Artifact, testSecurityGeneration)
	require.NoError(t, err)
	require.Nil(t, cached)
}
func TestSecurityRulesChangeInvalidatesPendingTask(t *testing.T) {
	store, _ := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	task, err := store.Claim(context.Background(), "rules-v2", time.Now(), time.Minute, 3)
	require.NoError(t, err)
	require.Nil(t, task)
	old, report, err := store.Get(context.Background(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Equal(t, security.Fail, old.State)
	require.Nil(t, report)
}
func TestSecurityPolicyVersionAdvances(t *testing.T) {
	store, _ := securityTestStore(t)
	p := &security.Policy{Repo: "alpha/m", Mode: "enforce", BlockSeverity: "high", UpdatedAt: time.Now()}
	require.NoError(t, store.SetPolicy(context.Background(), p, securityPolicyAudit(p.Repo)))
	first, err := store.Policy(context.Background(), "alpha/m")
	require.NoError(t, err)
	require.EqualValues(t, 2, first.Version)
	p.Mode = "audit"
	require.NoError(t, store.SetPolicy(context.Background(), p, securityPolicyAudit(p.Repo)))
	second, err := store.Policy(context.Background(), "alpha/m")
	require.NoError(t, err)
	require.EqualValues(t, 3, second.Version)
}
func TestSecurityCancelCannotCrossRepository(t *testing.T) {
	store, _ := securityTestStore(t)
	task := enqueueSecurityTask(t, store, "alpha/m")
	ok, err := store.Cancel(context.Background(), task.ID, "beta/m")
	require.NoError(t, err)
	require.False(t, ok)
}

func enqueueSecurityIntent(t *testing.T, store *SecurityStore, generation string, force bool, at time.Time) *security.Task {
	t.Helper()
	trigger := "upload"
	if force {
		trigger = "manual-rescan"
	}
	task, err := store.Enqueue(t.Context(), &security.Task{Repo: "alpha/m", Revision: testSecurityCommit,
		Generation: generation, Trigger: trigger, CreatedAt: at, UpdatedAt: at}, force)
	require.NoError(t, err)
	return task
}

func approvedSecurityTask(t *testing.T, store *SecurityStore) (*security.Task, *security.Report) {
	t.Helper()
	enqueueSecurityTask(t, store, "alpha/m")
	task := claimSecurityTask(t, store)
	report := completeSecurityReport(task)
	accepted, err := store.Finish(t.Context(), task, report)
	require.NoError(t, err)
	require.True(t, accepted)
	return task, report
}

func TestSecurityOfflineUploadRecoversWithoutMetadataRead(t *testing.T) {
	store, _ := securityTestStore(t)
	intent := enqueueSecurityIntent(t, store, "unavailable", false, time.Now())
	// Claim alone must recover the persisted intent after a process restart.
	store = NewSecurityStore(store.db)
	claim := claimSecurityTask(t, store)
	require.Equal(t, intent.ID, claim.ID)
	require.Equal(t, testSecurityGeneration, claim.Generation)
	require.False(t, claim.Force)
	accepted, err := store.Finish(t.Context(), claim, completeSecurityReport(claim))
	require.NoError(t, err)
	require.True(t, accepted)
	_, report, err := store.Get(t.Context(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.True(t, report.Complete)
}

func TestSecurityOfflineForceInvalidatesApprovalBeforeRecovery(t *testing.T) {
	store, _ := securityTestStore(t)
	old, report := approvedSecurityTask(t, store)
	intent := enqueueSecurityIntent(t, store, "unavailable", true, time.Now())
	// Scanner health can return before the first healthy worker poll. The old
	// complete report must already be hidden at this exact boundary.
	pending, current, err := store.Get(t.Context(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Equal(t, security.Pending, pending.State)
	require.True(t, pending.Force)
	require.Nil(t, current)
	claim := claimSecurityTask(t, store)
	require.Equal(t, old.ID, claim.ID)
	require.True(t, claim.Force, "recovery must not allow cached analyses")
	require.Greater(t, claim.Attempt, old.Attempt)
	retired, _, err := store.Get(t.Context(), "alpha/m", testSecurityCommit, "unavailable")
	require.NoError(t, err)
	require.Equal(t, intent.ID, retired.ID)
	require.Equal(t, security.Fail, retired.State)
	require.Contains(t, retired.Error, "superseded by task")
	historical, err := store.Historical(t.Context(), "alpha/m", report.ReportID)
	require.NoError(t, err)
	require.Equal(t, report.ReportID, historical.ReportID)
	require.True(t, historical.Complete)
}

func TestSecurityOfflineForceFencesInFlightCompletion(t *testing.T) {
	store, _ := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	old := claimSecurityTask(t, store)
	enqueueSecurityIntent(t, store, "unavailable", true, time.Now())
	accepted, err := store.Finish(t.Context(), old, completeSecurityReport(old))
	require.NoError(t, err)
	require.False(t, accepted)
	claim := claimSecurityTask(t, store)
	require.True(t, claim.Force)
	require.NotEqual(t, old.Token, claim.Token)
}

func TestSecurityOfflineCancellationDoesNotResurrect(t *testing.T) {
	for _, cancelKnown := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancelKnown=%t", cancelKnown), func(t *testing.T) {
			store, _ := securityTestStore(t)
			old, _ := approvedSecurityTask(t, store)
			intent := enqueueSecurityIntent(t, store, "unavailable", true, time.Now())
			id := intent.ID
			if cancelKnown {
				id = old.ID
			}
			ok, err := store.Cancel(t.Context(), id, "alpha/m")
			require.NoError(t, err)
			require.True(t, ok)
			claim, err := store.Claim(t.Context(), testSecurityGeneration, time.Now(), time.Minute, 3)
			require.NoError(t, err)
			require.Nil(t, claim)
			for _, gen := range []string{testSecurityGeneration, "unavailable"} {
				task, report, err := store.Get(t.Context(), "alpha/m", testSecurityCommit, gen)
				require.NoError(t, err)
				require.Equal(t, security.Fail, task.State)
				if gen == testSecurityGeneration {
					require.Equal(t, securityCancelled, task.Error)
				} else {
					require.Contains(t, task.Error, "superseded by task")
				}
				require.Nil(t, report)
			}
		})
	}
}

func TestSecurityOfflineCancelledNewUploadStaysCancelled(t *testing.T) {
	store, _ := securityTestStore(t)
	intent := enqueueSecurityIntent(t, store, "unavailable", false, time.Now())
	ok, err := store.Cancel(t.Context(), intent.ID, "alpha/m")
	require.NoError(t, err)
	require.True(t, ok)
	claim, err := store.Claim(t.Context(), testSecurityGeneration, time.Now(), time.Minute, 3)
	require.NoError(t, err)
	require.Nil(t, claim)
	// Reading metadata creates no new work, and a racing lazy ensure cannot
	// replace the transferred cancellation tombstone with a pending task.
	current, _, err := store.Get(t.Context(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Equal(t, security.Fail, current.State)
	ensured := enqueueSecurityIntent(t, store, testSecurityGeneration, false, time.Now())
	require.Equal(t, security.Fail, ensured.State)
}

func TestSecurityOfflineOlderIntentCannotReplaceNewForce(t *testing.T) {
	store, _ := securityTestStore(t)
	old, _ := approvedSecurityTask(t, store)
	tick := time.Now().Truncate(time.Millisecond)
	intent := enqueueSecurityIntent(t, store, "unavailable", true, tick)
	// Deliberately reuse the clock tick to exercise persisted ordering on MySQL.
	next := enqueueSecurityIntent(t, store, testSecurityGeneration, true, tick)
	require.Equal(t, old.ID, next.ID)
	require.True(t, next.UpdatedAt.After(intent.UpdatedAt))
	ok, err := store.Cancel(t.Context(), intent.ID, "alpha/m")
	require.NoError(t, err)
	require.False(t, ok, "an absorbed old intent must not cancel its replacement")
	claim := claimSecurityTask(t, store)
	require.Equal(t, next.ID, claim.ID)
	require.True(t, claim.Force)
}

func TestSecurityOfflineEnsureAndRecoveryHaveOneTask(t *testing.T) {
	store, db := securityTestStore(t)
	intent := enqueueSecurityIntent(t, store, "unavailable", true, time.Now())
	var wg sync.WaitGroup
	var mu sync.Mutex
	owners := 0
	for index := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if index%2 == 0 {
				_, err := store.Enqueue(t.Context(), &security.Task{Repo: "alpha/m", Revision: testSecurityCommit,
					Generation: testSecurityGeneration, Trigger: "lazy-ensure", CreatedAt: time.Now(), UpdatedAt: time.Now()}, false)
				require.NoError(t, err)
			} else {
				claim, err := store.Claim(t.Context(), testSecurityGeneration, time.Now(), time.Minute, 3)
				require.NoError(t, err)
				if claim != nil {
					require.True(t, claim.Force)
					require.Equal(t, intent.ID, claim.ID)
					mu.Lock()
					owners++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 1, owners)
	var count int64
	require.NoError(t, db.Model(&securityTaskRow{}).Where("repo = ? AND revision = ? AND generation = ?", "alpha/m", testSecurityCommit, testSecurityGeneration).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestSecurityOfflineRecoveryCannotCrossRecreatedScope(t *testing.T) {
	store, db := securityTestStore(t)
	intent := enqueueSecurityIntent(t, store, "unavailable", false, time.Now())
	require.NoError(t, db.Exec("DELETE FROM projects WHERE name='alpha'").Error)
	require.NoError(t, db.Exec("INSERT INTO projects(name,type) VALUES ('alpha',0)").Error)
	require.NoError(t, db.Exec("INSERT INTO models(name,project_id,size,default_branch,parameter_count,readme_content) SELECT 'm',id,0,'main',0,'' FROM projects WHERE name='alpha'").Error)
	claim, err := store.Claim(t.Context(), testSecurityGeneration, time.Now(), time.Minute, 3)
	require.NoError(t, err)
	require.Nil(t, claim)
	var retired securityTaskRow
	require.NoError(t, db.First(&retired, intent.ID).Error)
	require.Equal(t, "fail", retired.State)
	require.Equal(t, "repository identity no longer exists", retired.Error)
	current, _, err := store.Get(t.Context(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Nil(t, current)
}

func TestSecurityOfflineNonforceDoesNotResetKnownCancellation(t *testing.T) {
	store, _ := securityTestStore(t)
	known := enqueueSecurityTask(t, store, "alpha/m")
	ok, err := store.Cancel(t.Context(), known.ID, "alpha/m")
	require.NoError(t, err)
	require.True(t, ok)
	enqueueSecurityIntent(t, store, "unavailable", false, time.Now())
	claim, err := store.Claim(t.Context(), testSecurityGeneration, time.Now(), time.Minute, 3)
	require.NoError(t, err)
	require.Nil(t, claim)
	current, _, err := store.Get(t.Context(), "alpha/m", testSecurityCommit, testSecurityGeneration)
	require.NoError(t, err)
	require.Equal(t, securityCancelled, current.Error)
}

func securityPolicyAudit(repo string) *security.Audit {
	return &security.Audit{Repo: repo, Actor: "authorized-test-operator", Action: "policy-update", Entry: "test", CreatedAt: time.Now()}
}

func TestSecurityPolicyAuditFailureRollsBackPolicy(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
			store, db := securityTestStore(t)
			if existing {
				require.NoError(t, store.SetPolicy(t.Context(), &security.Policy{Repo: "alpha/m", Mode: "enforce", BlockSeverity: "high", UpdatedAt: time.Now()}, securityPolicyAudit("alpha/m")))
			}
			// A real database write failure inside an isolated test schema,
			// after the policy upsert, must roll back that upsert too.
			require.NoError(t, db.Migrator().DropTable(&securityAuditRow{}))
			policy := &security.Policy{Repo: "alpha/m", Mode: "audit", BlockSeverity: "critical", UpdatedAt: time.Now()}
			event := securityPolicyAudit(policy.Repo)
			require.Error(t, store.SetPolicy(t.Context(), policy, event))
			require.Zero(t, policy.Version)
			require.Zero(t, event.ID)
			require.Nil(t, event.Decision)
			stored, err := store.Policy(t.Context(), policy.Repo)
			require.NoError(t, err)
			if existing {
				require.Equal(t, "enforce", stored.Mode)
				require.Equal(t, "high", stored.BlockSeverity)
				require.EqualValues(t, 2, stored.Version)
			} else {
				require.Nil(t, stored)
			}
		})
	}
}

func TestSecurityConcurrentPolicyUpdatesReturnOwnAuditedVersion(t *testing.T) {
	store, _ := securityTestStore(t)
	const writers = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	policies := map[int64]security.Policy{}
	for index := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mode := "enforce"
			if index%2 == 1 {
				mode = "audit"
			}
			policy := &security.Policy{Repo: "alpha/m", Mode: mode, BlockSeverity: "high", UpdatedAt: time.Now()}
			event := securityPolicyAudit(policy.Repo)
			event.Actor = fmt.Sprintf("operator-%d", index)
			require.NoError(t, store.SetPolicy(t.Context(), policy, event))
			require.Positive(t, event.ID)
			require.Equal(t, policy.Version, event.Decision.PolicyVersion)
			require.Equal(t, "PolicyUpdated", event.Decision.Code)
			require.Equal(t, "mode="+mode+"; blockSeverity=high", event.Decision.Message)
			mu.Lock()
			require.NotContains(t, policies, policy.Version)
			policies[policy.Version] = *policy
			mu.Unlock()
		}()
	}
	wg.Wait()
	require.Len(t, policies, writers)
	events, err := store.Audits(t.Context(), "alpha/m", 50, 0)
	require.NoError(t, err)
	require.Len(t, events, writers)
	for _, event := range events {
		policy := policies[event.Decision.PolicyVersion]
		require.Equal(t, "mode="+policy.Mode+"; blockSeverity=high", event.Decision.Message)
	}
	stored, err := store.Policy(t.Context(), "alpha/m")
	require.NoError(t, err)
	require.EqualValues(t, writers+1, stored.Version)
}
