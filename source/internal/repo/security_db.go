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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

type SecurityStore struct {
	db *gorm.DB
	// A deployment has one API process/staging owner. Serialize capacity checks
	// within its store; multi-process writers require a database quota lock.
	enqueueMu sync.Mutex
}

func NewSecurityStore(db *gorm.DB) *SecurityStore { return &SecurityStore{db: db} }

// Empty queues and cache misses are expected control flow. Find avoids
// logging them as SQL errors while preserving the repository's missing-row
// contract and retaining genuine database errors.
func securityTake(query *gorm.DB, dest any) error {
	result := query.Limit(1).Find(dest)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

type securityTaskRow struct {
	ID         int64 `gorm:"primaryKey"`
	Scope      string
	Repo       string
	Revision   string
	Generation string
	State      string
	Trigger    string
	Force      bool
	Attempt    int
	RetryCount int
	Token      string
	LeaseUntil *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Error      string
	ReportJSON string
}

func (securityTaskRow) TableName() string { return "security_tasks" }

type securityReportRow struct {
	ReportID   string `gorm:"primaryKey"`
	Scope      string
	Repo       string
	TaskID     int64
	Attempt    int
	ReportJSON string
	CreatedAt  time.Time
}

func (securityReportRow) TableName() string { return "security_reports" }

type securityCacheRow struct {
	ID           int64 `gorm:"primaryKey"`
	Scope        string
	Digest       string
	Size         int64
	Type         string
	Generation   string
	AnalysisJSON string
	CreatedAt    time.Time
}

func (securityCacheRow) TableName() string { return "security_cache" }

type securityPolicyRow struct {
	Scope         string `gorm:"primaryKey"`
	Repo          string
	Mode          string
	BlockSeverity string
	Version       int64
	UpdatedAt     time.Time
}

func (securityPolicyRow) TableName() string { return "security_policies" }

type securityAuditRow struct {
	ID        int64 `gorm:"primaryKey"`
	Scope     string
	Repo      string
	EventJSON string
	CreatedAt time.Time
}

func (securityAuditRow) TableName() string { return "security_audit" }

// scope is resolved inside the same transaction when it guards a write.
// A reused namespace/name never inherits another project's model evidence.
func (s *SecurityStore) scope(ctx context.Context, db *gorm.DB, repo string) (string, error) {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return "", errors.New("invalid model scope")
	}
	var identity struct {
		ModelID   int64
		ProjectID int64
	}
	err := db.WithContext(ctx).Table("models m").Select("m.id AS model_id, p.id AS project_id").
		Joins("INNER JOIN projects p ON p.id = m.project_id").
		Where("p.name = ? AND m.name = ?", parts[0], parts[1]).Take(&identity).Error
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", identity.ProjectID, identity.ModelID), nil
}
func taskDTO(row securityTaskRow) *security.Task {
	t := &security.Task{ID: row.ID, Scope: row.Scope, Repo: row.Repo, Revision: row.Revision, Generation: row.Generation, State: security.State(row.State), Trigger: row.Trigger, Force: row.Force, Attempt: row.Attempt, Token: row.Token, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, Error: row.Error}
	if row.LeaseUntil != nil {
		t.LeaseUntil = *row.LeaseUntil
	}
	return t
}

const securityCancelled = "cancelled by authorized operator"

func securityForceChanges(trigger string, at time.Time) map[string]any {
	return map[string]any{"state": "pending", "force": true, "trigger": trigger, "token": "", "lease_until": nil, "retry_count": 0, "error": "", "report_json": "", "updated_at": at}
}

// Recover durable upload/rescan intents that could not discover a scanner
// generation. Both callers hold enqueueMu and use one transaction. A pending
// intent is either renamed (no current task) or absorbed by that unique task;
// cancelled/terminal intents are never resurrected. Report history is untouched.
func (s *SecurityStore) recoverUnavailable(ctx context.Context, tx *gorm.DB, generation string, now time.Time, scope, revision string) error {
	query := tx.Where("generation = ? AND (state = ? OR (state = ? AND error = ?))", "unavailable", "pending", "fail", securityCancelled)
	if scope != "" {
		query = query.Where("scope = ? AND revision = ?", scope, revision)
	}
	var intents []securityTaskRow
	if err := query.Order("id ASC").Find(&intents).Error; err != nil {
		return err
	}
	for _, intent := range intents {
		currentScope, err := s.scope(ctx, tx, intent.Repo)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err != nil || currentScope != intent.Scope {
			if err = tx.Model(&securityTaskRow{}).Where("id = ?", intent.ID).Updates(map[string]any{"state": "fail", "error": "repository identity no longer exists", "updated_at": now}).Error; err != nil {
				return err
			}
			continue
		}
		var target securityTaskRow
		err = securityTake(tx.Where("scope = ? AND revision = ? AND generation = ?", intent.Scope, intent.Revision, generation), &target)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// It has never run, so changing this unresolved generation cannot
			// alter any published report or invalidate an existing claim token.
			if err = tx.Model(&securityTaskRow{}).Where("id = ?", intent.ID).UpdateColumn("generation", generation).Error; err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		newerExplicitIntent := target.UpdatedAt.After(intent.UpdatedAt) && (target.Force || target.Error == securityCancelled)
		if intent.Error == securityCancelled {
			// Transfer the cancellation tombstone as well. Otherwise the first
			// metadata lazy ensure after recovery could resurrect a cancelled
			// upload that never had a known-generation task.
			if !newerExplicitIntent && (intent.Force || target.State == "pending" || target.State == "scanning") {
				if err = tx.Model(&securityTaskRow{}).Where("id = ?", target.ID).Updates(map[string]any{"state": "fail", "token": "", "lease_until": nil, "report_json": "", "error": securityCancelled, "updated_at": intent.UpdatedAt}).Error; err != nil {
					return err
				}
			}
		} else if intent.Force && !newerExplicitIntent {
			if err = tx.Model(&securityTaskRow{}).Where("id = ?", target.ID).Updates(securityForceChanges(intent.Trigger, intent.UpdatedAt)).Error; err != nil {
				return err
			}
		}
		if err = tx.Model(&securityTaskRow{}).Where("id = ?", intent.ID).Updates(map[string]any{"state": "fail", "token": "", "lease_until": nil, "report_json": "", "error": fmt.Sprintf("scanner recovery intent superseded by task %d", target.ID), "updated_at": now}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *SecurityStore) Enqueue(ctx context.Context, t *security.Task, force bool) (*security.Task, error) {
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	var result *security.Task
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scope, err := s.scope(ctx, tx, t.Repo)
		if err != nil {
			return err
		}
		at := t.UpdatedAt.UTC().Truncate(time.Millisecond)
		if t.Generation != "unavailable" {
			// A concurrent lazy ensure must merge an offline force intent, not
			// create a separate cache-eligible task that escapes cancellation.
			if err = s.recoverUnavailable(ctx, tx, t.Generation, at, scope, t.Revision); err != nil {
				return err
			}
		}
		if force {
			var latest securityTaskRow
			err = securityTake(tx.Where("scope = ? AND revision = ?", scope, t.Revision).Order("updated_at DESC"), &latest)
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			// This schema stores milliseconds. Distinguish intents even when
			// consecutive requests fall in the same persisted clock tick.
			if err == nil && !at.After(latest.UpdatedAt) {
				at = latest.UpdatedAt.Truncate(time.Millisecond).Add(time.Millisecond)
			}
		}
		var count int64
		if err = tx.Model(&securityTaskRow{}).Where("state IN ?", []string{"pending", "scanning"}).Count(&count).Error; err != nil {
			return err
		}
		if force && t.Generation == "unavailable" {
			var newlyActive int64
			known := tx.Model(&securityTaskRow{}).Where("scope = ? AND revision = ? AND generation <> ?", scope, t.Revision, "unavailable")
			if err = known.Where("state NOT IN ?", []string{"pending", "scanning"}).Count(&newlyActive).Error; err != nil {
				return err
			}
			if count+newlyActive > 1000 {
				return errors.New("scan queue capacity reached")
			}
			// Invalidate old approvals before a recovered scanner can expose
			// them through Get. A late worker also loses its publication token.
			if err = tx.Model(&securityTaskRow{}).Where("scope = ? AND revision = ? AND generation <> ?", scope, t.Revision, "unavailable").Updates(securityForceChanges(t.Trigger, at)).Error; err != nil {
				return err
			}
			count += newlyActive
		}
		var row securityTaskRow
		err = securityTake(tx.Where("scope = ? AND revision = ? AND generation = ?", scope, t.Revision, t.Generation), &row)
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			if count >= 1000 {
				return errors.New("scan queue capacity reached")
			}
			row = securityTaskRow{Scope: scope, Repo: t.Repo, Revision: t.Revision, Generation: t.Generation, State: "pending", Trigger: t.Trigger, Force: force, CreatedAt: t.CreatedAt, UpdatedAt: at}
			if err = tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "scope"}, {Name: "revision"}, {Name: "generation"}}, DoNothing: true}).Create(&row).Error; err != nil {
				return err
			}
			if err = tx.Where("scope = ? AND revision = ? AND generation = ?", scope, t.Revision, t.Generation).Take(&row).Error; err != nil {
				return err
			}
		case err != nil:
			return err
		case force:
			if row.State != "pending" && row.State != "scanning" && count >= 1000 {
				return errors.New("scan queue capacity reached")
			}
			changes := securityForceChanges(t.Trigger, at)
			if err = tx.Model(&securityTaskRow{}).Where("id = ?", row.ID).Updates(changes).Error; err != nil {
				return err
			}
			if err = tx.First(&row, row.ID).Error; err != nil {
				return err
			}
		}
		result = taskDTO(row)
		return nil
	})
	return result, err
}
func (s *SecurityStore) Get(ctx context.Context, repo, revision, generation string) (*security.Task, *security.Report, error) {
	scope, err := s.scope(ctx, s.db, repo)
	if err != nil {
		return nil, nil, err
	}
	var row securityTaskRow
	err = securityTake(s.db.WithContext(ctx).Where("scope = ? AND revision = ? AND generation = ?", scope, revision, generation), &row)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var report *security.Report
	if row.ReportJSON != "" {
		report = &security.Report{}
		if err = json.Unmarshal([]byte(row.ReportJSON), report); err != nil {
			return nil, nil, err
		}
	}
	return taskDTO(row), report, nil
}
func (s *SecurityStore) Historical(ctx context.Context, repo, id string) (*security.Report, error) {
	scope, err := s.scope(ctx, s.db, repo)
	if err != nil {
		return nil, err
	}
	var row securityReportRow
	if err = s.db.WithContext(ctx).Where("scope = ? AND report_id = ?", scope, id).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.Join(&security.AdmissionError{Code: "ReportNotFound", Message: "Security report not found"}, err)
		}
		return nil, err
	}
	r := &security.Report{}
	if err = json.Unmarshal([]byte(row.ReportJSON), r); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *SecurityStore) Claim(ctx context.Context, generation string, now time.Time, lease time.Duration, maxAttempts int) (*security.Task, error) {
	if generation == "" || generation == "unavailable" {
		return nil, errors.New("healthy scanner generation is required to claim work")
	}
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	var result *security.Task
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.recoverUnavailable(ctx, tx, generation, now, "", ""); err != nil {
			return err
		}
		// Every expired claim loses its token before any new attempt starts.
		var expired []securityTaskRow
		if err := tx.Where("state = ? AND lease_until <= ?", "scanning", now).Find(&expired).Error; err != nil {
			return err
		}
		for _, old := range expired {
			state := "pending"
			reason := "expired worker lease; retry pending"
			if old.RetryCount+1 >= maxAttempts {
				state = "fail"
				reason = "expired worker retry limit reached"
			}
			changes := map[string]any{"state": state, "token": "", "lease_until": nil, "retry_count": old.RetryCount + 1, "error": reason, "updated_at": now}
			if err := tx.Model(&securityTaskRow{}).Where("id = ? AND state = ? AND token = ?", old.ID, "scanning", old.Token).Updates(changes).Error; err != nil {
				return err
			}
		}
		// Old rules must never publish an approval in a new engine generation.
		if err := tx.Model(&securityTaskRow{}).Where("state = ? AND generation <> ?", "pending", generation).
			Updates(map[string]any{"state": "fail", "error": "scan generation changed; current-generation scan required", "updated_at": now}).Error; err != nil {
			return err
		}
		var row securityTaskRow
		err := securityTake(tx.Where("state = ? AND generation = ?", "pending", generation).Order("id ASC"), &row)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		scope, err := s.scope(ctx, tx, row.Repo)
		if err != nil || scope != row.Scope {
			return tx.Model(&securityTaskRow{}).Where("id = ?", row.ID).Updates(map[string]any{"state": "fail", "error": "repository identity no longer exists", "updated_at": now}).Error
		}
		var tokenBytes [16]byte
		if _, err = rand.Read(tokenBytes[:]); err != nil {
			return err
		}
		token := hex.EncodeToString(tokenBytes[:])
		until := now.Add(lease)
		update := tx.Model(&securityTaskRow{}).Where("id = ? AND state = ?", row.ID, "pending").
			Updates(map[string]any{"state": "scanning", "token": token, "attempt": gorm.Expr("attempt + 1"), "lease_until": until, "updated_at": now, "error": ""})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected == 0 {
			return nil
		}
		if err = tx.First(&row, row.ID).Error; err != nil {
			return err
		}
		result = taskDTO(row)
		return nil
	})
	return result, err
}

// OwnsClaim is a read-only execution fence. Namespace reuse, cancellation,
// force rescans, recovered leases and rule transitions all invalidate work.
// Finish rechecks ownership transactionally before any report can be published.
func (s *SecurityStore) OwnsClaim(ctx context.Context, task *security.Task) (bool, error) {
	if task == nil || task.ID <= 0 || task.Attempt <= 0 || task.Token == "" || task.Scope == "" || task.Generation == "" {
		return false, nil
	}
	scope, err := s.scope(ctx, s.db, task.Repo)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil || scope != task.Scope {
		return false, err
	}
	var count int64
	err = s.db.WithContext(ctx).Model(&securityTaskRow{}).
		Where("id = ? AND scope = ? AND repo = ? AND revision = ? AND generation = ? AND state = ? AND attempt = ? AND token = ? AND lease_until > ?",
			task.ID, scope, task.Repo, task.Revision, task.Generation, "scanning", task.Attempt, task.Token, time.Now()).Count(&count).Error
	return count == 1 && err == nil, err
}

func validateSecurityReport(task *security.Task, r *security.Report) error {
	if task == nil || r == nil {
		return errors.New("report requires a claimed task")
	}
	if r.TaskID != task.ID || r.Attempt != task.Attempt || r.ReportID != fmt.Sprintf("%d-%d", task.ID, task.Attempt) || r.Repo != task.Repo || r.Revision != task.Revision || r.Generation != task.Generation {
		return errors.New("report identity does not match claimed task")
	}
	for _, f := range r.Files {
		if f.Generation == "" {
			// A global failure may leave staged, unanalysed placeholders. They
			// must not carry evidence disguised as an empty-generation result.
			if f.Complete || len(f.Findings) != 0 || len(f.Engines) != 0 || f.DurationMs != 0 {
				return errors.New("invalid unanalysed manifest entry")
			}
			continue
		}
		if err := validateSecurityAnalysis(security.Bundle{Generation: r.Generation, Engines: f.Engines}, f.Analysis); err != nil {
			return err
		}
	}
	if r.Complete {
		if r.State != security.Pass && r.State != security.Warn && r.State != security.Block {
			return errors.New("invalid complete report state")
		}
		if r.ExpectedFiles != len(r.Files) {
			return errors.New("manifest coverage count mismatch")
		}
		paths := map[string]bool{}
		for _, f := range r.Files {
			if paths[f.Path] || f.Path == "" || !f.Complete || f.Generation != r.Generation || f.ID == "" || len(f.Digest) != 64 || f.Artifact.Size != f.SourceFile.Size || len(f.Engines) < 2 {
				return errors.New("incomplete or inconsistent manifest entry")
			}
			if f.LFSOID != "" && f.LFSOID != f.Digest {
				return errors.New("LFS manifest digest mismatch")
			}
			paths[f.Path] = true
		}
	} else if r.State != security.Fail {
		return errors.New("partial report cannot be approved")
	}
	return nil
}
func (s *SecurityStore) Finish(ctx context.Context, t *security.Task, r *security.Report) (bool, error) {
	if err := validateSecurityReport(t, r); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	accepted := false
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scope, err := s.scope(ctx, tx, t.Repo)
		if err != nil {
			return err
		}
		if scope != t.Scope {
			return nil
		}
		now := time.Now()
		update := tx.Model(&securityTaskRow{}).Where("id = ? AND scope = ? AND state = ? AND token = ? AND attempt = ? AND lease_until > ?", t.ID, scope, "scanning", t.Token, t.Attempt, now).
			Updates(map[string]any{"state": string(r.State), "token": "", "lease_until": nil, "error": r.Error, "report_json": string(encoded), "updated_at": now})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected == 0 {
			return nil
		}
		if err = tx.Create(&securityReportRow{ReportID: r.ReportID, Scope: scope, Repo: t.Repo, TaskID: t.ID, Attempt: t.Attempt, ReportJSON: string(encoded), CreatedAt: now}).Error; err != nil {
			return err
		}
		if r.Complete {
			for _, f := range r.Files {
				analysis, err := json.Marshal(f.Analysis)
				if err != nil {
					return err
				}
				c := securityCacheRow{Scope: scope, Digest: f.Digest, Size: f.Artifact.Size, Type: f.Type, Generation: r.Generation, AnalysisJSON: string(analysis), CreatedAt: now}
				if err = tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "scope"}, {Name: "digest"}, {Name: "size"}, {Name: "type"}, {Name: "generation"}}, DoNothing: true}).Create(&c).Error; err != nil {
					return err
				}
			}
		}
		completeFiles := 0
		for _, f := range r.Files {
			if f.Complete {
				completeFiles++
			}
		}
		event := &security.Audit{Repo: t.Repo, Revision: t.Revision, Actor: "security-worker", Action: "scan-completed", Entry: "jobserver", CreatedAt: now,
			Completion: &security.ScanCompletion{TaskID: t.ID, Attempt: t.Attempt, ReportID: r.ReportID, Generation: r.Generation,
				State: r.State, Complete: r.Complete, ExpectedFiles: r.ExpectedFiles, ReportedFiles: len(r.Files),
				CompleteFiles: completeFiles, CachedFiles: r.CachedFiles, DurationMs: r.DurationMs}}
		auditJSON, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if err = tx.Create(&securityAuditRow{Scope: scope, Repo: t.Repo, EventJSON: string(auditJSON), CreatedAt: now}).Error; err != nil {
			return err
		}
		accepted = true
		return nil
	})
	return accepted && err == nil, err
}
func (s *SecurityStore) Cancel(ctx context.Context, id int64, repo string) (bool, error) {
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	cancelled := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scope, err := s.scope(ctx, tx, repo)
		if err != nil {
			return err
		}
		var row securityTaskRow
		err = securityTake(tx.Where("id = ? AND scope = ? AND state IN ?", id, scope, []string{"pending", "scanning"}), &row)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		// The known-generation row and an unresolved force row can represent
		// one intent. Cancel both directions, but never a later explicit rescan.
		result := tx.Model(&securityTaskRow{}).Where("scope = ? AND revision = ? AND state IN ? AND updated_at <= ?", scope, row.Revision, []string{"pending", "scanning"}, row.UpdatedAt).
			Updates(map[string]any{"state": "fail", "token": "", "lease_until": nil, "report_json": "", "error": securityCancelled, "updated_at": time.Now().UTC().Truncate(time.Millisecond)})
		cancelled = result.RowsAffected > 0
		return result.Error
	})
	return cancelled, err
}
func (s *SecurityStore) Cached(ctx context.Context, repo string, a security.Artifact, generation string) (*security.Analysis, error) {
	scope, err := s.scope(ctx, s.db, repo)
	if err != nil {
		return nil, err
	}
	var row securityCacheRow
	err = securityTake(s.db.WithContext(ctx).Where("scope = ? AND digest = ? AND size = ? AND type = ? AND generation = ?", scope, a.Digest, a.Size, a.Type, generation), &row)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result := &security.Analysis{}
	if err = json.Unmarshal([]byte(row.AnalysisJSON), result); err != nil {
		return nil, err
	}
	if !result.Complete || result.Generation != generation {
		return nil, nil
	}
	return result, nil
}
func (s *SecurityStore) Policy(ctx context.Context, repo string) (*security.Policy, error) {
	scope, err := s.scope(ctx, s.db, repo)
	if err != nil {
		return nil, err
	}
	var row securityPolicyRow
	err = securityTake(s.db.WithContext(ctx).Where("scope = ?", scope), &row)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &security.Policy{Repo: repo, Mode: row.Mode, BlockSeverity: row.BlockSeverity, Version: row.Version, UpdatedAt: row.UpdatedAt}, nil
}
func (s *SecurityStore) SetPolicy(ctx context.Context, p *security.Policy, audit *security.Audit) error {
	if p == nil || audit == nil || audit.Repo != p.Repo || audit.Action != "policy-update" {
		return errors.New("policy update requires matching audit evidence")
	}
	var saved security.Policy
	event := *audit
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scope, err := s.scope(ctx, tx, p.Repo)
		if err != nil {
			return err
		}
		row := securityPolicyRow{Scope: scope, Repo: p.Repo, Mode: p.Mode, BlockSeverity: p.BlockSeverity, Version: 2, UpdatedAt: p.UpdatedAt}
		if err = tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "scope"}}, DoUpdates: clause.Assignments(map[string]any{"mode": p.Mode, "block_severity": p.BlockSeverity, "version": gorm.Expr("version + 1"), "updated_at": p.UpdatedAt})}).Create(&row).Error; err != nil {
			return err
		}
		if err = tx.Where("scope = ?", scope).Take(&row).Error; err != nil {
			return err
		}
		saved = security.Policy{Repo: row.Repo, Mode: row.Mode, BlockSeverity: row.BlockSeverity, Version: row.Version, UpdatedAt: row.UpdatedAt}
		event.Decision = &security.Decision{Repo: row.Repo, Allowed: true, Code: "PolicyUpdated", PolicyVersion: row.Version,
			Message: fmt.Sprintf("mode=%s; blockSeverity=%s", row.Mode, row.BlockSeverity)}
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		auditRow := securityAuditRow{Scope: scope, Repo: event.Repo, EventJSON: string(encoded), CreatedAt: event.CreatedAt}
		if err = tx.Create(&auditRow).Error; err != nil {
			return err
		}
		event.ID = auditRow.ID
		return nil
	})
	if err == nil {
		*p = saved
		*audit = event
	}
	return err
}
func (s *SecurityStore) AppendAudit(ctx context.Context, a *security.Audit) error {
	scope, err := s.scope(ctx, s.db, a.Repo)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(a)
	if err != nil {
		return err
	}
	row := securityAuditRow{Scope: scope, Repo: a.Repo, EventJSON: string(encoded), CreatedAt: a.CreatedAt}
	if err = s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return err
	}
	a.ID = row.ID
	return nil
}
func securityPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
func (s *SecurityStore) Audits(ctx context.Context, repo string, limit, offset int) ([]security.Audit, error) {
	scope, err := s.scope(ctx, s.db, repo)
	if err != nil {
		return nil, err
	}
	limit, offset = securityPage(limit, offset)
	var rows []securityAuditRow
	if err = s.db.WithContext(ctx).Where("scope = ?", scope).Order("id DESC").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]security.Audit, 0, len(rows))
	for _, row := range rows {
		var a security.Audit
		if err = json.Unmarshal([]byte(row.EventJSON), &a); err != nil {
			return nil, err
		}
		a.ID = row.ID
		out = append(out, a)
	}
	return out, nil
}
func (s *SecurityStore) Tasks(ctx context.Context, repo string, limit, offset int) ([]security.Task, error) {
	scope, err := s.scope(ctx, s.db, repo)
	if err != nil {
		return nil, err
	}
	limit, offset = securityPage(limit, offset)
	var rows []securityTaskRow
	if err = s.db.WithContext(ctx).Where("scope = ?", scope).Order("id DESC").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]security.Task, 0, len(rows))
	for _, row := range rows {
		out = append(out, *taskDTO(row))
	}
	return out, nil
}

var _ security.Store = (*SecurityStore)(nil)
