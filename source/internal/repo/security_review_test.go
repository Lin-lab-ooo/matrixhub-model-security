// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func reviewDatabaseFixture(t *testing.T) (*SecurityStore, *gorm.DB, *security.Report) {
	t.Helper()
	s, db := securityTestStore(t)
	gen := strings.Repeat("a", 64)
	now := time.Now()
	_, err := s.Enqueue(t.Context(), &security.Task{Repo: "alpha/m", Revision: testSecurityCommit, Generation: gen, State: security.Pending, CreatedAt: now, UpdatedAt: now}, false)
	require.NoError(t, err)
	task, err := s.Claim(t.Context(), gen, now, time.Minute, 3)
	require.NoError(t, err)
	require.NotNil(t, task)
	r := completeSecurityReport(task)
	ok, err := s.Finish(t.Context(), task, r)
	require.NoError(t, err)
	require.True(t, ok)
	return s, db, r
}

func reviewRecord(r *security.Report, comment string) *security.Review {
	return &security.Review{Repo: r.Repo, ReportID: r.ReportID, Revision: r.Revision, Generation: r.Generation,
		ActorID: 123, Actor: "user:reviewer", Verdict: "false_positive", Comment: comment, CreatedAt: time.Now().UTC()}
}

func TestSecurityReviewAppendAuditAndStableReport(t *testing.T) {
	s, db, r := reviewDatabaseFixture(t)
	before, err := s.Historical(t.Context(), r.Repo, r.ReportID)
	require.NoError(t, err)
	encoded, err := json.Marshal(before)
	require.NoError(t, err)
	var cacheBefore int64
	require.NoError(t, db.Model(&securityCacheRow{}).Count(&cacheBefore).Error)
	for _, comment := range []string{"第一次复核 <script>inert text</script>", "更正意见仅追加"} {
		review := reviewRecord(r, comment)
		require.NoError(t, s.AppendReview(t.Context(), review, "rest-security"))
		require.Positive(t, review.ID)
	}
	rows, err := s.Reviews(t.Context(), r.Repo, r.ReportID, 1, 0)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "更正意见仅追加", rows[0].Comment)
	older, err := s.Reviews(t.Context(), r.Repo, r.ReportID, 1, 1)
	require.NoError(t, err)
	require.Len(t, older, 1)
	require.Greater(t, rows[0].ID, older[0].ID)
	audits, err := s.Audits(t.Context(), r.Repo, 50, 0)
	require.NoError(t, err)
	var reviewAudits int
	for _, audit := range audits {
		if audit.Action == "manual-review" {
			reviewAudits++
			require.NotNil(t, audit.Review)
			require.Nil(t, audit.Decision)
			require.Equal(t, r.ReportID, audit.Review.ReportID)
			require.Equal(t, int64(123), audit.Review.ActorID)
		}
	}
	require.Equal(t, 2, reviewAudits)
	after, err := s.Historical(t.Context(), r.Repo, r.ReportID)
	require.NoError(t, err)
	afterJSON, err := json.Marshal(after)
	require.NoError(t, err)
	require.Equal(t, encoded, afterJSON)
	var cacheAfter int64
	require.NoError(t, db.Model(&securityCacheRow{}).Count(&cacheAfter).Error)
	require.Equal(t, cacheBefore, cacheAfter)
}

func TestSecurityReviewTransactionRollsBackIfAuditFails(t *testing.T) {
	s, db, r := reviewDatabaseFixture(t)
	failure := errors.New("injected audit write failure")
	name := "review-audit-failure"
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == "security_audit" {
			tx.AddError(failure)
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Create().Remove(name) })
	review := reviewRecord(r, "必须原子提交")
	require.ErrorIs(t, s.AppendReview(t.Context(), review, "rest-security"), failure)
	require.Zero(t, review.ID)
	var count int64
	require.NoError(t, db.Model(&securityReviewRow{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestSecurityReviewScopeAndReportIdentityFenced(t *testing.T) {
	s, db, r := reviewDatabaseFixture(t)
	for _, mutation := range []string{"repo", "generation", "revision"} {
		review := reviewRecord(r, "绑定检查")
		switch mutation {
		case "repo":
			review.Repo = "beta/m"
		case "generation":
			review.Generation = strings.Repeat("b", 64)
		case "revision":
			review.Revision = strings.Repeat("2", 40)
		}
		require.Error(t, s.AppendReview(t.Context(), review, "rest-security"))
		require.Zero(t, review.ID)
	}
	review := reviewRecord(r, "原model记录")
	require.NoError(t, s.AppendReview(t.Context(), review, "rest-security"))
	other, err := s.Reviews(t.Context(), "beta/m", r.ReportID, 50, 0)
	require.NoError(t, err)
	require.Empty(t, other)
	require.NoError(t, db.Exec("DELETE FROM models WHERE name='m' AND project_id=(SELECT id FROM projects WHERE name='alpha')").Error)
	require.NoError(t, db.Exec("INSERT INTO models(name,project_id,size,default_branch,parameter_count,readme_content) SELECT 'm',id,0,'main',0,'' FROM projects WHERE name='alpha'").Error)
	reused, err := s.Reviews(context.Background(), r.Repo, r.ReportID, 50, 0)
	require.NoError(t, err)
	require.Empty(t, reused)
	require.Error(t, s.AppendReview(t.Context(), reviewRecord(r, "不得继承旧报告"), "rest-security"))
}

func TestSecurityReviewMissingHistoryIsTypedNotFound(t *testing.T) {
	s, _, r := reviewDatabaseFixture(t)
	_, err := s.Historical(t.Context(), "beta/m", r.ReportID)
	var admission *security.AdmissionError
	require.ErrorAs(t, err, &admission)
	require.Equal(t, "ReportNotFound", admission.Code)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}
