// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

type securityReviewRow struct {
	ID         int64 `gorm:"primaryKey"`
	Scope      string
	Repo       string
	ReportID   string
	Revision   string
	Generation string
	ActorID    int64
	Actor      string
	Verdict    string
	Comment    string
	CreatedAt  time.Time
}

func (securityReviewRow) TableName() string { return "security_reviews" }

func (r securityReviewRow) dto() security.Review {
	return security.Review{ID: r.ID, Repo: r.Repo, ReportID: r.ReportID, Revision: r.Revision,
		Generation: r.Generation, ActorID: r.ActorID, Actor: r.Actor, Verdict: r.Verdict,
		Comment: r.Comment, CreatedAt: r.CreatedAt}
}

// AppendReview resolves the live model identity inside the transaction, preventing
// a deleted/recreated namespace from inheriting a previous model's review.
func (s *SecurityStore) AppendReview(ctx context.Context, review *security.Review, entry string) error {
	if review == nil || review.ID != 0 || review.ActorID <= 0 || review.Actor == "" || len(review.Actor) > 512 || review.CreatedAt.IsZero() || len(entry) > 128 {
		return errors.New("invalid append-only security review")
	}
	if err := security.ValidateReviewInput(security.ReviewInput{Revision: review.Revision, Generation: review.Generation, Verdict: review.Verdict, Comment: review.Comment}); err != nil {
		return err
	}
	var committedID int64
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scope, err := s.scope(ctx, tx, review.Repo)
		if err != nil {
			return err
		}
		var stored securityReportRow
		if err = securityTake(tx.Where("scope = ? AND report_id = ?", scope, review.ReportID), &stored); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return &security.AdmissionError{Code: "ReportNotFound", Message: "Security report not found"}
			}
			return err
		}
		var report security.Report
		if err = json.Unmarshal([]byte(stored.ReportJSON), &report); err != nil {
			return err
		}
		if report.Repo != review.Repo || report.ReportID != review.ReportID || report.Revision != review.Revision || report.Generation != review.Generation ||
			(report.State != security.Pass && report.State != security.Warn && report.State != security.Block && report.State != security.Fail) {
			return &security.AdmissionError{Code: "ReviewBindingMismatch", Message: "Review identity does not match a terminal machine report"}
		}
		row := securityReviewRow{Scope: scope, Repo: review.Repo, ReportID: review.ReportID, Revision: review.Revision,
			Generation: review.Generation, ActorID: review.ActorID, Actor: review.Actor, Verdict: review.Verdict,
			Comment: review.Comment, CreatedAt: review.CreatedAt}
		if err = tx.Create(&row).Error; err != nil {
			return err
		}
		copy := row.dto()
		audit := security.Audit{Repo: copy.Repo, Revision: copy.Revision, Actor: copy.Actor,
			Action: "manual-review", Entry: entry, CreatedAt: copy.CreatedAt, Review: &copy}
		encoded, err := json.Marshal(audit)
		if err != nil {
			return err
		}
		if err = tx.Create(&securityAuditRow{Scope: scope, Repo: copy.Repo, EventJSON: string(encoded), CreatedAt: copy.CreatedAt}).Error; err != nil {
			return err
		}
		committedID = row.ID
		return nil
	})
	if err == nil {
		review.ID = committedID
	}
	return err
}

func (s *SecurityStore) Reviews(ctx context.Context, repo, reportID string, limit, offset int) ([]security.Review, error) {
	scope, err := s.scope(ctx, s.db, repo)
	if err != nil {
		return nil, err
	}
	limit, offset = securityPage(limit, offset)
	var rows []securityReviewRow
	if err = s.db.WithContext(ctx).Where("scope = ? AND report_id = ?", scope, reportID).
		Order("id DESC").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]security.Review, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.dto())
	}
	return out, nil
}

var _ security.ReviewStore = (*SecurityStore)(nil)
