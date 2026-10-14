// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security

import (
	"context"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Review is an append-only human opinion about an immutable machine report.
// It is never an input to machine state, cache eligibility or download admission.
type Review struct {
	ID         int64     `json:"id"`
	Repo       string    `json:"repo"`
	ReportID   string    `json:"reportId"`
	Revision   string    `json:"revision"`
	Generation string    `json:"generation"`
	ActorID    int64     `json:"actorId"`
	Actor      string    `json:"actor"`
	Verdict    string    `json:"verdict"`
	Comment    string    `json:"comment"`
	CreatedAt  time.Time `json:"createdAt"`
}

type ReviewInput struct {
	Revision   string `json:"revision"`
	Generation string `json:"generation"`
	Verdict    string `json:"verdict"`
	Comment    string `json:"comment"`
}

// ReviewStore must revalidate report scope/identity and atomically append the
// review and its general audit event. It exposes no update/delete operation.
type ReviewStore interface {
	AppendReview(context.Context, *Review, string) error
	Reviews(context.Context, string, string, int, int) ([]Review, error)
}

type ReviewActor func(context.Context) (int64, string)
type ServiceOption func(*Service)

func WithReviews(store ReviewStore, actor ReviewActor) ServiceOption {
	return func(s *Service) { s.reviews, s.reviewer = store, actor }
}

var immutableReviewReportID = regexp.MustCompile(`^[1-9][0-9]*-[1-9][0-9]*$`)

func ValidateReviewInput(input ReviewInput) error {
	_, generationErr := hex.DecodeString(input.Generation)
	if !validCommit(input.Revision) || len(input.Generation) != 64 || generationErr != nil || strings.ToLower(input.Generation) != input.Generation {
		return &AdmissionError{Code: "InvalidArgument", Message: "An immutable revision and scanner generation are required"}
	}
	if input.Verdict != "confirmed_risk" && input.Verdict != "false_positive" && input.Verdict != "needs_followup" {
		return &AdmissionError{Code: "InvalidArgument", Message: "A supported review verdict is required"}
	}
	if !utf8.ValidString(input.Comment) || strings.TrimSpace(input.Comment) == "" || utf8.RuneCountInString(input.Comment) > 1000 || strings.ContainsRune(input.Comment, '\x00') {
		return &AdmissionError{Code: "InvalidArgument", Message: "Review comments require 1-1000 Unicode characters without NUL"}
	}
	return nil
}

func (s *Service) reviewReport(ctx context.Context, repo, id string) (*Report, error) {
	if len(id) > 64 || !immutableReviewReportID.MatchString(id) {
		return nil, &AdmissionError{Code: "InvalidArgument", Message: "An immutable task-attempt report ID is required"}
	}
	report, err := s.store.Historical(ctx, repo, id)
	if err != nil {
		return nil, err
	}
	if report == nil || report.Repo != repo || report.ReportID != id {
		return nil, &AdmissionError{Code: "ReportNotFound", Message: "Security report not found"}
	}
	if report.State != Pass && report.State != Warn && report.State != Block && report.State != Fail {
		return nil, &AdmissionError{Code: "ReviewNotReady", Message: "Only a terminal machine report can be reviewed"}
	}
	return report, nil
}

func (s *Service) AddReview(ctx context.Context, repo, id string, input ReviewInput) (*Review, error) {
	if err := s.auth(ctx, repo, "write"); err != nil {
		return nil, err
	}
	if s.reviews == nil || s.reviewer == nil {
		return nil, &AdmissionError{Code: "SecurityUnavailable", Message: "Human review storage is unavailable"}
	}
	actorID, actor := s.reviewer(ctx)
	if actorID <= 0 || actor == "" {
		return nil, &AdmissionError{Code: "Unauthenticated", Message: "A named reviewer identity is required"}
	}
	if err := ValidateReviewInput(input); err != nil {
		return nil, err
	}
	report, err := s.reviewReport(ctx, repo, id)
	if err != nil {
		return nil, err
	}
	if report.Revision != input.Revision || report.Generation != input.Generation {
		return nil, &AdmissionError{Code: "ReviewBindingMismatch", Message: "Review identity does not match the selected immutable report"}
	}
	review := &Review{Repo: repo, ReportID: id, Revision: report.Revision, Generation: report.Generation,
		ActorID: actorID, Actor: actor, Verdict: input.Verdict, Comment: input.Comment, CreatedAt: s.now().UTC()}
	entry, _ := ctx.Value(entryKey{}).(string)
	if err = s.reviews.AppendReview(ctx, review, entry); err != nil {
		return nil, err
	}
	return review, nil
}

func (s *Service) Reviews(ctx context.Context, repo, id string, limit, offset int) ([]Review, error) {
	if err := s.auth(ctx, repo, "read"); err != nil {
		return nil, err
	}
	if s.reviews == nil {
		return nil, &AdmissionError{Code: "SecurityUnavailable", Message: "Human review storage is unavailable"}
	}
	if limit < 1 || limit > 200 || offset < 0 || offset > 1000000 {
		return nil, &AdmissionError{Code: "InvalidArgument", Message: "Invalid review pagination"}
	}
	if _, err := s.reviewReport(ctx, repo, id); err != nil {
		return nil, err
	}
	return s.reviews.Reviews(ctx, repo, id, limit, offset)
}
