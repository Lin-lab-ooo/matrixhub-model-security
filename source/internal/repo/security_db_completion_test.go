// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func TestSecurityFinishAuditsEachTerminalAttemptOnce(t *testing.T) {
	for _, state := range []security.State{security.Pass, security.Warn, security.Block, security.Fail} {
		t.Run(string(state), func(t *testing.T) {
			store, _ := securityTestStore(t)
			enqueueSecurityTask(t, store, "alpha/m")
			claim := claimSecurityTask(t, store)
			report := completeSecurityReport(claim)
			report.State = state
			report.DurationMs = 12
			completeFiles := 1
			if state == security.Fail {
				completeFiles = 0
				report.Complete = false
				report.Error = "scanner did not provide complete coverage: malformed_pickle"
				report.Files[0].Complete = false
				report.Files[0].Findings = []security.Finding{securityEvidenceFinding(), securityFileFailureFinding("malformed_pickle")}
			}
			accepted, err := store.Finish(t.Context(), claim, report)
			require.NoError(t, err)
			require.True(t, accepted)
			accepted, err = store.Finish(t.Context(), claim, report)
			require.NoError(t, err)
			require.False(t, accepted)
			events, err := store.Audits(t.Context(), claim.Repo, 50, 0)
			require.NoError(t, err)
			require.Len(t, events, 1)
			event := events[0]
			require.Equal(t, "scan-completed", event.Action)
			require.Equal(t, "security-worker", event.Actor)
			require.Equal(t, "jobserver", event.Entry)
			require.Equal(t, claim.Repo, event.Repo)
			require.Equal(t, claim.Revision, event.Revision)
			require.Nil(t, event.Decision)
			require.Equal(t, &security.ScanCompletion{TaskID: claim.ID, Attempt: claim.Attempt, ReportID: report.ReportID,
				Generation: claim.Generation, State: state, Complete: report.Complete, ExpectedFiles: 1, ReportedFiles: 1,
				CompleteFiles: completeFiles, CachedFiles: 0, DurationMs: 12}, event.Completion)
			historical, err := store.Historical(t.Context(), claim.Repo, report.ReportID)
			require.NoError(t, err)
			require.Equal(t, report.Files, historical.Files)
			if state == security.Fail {
				cached, err := store.Cached(t.Context(), claim.Repo, report.Files[0].Artifact, claim.Generation)
				require.NoError(t, err)
				require.Nil(t, cached)
			}
		})
	}
}

func TestSecurityCompletionAuditFailureRollsBackPublicationAndCanRetry(t *testing.T) {
	store, db := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	report := completeSecurityReport(claim)
	require.NoError(t, db.Migrator().DropTable(&securityAuditRow{}))
	accepted, err := store.Finish(t.Context(), claim, report)
	require.Error(t, err)
	require.False(t, accepted)
	task, current, err := store.Get(t.Context(), claim.Repo, claim.Revision, claim.Generation)
	require.NoError(t, err)
	require.Nil(t, current)
	require.Equal(t, security.Scanning, task.State)
	require.Equal(t, claim.Token, task.Token)
	_, err = store.Historical(t.Context(), claim.Repo, report.ReportID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	cached, err := store.Cached(t.Context(), claim.Repo, report.Files[0].Artifact, claim.Generation)
	require.NoError(t, err)
	require.Nil(t, cached)
	require.NoError(t, db.Migrator().CreateTable(&securityAuditRow{}))
	accepted, err = store.Finish(t.Context(), claim, report)
	require.NoError(t, err)
	require.True(t, accepted)
	events, err := store.Audits(t.Context(), claim.Repo, 50, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, report.ReportID, events[0].Completion.ReportID)
}

func TestSecurityRejectedCompletionClaimsEmitNoAudit(t *testing.T) {
	for _, reason := range []string{"expired", "cancelled", "replaced"} {
		t.Run(reason, func(t *testing.T) {
			store, db := securityTestStore(t)
			original := enqueueSecurityTask(t, store, "alpha/m")
			claim := claimSecurityTask(t, store)
			switch reason {
			case "expired":
				require.NoError(t, db.Model(&securityTaskRow{}).Where("id = ?", claim.ID).Update("lease_until", time.Now().Add(-time.Second)).Error)
			case "cancelled":
				accepted, err := store.Cancel(t.Context(), claim.ID, claim.Repo)
				require.NoError(t, err)
				require.True(t, accepted)
			case "replaced":
				original.UpdatedAt = time.Now()
				_, err := store.Enqueue(t.Context(), original, true)
				require.NoError(t, err)
			}
			accepted, err := store.Finish(t.Context(), claim, completeSecurityReport(claim))
			require.NoError(t, err)
			require.False(t, accepted)
			events, err := store.Audits(t.Context(), claim.Repo, 50, 0)
			require.NoError(t, err)
			require.Empty(t, events)
		})
	}
}

func TestSecurityForceRescanCompletionAuditsBindDifferentAttempts(t *testing.T) {
	store, _ := securityTestStore(t)
	original := enqueueSecurityTask(t, store, "alpha/m")
	first := claimSecurityTask(t, store)
	firstReport := completeSecurityReport(first)
	accepted, err := store.Finish(t.Context(), first, firstReport)
	require.NoError(t, err)
	require.True(t, accepted)
	original.UpdatedAt = time.Now()
	_, err = store.Enqueue(t.Context(), original, true)
	require.NoError(t, err)
	second := claimSecurityTask(t, store)
	secondReport := completeSecurityReport(second)
	accepted, err = store.Finish(t.Context(), second, secondReport)
	require.NoError(t, err)
	require.True(t, accepted)
	events, err := store.Audits(t.Context(), original.Repo, 50, 0)
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, secondReport.ReportID, events[0].Completion.ReportID)
	require.Equal(t, second.Attempt, events[0].Completion.Attempt)
	require.Equal(t, firstReport.ReportID, events[1].Completion.ReportID)
	require.Equal(t, first.Attempt, events[1].Completion.Attempt)
	require.NotEqual(t, events[0].Completion.ReportID, events[1].Completion.ReportID)
	historical, err := store.Historical(t.Context(), original.Repo, firstReport.ReportID)
	require.NoError(t, err)
	require.Equal(t, firstReport.ReportID, historical.ReportID)
}

func TestSecurityPartialReportsRejectUnboundOrUncontrolledAnalyses(t *testing.T) {
	cases := []struct {
		name   string
		change func(*security.Analysis)
		valid  bool
	}{
		{"controlled-partial", func(a *security.Analysis) {
			a.Complete = false
			a.Findings = []security.Finding{securityFileFailureFinding("malformed_pickle")}
		}, true},
		{"unanalysed-placeholder", func(a *security.Analysis) { *a = security.Analysis{} }, true},
		{"bare-incomplete", func(a *security.Analysis) { a.Complete = false }, false},
		{"empty-generation-evidence", func(a *security.Analysis) {
			a.Generation = ""
			a.Complete = false
			a.Findings = []security.Finding{securityFileFailureFinding("malformed_pickle")}
		}, false},
		{"empty-generation-engines", func(a *security.Analysis) { a.Generation = ""; a.Complete = false }, false},
		{"uncontrolled-code", func(a *security.Analysis) {
			a.Complete = false
			a.Findings = []security.Finding{securityFileFailureFinding("expanded_bytes_limit")}
		}, false},
		{"wrong-generation", func(a *security.Analysis) { a.Generation = "other" }, false},
		{"invalid-evidence", func(a *security.Analysis) {
			f := securityEvidenceFinding()
			f.Evidence.Observation = "executed"
			a.Findings = []security.Finding{f}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := securityTestStore(t)
			enqueueSecurityTask(t, store, "alpha/m")
			claim := claimSecurityTask(t, store)
			report := completeSecurityReport(claim)
			report.Complete = false
			report.State = security.Fail
			report.Error = fmt.Sprintf("test failure: %s", tc.name)
			tc.change(&report.Files[0].Analysis)
			accepted, err := store.Finish(t.Context(), claim, report)
			if tc.valid {
				require.NoError(t, err)
				require.True(t, accepted)
			} else {
				require.Error(t, err)
				require.False(t, accepted)
				events, err := store.Audits(t.Context(), claim.Repo, 50, 0)
				require.NoError(t, err)
				require.Empty(t, events)
			}
		})
	}
}
