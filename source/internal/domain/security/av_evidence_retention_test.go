// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func retainedAntivirusAnalysis() security.Analysis {
	return security.Analysis{Complete: false, Findings: []security.Finding{
		{Engine: "clamav", Rule: "malware.signature-match", Severity: "critical", Message: "ClamAV matched a malware or dangerous-content signature.", Remediation: security.FileAnalysisFailureRemediation},
		{Engine: "clamav", Rule: "clamav.Eicar-Test-Signature", Severity: "critical", Message: "ClamAV matched a malware or dangerous-content signature.", Remediation: security.FileAnalysisFailureRemediation},
		{Engine: "coverage", Rule: "coverage.pickle_argument_limit", Severity: "high", Message: security.FileAnalysisFailureMessage, Remediation: security.FileAnalysisFailureRemediation},
	}}
}

func TestSecurityRetainsAVOperandFailureOnlyWithExactConfirmedEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*security.Analysis)
		valid  bool
	}{
		{"confirmed native hit retained", func(a *security.Analysis) {}, true},
		{"no canonical hit", func(a *security.Analysis) { a.Findings = a.Findings[1:] }, false},
		{"specific prefix cannot authorize retention", func(a *security.Analysis) { a.Findings[0].Rule = "clamav.UnknownSignature" }, false},
		{"unknown engine", func(a *security.Analysis) { a.Findings[0].Engine = "unknown" }, false},
		{"wrong canonical severity", func(a *security.Analysis) { a.Findings[0].Severity = "high" }, false},
		{"wrong canonical message", func(a *security.Analysis) { a.Findings[0].Message = "unverified" }, false},
		{"wrong canonical remediation", func(a *security.Analysis) { a.Findings[0].Remediation = "unverified" }, false},
		{"canonical evidence prohibited", func(a *security.Analysis) { a.Findings[0].Evidence = &security.FindingEvidence{} }, false},
		{"cannot become complete", func(a *security.Analysis) { a.Complete = true }, false},
		{"missing coverage", func(a *security.Analysis) { a.Findings = a.Findings[:2] }, false},
		{"multiple coverage failures", func(a *security.Analysis) { a.Findings = append(a.Findings, a.Findings[2]) }, false},
		{"coverage engine mismatch", func(a *security.Analysis) { a.Findings[2].Engine = "clamav" }, false},
		{"coverage severity mismatch", func(a *security.Analysis) { a.Findings[2].Severity = "critical" }, false},
		{"coverage message mismatch", func(a *security.Analysis) { a.Findings[2].Message = "unverified" }, false},
		{"coverage remediation mismatch", func(a *security.Analysis) { a.Findings[2].Remediation = "unverified" }, false},
		{"coverage evidence prohibited", func(a *security.Analysis) { a.Findings[2].Evidence = &security.FindingEvidence{} }, false},
		{"global timeout cannot be retained", func(a *security.Analysis) { a.Findings[2].Rule = "coverage.scan_timeout" }, false},
		{"opcode limit not generalized", func(a *security.Analysis) { a.Findings[2].Rule = "coverage.pickle_opcode_limit" }, false},
		{"identity failure cannot be retained", func(a *security.Analysis) { a.Findings[2].Rule = "coverage.snapshot_digest" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := retainedAntivirusAnalysis()
			tc.mutate(&a)
			err := security.ValidateAnalysisCoverage(a)
			if tc.valid {
				require.NoError(t, err)
				require.False(t, a.Complete)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestSecurityAVOperandFailureIsPersistedButNeverApprovesVersion(t *testing.T) {
	for _, capacity := range []int{0, 2} {
		t.Run(fmt.Sprintf("batch-capacity=%d", capacity), func(t *testing.T) {
			f, batch, task, clean := setupBatch(t, 2, capacity, 1024)
			partial := retainedAntivirusAnalysis()
			partial.Generation = clean.Generation
			partial.Engines = clean.Engines
			if capacity == 0 {
				gomock.InOrder(
					f.scanner.EXPECT().Analyze(gomock.Any(), gomock.Any()).Return(partial, nil),
					f.scanner.EXPECT().Analyze(gomock.Any(), gomock.Any()).Return(clean, nil),
				)
			} else {
				batch.EXPECT().AnalyzeBatch(gomock.Any(), gomock.Any()).Return([]security.Analysis{partial, clean}, nil)
			}
			f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
				require.False(t, r.Complete)
				require.Equal(t, security.Fail, r.State)
				require.Len(t, r.Files, 2)
				require.False(t, r.Files[0].Complete)
				require.Equal(t, partial.Findings, r.Files[0].Findings)
				require.Equal(t, clean.Generation, r.Files[0].Generation)
				require.True(t, r.Files[1].Complete)
				f.report = r
				return true, nil
			})
			processErr := f.svc.Process(t.Context(), task)
			require.ErrorContains(t, processErr, "did not provide complete coverage")
			require.ErrorContains(t, processErr, "pickle_argument_limit")
			for _, mode := range []string{"enforce", "audit"} {
				f.policy.Mode = mode
				d, err := f.svc.Check(t.Context(), scope, revision, "file-1.pkl", "", 0)
				require.False(t, d.Allowed)
				require.Equal(t, "RevisionFailed", admissionCode(t, err))
			}
		})
	}
}
