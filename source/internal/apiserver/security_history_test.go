// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
)

func TestSecurityNativeCommitPolicyDisabled(t *testing.T) {
	hide, err := nativeCommitDiffPolicy(nil)(t.Context(), "proj/model")
	require.NoError(t, err)
	require.False(t, hide)
	gate := mocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(false)
	hide, err = nativeCommitDiffPolicy(gate)(t.Context(), "proj/model")
	require.NoError(t, err)
	require.False(t, hide)
}

func TestSecurityNativeCommitPolicyOnlyKnownDenialHidesDiff(t *testing.T) {
	known := &security.AdmissionError{Code: "RawGitDisabled", State: security.Block}
	for _, tc := range []struct {
		name string
		err  error
		hide bool
	}{
		{name: "audit-allowed"},
		{name: "enforce", err: known, hide: true},
		{name: "wrapped-enforce", err: fmt.Errorf("decision: %w", known), hide: true},
		{name: "invalid-policy", err: &security.AdmissionError{Code: "PolicyInvalid", State: security.Fail}},
		{name: "authorization", err: &security.AdmissionError{Code: "PermissionDenied", State: security.Fail}},
		{name: "policy-read", err: errors.New("policy read unavailable")},
		{name: "audit-write", err: errors.New("audit write unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := mocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(true)
			gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(tc.err)
			hide, err := nativeCommitDiffPolicy(gate)(t.Context(), "proj/model")
			require.Equal(t, tc.hide, hide)
			if tc.hide || tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestSecurityNativeCommitPolicyAuditsCanonicalRepository(t *testing.T) {
	store := mocks.NewMockStore(gomock.NewController(t))
	store.EXPECT().Policy(gomock.Any(), "proj/model").Return(&security.Policy{
		Repo: "proj/model", Mode: "enforce", BlockSeverity: "high", Version: 12,
	}, nil)
	store.EXPECT().AppendAudit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, audit *security.Audit) error {
		require.Equal(t, "native-commit-diff", audit.Entry)
		require.Equal(t, "proj/model", audit.Repo)
		require.Equal(t, int64(12), audit.Decision.PolicyVersion)
		require.Equal(t, "RawGitDisabled", audit.Decision.Code)
		require.False(t, audit.Decision.Allowed)
		return nil
	})
	service := security.NewService(store, nil, nil, security.Settings{Enabled: true, Mode: "audit"},
		func(_ context.Context, repository, operation string) error {
			require.Equal(t, "proj/model", repository)
			require.Equal(t, "read", operation)
			return nil
		}, nil)
	hide, err := nativeCommitDiffPolicy(service)(t.Context(), "proj/model")
	require.NoError(t, err)
	require.True(t, hide)
}
