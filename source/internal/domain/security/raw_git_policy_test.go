// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
)

func TestRawGitPolicyRespectsGlobalAndRepositoryEnforcement(t *testing.T) {
	for _, global := range []string{"audit", "enforce"} {
		for _, repositoryMode := range []string{"audit", "enforce"} {
			t.Run(global+"/"+repositoryMode, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				store := mocks.NewMockStore(ctrl)
				ctx := security.WithEntry(t.Context(), "git-http")
				authCalls := 0
				svc := security.NewService(store, nil, nil, security.Settings{Enabled: true, Mode: global},
					func(got context.Context, repo, op string) error {
						require.Same(t, ctx, got)
						require.Equal(t, scope, repo)
						require.Equal(t, "read", op)
						authCalls++
						return nil
					}, nil)
				store.EXPECT().Policy(ctx, scope).Return(&security.Policy{Repo: scope, Mode: repositoryMode, BlockSeverity: "high", Version: 7}, nil)
				deny := global == "enforce" || repositoryMode == "enforce"
				store.EXPECT().AppendAudit(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, audit *security.Audit) error {
					require.Equal(t, "git-http", audit.Entry)
					require.Equal(t, scope, audit.Repo)
					require.Equal(t, "raw-git", audit.Action)
					require.Equal(t, int64(7), audit.Decision.PolicyVersion)
					require.Equal(t, !deny, audit.Decision.Allowed)
					return nil
				})
				err := svc.DenyRawGit(ctx, scope)
				if deny {
					require.Equal(t, "RawGitDisabled", admissionCode(t, err))
				} else {
					require.NoError(t, err)
				}
				require.Equal(t, 1, authCalls)
			})
		}
	}
}

func TestRawGitPolicyFallsBackToGlobalMode(t *testing.T) {
	for _, mode := range []string{"audit", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mocks.NewMockStore(ctrl)
			store.EXPECT().Policy(gomock.Any(), scope).Return(nil, nil)
			store.EXPECT().AppendAudit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, audit *security.Audit) error {
				require.Equal(t, int64(1), audit.Decision.PolicyVersion)
				require.Equal(t, mode == "audit", audit.Decision.Allowed)
				return nil
			})
			svc := security.NewService(store, nil, nil, security.Settings{Enabled: true, Mode: mode}, func(context.Context, string, string) error { return nil }, nil)
			err := svc.DenyRawGit(t.Context(), scope)
			if mode == "enforce" {
				require.Equal(t, "RawGitDisabled", admissionCode(t, err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRawGitDisabledDoesNotReadAuthorizationOrPolicy(t *testing.T) {
	svc := security.NewService(nil, nil, nil, security.Settings{}, nil, nil)
	require.NoError(t, svc.DenyRawGit(t.Context(), scope))
}

func TestRawGitAuthorizationAndPolicyErrorsFailClosed(t *testing.T) {
	for _, failure := range []string{"authorization", "policy-read", "audit-write"} {
		t.Run(failure, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mocks.NewMockStore(ctrl)
			want := errors.New(failure + " unavailable")
			authorize := func(context.Context, string, string) error {
				if failure == "authorization" {
					return want
				}
				return nil
			}
			if failure == "policy-read" {
				store.EXPECT().Policy(gomock.Any(), scope).Return(nil, want)
			} else if failure == "audit-write" {
				store.EXPECT().Policy(gomock.Any(), scope).Return(&security.Policy{Repo: scope, Mode: "audit", BlockSeverity: "high", Version: 3}, nil)
				store.EXPECT().AppendAudit(gomock.Any(), gomock.Any()).Return(want)
			}
			svc := security.NewService(store, nil, nil, security.Settings{Enabled: true, Mode: "audit"}, authorize, nil)
			require.ErrorIs(t, svc.DenyRawGit(t.Context(), scope), want)
		})
	}
}

func TestRawGitCorruptPolicyCannotPermitHistory(t *testing.T) {
	for _, failure := range []string{"repository", "mode", "version", "severity"} {
		t.Run(failure, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mocks.NewMockStore(ctrl)
			policy := &security.Policy{Repo: scope, Mode: "audit", BlockSeverity: "high", Version: 2}
			switch failure {
			case "repository":
				policy.Repo = "other/model"
			case "mode":
				policy.Mode = "invalid"
			case "version":
				policy.Version = 0
			case "severity":
				policy.BlockSeverity = "invalid"
			}
			store.EXPECT().Policy(gomock.Any(), scope).Return(policy, nil)
			store.EXPECT().AppendAudit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, audit *security.Audit) error {
				require.False(t, audit.Decision.Allowed)
				require.Equal(t, "PolicyInvalid", audit.Decision.Code)
				return nil
			})
			svc := security.NewService(store, nil, nil, security.Settings{Enabled: true, Mode: "audit"}, func(context.Context, string, string) error { return nil }, nil)
			require.Equal(t, "PolicyInvalid", admissionCode(t, svc.DenyRawGit(t.Context(), scope)))
		})
	}
}

func TestRawGitUsesUpdatedPolicyOnNextRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mocks.NewMockStore(ctrl)
	policy := &security.Policy{Repo: scope, Mode: "audit", BlockSeverity: "high", Version: 4}
	store.EXPECT().Policy(gomock.Any(), scope).DoAndReturn(func(context.Context, string) (*security.Policy, error) { return policy, nil }).Times(2)
	var decisions []security.Decision
	store.EXPECT().AppendAudit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, audit *security.Audit) error {
		decisions = append(decisions, *audit.Decision)
		return nil
	}).Times(2)
	svc := security.NewService(store, nil, nil, security.Settings{Enabled: true, Mode: "audit"}, func(context.Context, string, string) error { return nil }, nil)
	require.NoError(t, svc.DenyRawGit(t.Context(), scope))
	policy = &security.Policy{Repo: scope, Mode: "enforce", BlockSeverity: "high", Version: 5}
	require.Equal(t, "RawGitDisabled", admissionCode(t, svc.DenyRawGit(t.Context(), scope)))
	require.True(t, decisions[0].Allowed)
	require.Equal(t, int64(4), decisions[0].PolicyVersion)
	require.False(t, decisions[1].Allowed)
	require.Equal(t, int64(5), decisions[1].PolicyVersion)
}
