// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/matrixhub-ai/matrixhub/internal/domain/git"
	gitmocks "github.com/matrixhub-ai/matrixhub/internal/domain/git/mocks"
	"github.com/matrixhub-ai/matrixhub/internal/domain/model"
	modelmocks "github.com/matrixhub-ai/matrixhub/internal/domain/model/mocks"
)

func TestSecurityNativeCommitDiffProtection(t *testing.T) {
	for _, mode := range []string{"existing-behavior", "audit", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			protected := mode == "enforce"
			ctrl := gomock.NewController(t)
			modelRepo := modelmocks.NewMockIModelRepo(ctrl)
			gitRepo := gitmocks.NewMockIGitRepo(ctrl)
			policyChecked := false
			modelRepo.EXPECT().GetByProjectAndName(gomock.Any(), "proj", "model").DoAndReturn(func(ctx context.Context, _, _ string) (*model.Model, error) {
				require.Equal(t, mode != "existing-behavior", policyChecked)
				require.Equal(t, !protected, git.CommitDiffRequested(ctx))
				return &model.Model{Name: "model"}, nil
			})
			original := &git.Commit{ID: "commit", Message: "description", Diff: "historical source bytes"}
			gitRepo.EXPECT().GetCommit(gomock.Any(), "models", "proj", "model", "commit").DoAndReturn(func(ctx context.Context, _, _, _, _ string) (*git.Commit, error) {
				require.Equal(t, !protected, git.CommitDiffRequested(ctx))
				return original, nil
			})
			svc := model.NewModelService(modelRepo, nil, gitRepo, nil, nil)
			if mode != "existing-behavior" {
				svc.(interface {
					SetHideCommitDiff(func(context.Context, string) (bool, error))
				}).SetHideCommitDiff(func(ctx context.Context, repository string) (bool, error) {
					require.Same(t, t.Context(), ctx)
					require.Equal(t, "proj/model", repository)
					policyChecked = true
					return protected, nil
				})
			}
			got, err := svc.GetModelCommit(t.Context(), "proj", "model", "commit")
			require.NoError(t, err)
			require.Equal(t, "description", got.Message)
			if protected {
				require.Empty(t, got.Diff)
			} else {
				require.Equal(t, original.Diff, got.Diff)
			}
			require.Equal(t, "historical source bytes", original.Diff)
		})
	}
}

func TestSecurityNativeCommitPolicyErrorsPrecedeRepositoryAccess(t *testing.T) {
	for _, failure := range []string{"authorization", "policy-read", "audit-write"} {
		t.Run(failure, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			modelRepo := modelmocks.NewMockIModelRepo(ctrl)
			gitRepo := gitmocks.NewMockIGitRepo(ctrl)
			want := errors.New(failure + " unavailable")
			svc := model.NewModelService(modelRepo, nil, gitRepo, nil, nil)
			svc.(interface {
				SetHideCommitDiff(func(context.Context, string) (bool, error))
			}).SetHideCommitDiff(func(ctx context.Context, repository string) (bool, error) {
				require.Same(t, t.Context(), ctx)
				require.Equal(t, "proj/model", repository)
				return false, want
			})
			got, err := svc.GetModelCommit(t.Context(), "proj", "model", "commit")
			require.ErrorIs(t, err, want)
			require.Nil(t, got)
		})
	}
}
