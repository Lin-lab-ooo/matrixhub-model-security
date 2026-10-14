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

package cleanup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	datasetmocks "github.com/matrixhub-ai/matrixhub/internal/domain/dataset/mocks"
	"github.com/matrixhub-ai/matrixhub/internal/domain/git"
	gitmocks "github.com/matrixhub-ai/matrixhub/internal/domain/git/mocks"
	modelmocks "github.com/matrixhub-ai/matrixhub/internal/domain/model/mocks"
)

func TestCleanupServicePreviewUsesDomainPorts(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	modelRepo := modelmocks.NewMockIModelRepo(ctrl)
	datasetRepo := datasetmocks.NewMockIDatasetRepo(ctrl)
	gitRepo := gitmocks.NewMockIGitRepo(ctrl)

	modelPaths := []string{"project/model"}
	datasetPaths := []string{"project/dataset"}
	orphanedRepos := []*git.OrphanedRepo{{Path: "orphan/model.git", SizeBytes: 10}}
	orphanedLFS := []*git.OrphanedLFS{{OID: "12345678", SizeBytes: 20}}
	modelRepo.EXPECT().ListAllPaths(ctx).Return(modelPaths, nil)
	datasetRepo.EXPECT().ListAllPaths(ctx).Return(datasetPaths, nil)
	gitRepo.EXPECT().FindOrphanedRepos(ctx, modelPaths, datasetPaths).Return(orphanedRepos, nil)
	gitRepo.EXPECT().FindOrphanedLFS(ctx).Return(orphanedLFS, nil)

	service := NewCleanupService(modelRepo, datasetRepo, gitRepo)

	preview, err := service.PreviewCleanup(ctx, true, true)
	require.NoError(t, err)
	require.EqualValues(t, 30, preview.TotalReclaimable)
}

func TestCleanupServiceExecuteDelegatesDeletionToStoragePort(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	modelRepo := modelmocks.NewMockIModelRepo(ctrl)
	datasetRepo := datasetmocks.NewMockIDatasetRepo(ctrl)
	gitRepo := gitmocks.NewMockIGitRepo(ctrl)
	orphanedRepo := &git.OrphanedRepo{Path: "orphan/model.git", SizeBytes: 10}
	orphanedLFS := &git.OrphanedLFS{OID: "12345678", SizeBytes: 20}

	modelRepo.EXPECT().ListAllPaths(ctx).Return(nil, nil)
	datasetRepo.EXPECT().ListAllPaths(ctx).Return(nil, nil)
	gitRepo.EXPECT().FindOrphanedRepos(ctx, nil, nil).Return([]*git.OrphanedRepo{orphanedRepo}, nil)
	gitRepo.EXPECT().DeleteRepositoryAtRelPath(ctx, orphanedRepo.Path).Return(nil)
	gitRepo.EXPECT().FindOrphanedLFS(ctx).Return([]*git.OrphanedLFS{orphanedLFS}, nil)
	gitRepo.EXPECT().DeleteLFSObject(ctx, orphanedLFS).Return(nil)

	service := NewCleanupService(modelRepo, datasetRepo, gitRepo)

	result, err := service.ExecuteCleanup(ctx, true, true, false)
	require.NoError(t, err)
	require.Equal(t, 1, result.ReposDeleted)
	require.Equal(t, 1, result.LFSObjectsDeleted)
	require.EqualValues(t, 30, result.SpaceReclaimed)
}
