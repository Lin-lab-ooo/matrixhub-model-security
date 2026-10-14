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

package authz_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/matrixhub-ai/matrixhub/internal/domain/authz"
	"github.com/matrixhub-ai/matrixhub/internal/domain/project"
	"github.com/matrixhub-ai/matrixhub/internal/domain/role"
)

type projectRepoStub struct {
	project.IProjectRepo
	getProjectByName func(context.Context, string) (*project.Project, error)
}

func (s *projectRepoStub) GetProjectByName(ctx context.Context, name string) (*project.Project, error) {
	return s.getProjectByName(ctx, name)
}

func TestAuthzService_VerifyProjectPermissionByNameReturnsFalseForMissingProject(t *testing.T) {
	service := authz.NewAuthzService(
		nil,
		&projectRepoStub{getProjectByName: func(context.Context, string) (*project.Project, error) {
			return nil, gorm.ErrRecordNotFound
		}},
		nil,
	)

	allowed, err := service.VerifyProjectPermissionByName(context.Background(), "missing", role.ModelPush)

	require.NoError(t, err)
	require.False(t, allowed)
}
