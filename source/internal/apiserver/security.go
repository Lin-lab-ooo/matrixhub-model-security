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

package apiserver

import (
	"context"
	"errors"
	"strings"

	"github.com/matrixhub-ai/hfd/pkg/authenticate"

	"github.com/matrixhub-ai/matrixhub/internal/domain/auth"
	"github.com/matrixhub-ai/matrixhub/internal/domain/authz"
	"github.com/matrixhub-ai/matrixhub/internal/domain/role"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/matrixhub-ai/matrixhub/internal/infra/authcodec"
	"github.com/matrixhub-ai/matrixhub/internal/infra/log"
	"github.com/matrixhub-ai/matrixhub/internal/jobserver/processor"
	"github.com/matrixhub-ai/matrixhub/internal/repo"
)

// nativeCommitDiffPolicy permits commit metadata for an enforced repository
// while preventing raw history construction. Operational errors remain errors.
func nativeCommitDiffPolicy(gate security.Gate) func(context.Context, string) (bool, error) {
	return func(ctx context.Context, repository string) (bool, error) {
		if gate == nil || !gate.Enabled() {
			return false, nil
		}
		err := gate.DenyRawGit(security.WithEntry(ctx, "native-commit-diff"), repository)
		var admission *security.AdmissionError
		if errors.As(err, &admission) && admission.Code == "RawGitDisabled" {
			return true, nil
		}
		return false, err
	}
}

func securityIdentity(ctx context.Context) context.Context {
	if _, ok := auth.IdentityFromContext(ctx); ok {
		return ctx
	}
	if info, ok := authenticate.GetUserInfo(ctx); ok && info.User != authenticate.Anonymous {
		if identity, err := authcodec.Unmarshal(info.User); err == nil {
			return auth.WithIdentity(ctx, identity)
		}
	}
	return ctx
}
func securityAuthorizer(authzSvc authz.IAuthzService) security.Authorizer {
	return func(ctx context.Context, repository, operation string) error {
		ctx = securityIdentity(ctx)
		namespace, _, ok := strings.Cut(repository, "/")
		if !ok || namespace == "" {
			return &security.AdmissionError{Code: "PermissionDenied", Message: "Invalid repository scope", State: security.Fail}
		}
		perm := role.ModelPull
		switch operation {
		case "read":
		case "write":
			perm = role.ModelPush
		case "admin":
			perm = role.ModelSetting
		default:
			return &security.AdmissionError{Code: "PermissionDenied", Message: "Unknown security operation", State: security.Fail}
		}
		allowed, err := authzSvc.VerifyProjectPermissionByName(ctx, namespace, perm)
		if err != nil {
			return &security.AdmissionError{Code: "AuthorizationUnavailable", Message: "Project authorization could not be verified", State: security.Fail}
		}
		if !allowed {
			return &security.AdmissionError{Code: "PermissionDenied", Message: "Project permission is required", State: security.Fail}
		}
		return nil
	}
}
func (server *APIServer) initSecurityService(repos *repo.Repos, authzSvc authz.IAuthzService) *security.Service {
	c := server.config.Security
	if c == nil || !c.Enabled {
		return nil
	}
	if err := c.DefaultAndValidate(server.config.DataDir); err != nil {
		log.Fatalw("invalid security configuration", "error", err)
	}
	scanner, err := repo.NewSecurityScanner(c.SocketPath, c.Timeout)
	if err != nil {
		log.Fatalw("create isolated security scanner failed", "error", err)
	}
	artifacts, err := repo.NewSecurityArtifacts(server.gitStorage.storage, c.StagingRoot, c.MaxStagingBytes,
		repo.WithSecurityLFSStorage(server.gitStorage.lfsStorage), repo.WithSecurityMaxTaskBytes(c.MaxTaskBytes), repo.WithSecurityMaxFiles(c.MaxFiles), repo.WithSecurityPrefixProber(scanner))
	if err != nil {
		log.Fatalw("create security staging failed", "error", err)
	}
	server.securityArtifacts = artifacts
	settings := security.Settings{Enabled: true, Mode: c.Mode, BlockSeverity: c.BlockSeverity,
		MaxFileBytes: c.MaxFileBytes, MaxTaskBytes: c.MaxTaskBytes, MaxFiles: c.MaxFiles, Timeout: c.Timeout,
		BatchFiles: c.BatchFiles, BatchBytes: c.BatchBytes,
		Lease: c.Lease, PollInterval: c.PollInterval, Concurrency: c.Concurrency, MaxAttempts: c.MaxAttempts}
	store := repo.NewSecurityStore(repos.DB)
	svc := security.NewService(store, artifacts, scanner, settings, securityAuthorizer(authzSvc), func(ctx context.Context) string {
		if id, ok := auth.IdentityFromContext(securityIdentity(ctx)); ok {
			return id.TypeName() + ":" + id.GetName()
		}
		return "system"
	}, security.WithReviews(store, securityReviewActor))
	server.securityProcessor = processor.NewSecurityProcessor(svc)
	return svc
}

func securityReviewActor(ctx context.Context) (int64, string) {
	if id, ok := auth.IdentityFromContext(securityIdentity(ctx)); ok && id != nil && id.TypeName() == "user" {
		return int64(id.GetID()), id.TypeName() + ":" + id.GetName()
	}
	return 0, ""
}
