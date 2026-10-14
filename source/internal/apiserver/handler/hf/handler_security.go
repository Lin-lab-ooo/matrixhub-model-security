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

package hf

import (
	"errors"
	"net/http"
	"strings"

	"github.com/matrixhub-ai/hfd/pkg/repository"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func (h *Handler) securityEnabled() bool {
	return h.securityGate != nil && h.securityGate.Enabled()
}

func respondAdmissionError(w http.ResponseWriter, err error) {
	admission := &security.AdmissionError{Code: "security_unavailable", Message: "Artifact security verification is unavailable", State: security.Fail}
	statusCode := http.StatusServiceUnavailable
	if errors.As(err, &admission) {
		statusCode = http.StatusForbidden
	}
	w.Header().Set("X-Error-Code", admission.Code)
	w.Header().Set("X-Error-Message", strings.NewReplacer("\r", " ", "\n", " ").Replace(admission.Message))
	w.Header().Set("Cache-Control", "no-store")
	responseJSON(w, struct {
		Error   string         `json:"error"`
		Code    string         `json:"code"`
		Message string         `json:"message"`
		State   security.State `json:"state"`
	}{admission.Message, admission.Code, admission.Message, admission.State}, statusCode)
}

// pinRevision resolves a mutable branch or tag once. Every subsequent source
// read and security decision must use the returned immutable commit.
func pinRevision(repo *repository.Repository, rev string) (string, error) {
	if rev == "" {
		rev = repo.DefaultBranch()
	}
	return repo.ResolveRevision(rev)
}
