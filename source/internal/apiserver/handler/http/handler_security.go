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

package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func (h *Handler) rejectRawGit(w http.ResponseWriter, r *http.Request, repoName string) bool {
	if h.securityGate == nil || !h.securityGate.Enabled() {
		return false
	}
	err := h.securityGate.DenyRawGit(security.WithEntry(r.Context(), "git-http"), repoName)
	if err == nil {
		return false
	}
	admission := &security.AdmissionError{Code: "security_unavailable", Message: "Artifact security verification is unavailable", State: security.Fail}
	statusCode := http.StatusServiceUnavailable
	if errors.As(err, &admission) {
		statusCode = http.StatusForbidden
	}
	w.Header().Set("X-Error-Code", admission.Code)
	w.Header().Set("X-Error-Message", strings.NewReplacer("\r", " ", "\n", " ").Replace(admission.Message))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(admission)
	return true
}
