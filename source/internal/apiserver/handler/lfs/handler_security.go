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

package lfs

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/matrixhub-ai/hfd/pkg/permission"
	"github.com/matrixhub-ai/hfd/pkg/repository"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func (h *Handler) securityEnabled() bool {
	return h.securityGate != nil && h.securityGate.Enabled()
}

func admissionDetails(err error) (*security.AdmissionError, int) {
	admission := &security.AdmissionError{Code: "security_unavailable", Message: "Artifact security verification is unavailable", State: security.Fail}
	statusCode := http.StatusServiceUnavailable
	if errors.As(err, &admission) {
		statusCode = http.StatusForbidden
	}
	return admission, statusCode
}

func respondAdmissionError(w http.ResponseWriter, err error) {
	admission, statusCode := admissionDetails(err)
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

func deniedObject(object *lfsRequestVars, err error) *lfsRepresentation {
	admission, statusCode := admissionDetails(err)
	return &lfsRepresentation{
		Oid: object.Oid, Size: object.Size,
		Error: &lfsObjectError{Code: statusCode, Message: admission.Error(), SecurityCode: admission.Code, State: admission.State},
	}
}

func (h *Handler) freezeBatchCommit(bv *lfsBatchVars) (string, error) {
	repoPath := h.storage.ResolvePath(bv.repoName())
	if repoPath == "" {
		return "", &security.AdmissionError{Code: "invalid_repository", Message: "Repository context is required for LFS downloads", State: security.Fail}
	}
	repo, err := repository.Open(repoPath)
	if err != nil {
		return "", err
	}
	rev := bv.Ref.Name
	if rev == "" {
		rev = repo.DefaultBranch()
	}
	return repo.ResolveRevision(rev)
}

// handleApprovedContent rechecks authorization, the current policy, generation
// and manifest before serving the immutable snapshot, including HEAD and Range.
func (h *Handler) handleApprovedContent(w http.ResponseWriter, r *http.Request) {
	if !h.securityEnabled() {
		responseJSON(w, "Protected LFS downloads are unavailable", http.StatusNotFound)
		return
	}
	vars := mux.Vars(r)
	repoName, commit, oid := vars["repo"], vars["commit"], vars["oid"]
	size, err := strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
	if err != nil || size < 0 {
		respondAdmissionError(w, &security.AdmissionError{Code: "invalid_lfs_size", Message: "The approved LFS size is required", State: security.Fail})
		return
	}
	if h.permissionHookFunc != nil {
		ok, err := h.permissionHookFunc(r.Context(), permission.OperationReadRepo, repoName, permission.Context{Ref: commit})
		if err != nil {
			respondAdmissionError(w, err)
			return
		}
		if !ok {
			respondAdmissionError(w, &security.AdmissionError{Code: "permission_denied", Message: "Permission denied", State: security.Block})
			return
		}
	}
	ctx := security.WithEntry(r.Context(), "lfs-content")
	decision, err := h.securityGate.CheckLFS(ctx, repoName, commit, oid, size)
	if err != nil {
		respondAdmissionError(w, err)
		return
	}
	if !decision.Allowed || decision.Repo != repoName || decision.Revision != commit || decision.Digest != oid || decision.Size != size || decision.Path == "" {
		respondAdmissionError(w, &security.AdmissionError{Code: "lfs_manifest_mismatch", Message: "LFS content does not match the approved repository manifest", State: security.Fail})
		return
	}
	approved, err := h.securityGate.OpenApproved(ctx, repoName, commit, decision.Path)
	if err != nil {
		respondAdmissionError(w, err)
		return
	}
	if approved == nil || approved.Reader == nil {
		respondAdmissionError(w, errors.New("security gate returned no verified content"))
		return
	}
	defer func() { _ = approved.Close() }()
	if !approved.Decision.Allowed || approved.Decision.Repo != repoName || approved.Decision.Revision != commit || approved.Decision.Path != decision.Path || approved.Decision.Digest != oid || approved.Decision.Size != size {
		respondAdmissionError(w, &security.AdmissionError{Code: "lfs_snapshot_mismatch", Message: "Verified LFS snapshot does not match the requested object", State: security.Fail})
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%s\"", oid))
	w.Header().Set("X-Repo-Commit", commit)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, oid, time.Time{}, approved.Reader)
}
