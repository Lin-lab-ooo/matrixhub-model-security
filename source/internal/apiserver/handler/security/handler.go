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

package security

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/matrixhub-ai/matrixhub/internal/domain/auth"
	domainsecurity "github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/matrixhub-ai/matrixhub/internal/infra/log"
)

const prefix = "/api/security/v1alpha1/models/{namespace}/{name}/"

var reportIDPattern = regexp.MustCompile(`^[1-9][0-9]*-[1-9][0-9]*$`)

// SecurityService is the transport's view of the domain service.
//
//go:generate go tool mockgen -source=handler.go -destination=mocks/service_mock.go -package=mocks
type SecurityService interface {
	Enabled() bool
	Resolve(context.Context, string, string) (string, error)
	Report(context.Context, string, string) (*domainsecurity.Report, error)
	History(context.Context, string, string) (*domainsecurity.Report, error)
	Enqueue(context.Context, string, string, string, bool) (*domainsecurity.Task, error)
	GetPolicy(context.Context, string) (*domainsecurity.Policy, error)
	UpdatePolicy(context.Context, string, domainsecurity.Policy) (*domainsecurity.Policy, error)
	Tasks(context.Context, string, int, int) ([]domainsecurity.Task, error)
	Audits(context.Context, string, int, int) ([]domainsecurity.Audit, error)
	Cancel(context.Context, string, int64) (bool, error)
	AddReview(context.Context, string, string, domainsecurity.ReviewInput) (*domainsecurity.Review, error)
	Reviews(context.Context, string, string, int, int) ([]domainsecurity.Review, error)
}

type handler struct {
	service SecurityService
	mux     *http.ServeMux
}

// NewSecurityHandler exposes the model security API. The composition root must
// wrap it with the existing HFAuthnMiddleware; the handler independently rejects
// missing identities, and all operations retain the service's project RBAC.
func NewSecurityHandler(svc *domainsecurity.Service) http.Handler {
	if svc == nil {
		return newHandler(nil)
	}
	return newHandler(svc)
}

func newHandler(svc SecurityService) *handler {
	h := &handler{service: svc, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET "+prefix+"report", h.report)
	h.mux.HandleFunc("GET "+prefix+"history/{reportId}", h.history)
	h.mux.HandleFunc("GET "+prefix+"history/{reportId}/reviews", h.reviews)
	h.mux.HandleFunc("POST "+prefix+"history/{reportId}/reviews", h.addReview)
	h.mux.HandleFunc("GET "+prefix+"tasks", h.tasks)
	h.mux.HandleFunc("GET "+prefix+"audits", h.audits)
	h.mux.HandleFunc("POST "+prefix+"rescan", h.rescan)
	h.mux.HandleFunc("POST "+prefix+"tasks/{id}/cancel", h.cancel)
	h.mux.HandleFunc("GET "+prefix+"policy", h.policy)
	h.mux.HandleFunc("PUT "+prefix+"policy", h.updatePolicy)
	h.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "RouteNotFound", "Security API route not found")
	})
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok || identity == nil || identity.GetID() <= 0 || identity.GetName() == "" {
		writeError(w, http.StatusUnauthorized, "Unauthenticated", "Authentication is required")
		return
	}
	if h.service == nil || !h.service.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "SecurityUnavailable", "Artifact security scanning is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(domainsecurity.WithEntry(r.Context(), "rest-security"), 30*time.Second)
	defer cancel()
	h.mux.ServeHTTP(w, r.WithContext(ctx))
}

func repository(r *http.Request) (string, bool) {
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	for _, part := range []string{namespace, name} {
		if part == "" || part == "." || part == ".." || len(part) > 255 || strings.ContainsAny(part, "/\\\x00\r\n") {
			return "", false
		}
	}
	return namespace + "/" + name, true
}

func (h *handler) scope(w http.ResponseWriter, r *http.Request) (string, bool) {
	repo, ok := repository(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidArgument", "A valid model namespace and name are required")
	}
	return repo, ok
}

func validRevision(ref string) bool {
	return ref != "" && len(ref) <= 1024 && !strings.ContainsAny(ref, "\x00\r\n")
}

func (h *handler) report(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.scope(w, r)
	if !ok {
		return
	}
	ref := r.URL.Query().Get("revision")
	if ref == "" {
		ref = "main"
	}
	if !validRevision(ref) {
		writeError(w, http.StatusBadRequest, "InvalidArgument", "A valid revision is required")
		return
	}
	commit, err := h.service.Resolve(r.Context(), repo, ref)
	if err != nil {
		respondError(w, err)
		return
	}
	report, err := h.service.Report(r.Context(), repo, commit)
	if err != nil {
		respondError(w, err)
		return
	}
	if report == nil {
		writeError(w, http.StatusNotFound, "ReportNotFound", "Security report not found")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *handler) history(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.scope(w, r)
	if !ok {
		return
	}
	id := r.PathValue("reportId")
	if len(id) > 64 || !reportIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "InvalidArgument", "An immutable task-attempt report ID is required")
		return
	}
	report, err := h.service.History(r.Context(), repo, id)
	if err != nil {
		respondError(w, err)
		return
	}
	if report == nil {
		writeError(w, http.StatusNotFound, "ReportNotFound", "Security report not found")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type revisionRequest struct {
	Revision string `json:"revision"`
}

func (h *handler) rescan(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.scope(w, r)
	if !ok {
		return
	}
	var input revisionRequest
	if !decodeBody(w, r, &input) {
		return
	}
	if !validRevision(input.Revision) {
		writeError(w, http.StatusBadRequest, "InvalidArgument", "A valid revision is required")
		return
	}
	commit, err := h.service.Resolve(r.Context(), repo, input.Revision)
	if err != nil {
		respondError(w, err)
		return
	}
	task, err := h.service.Enqueue(r.Context(), repo, commit, "manual", true)
	if err != nil {
		respondError(w, err)
		return
	}
	if task == nil {
		writeError(w, http.StatusServiceUnavailable, "SecurityUnavailable", "Artifact security scanning is unavailable")
		return
	}
	writeJSON(w, http.StatusAccepted, task)
}

func (h *handler) cancel(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "InvalidArgument", "A positive task ID is required")
		return
	}
	canceled, err := h.service.Cancel(r.Context(), repo, id)
	if err != nil {
		respondError(w, err)
		return
	}
	if !canceled {
		writeError(w, http.StatusNotFound, "TaskNotFound", "Active task not found in this model repository")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "canceled": true})
}

func pagination(w http.ResponseWriter, r *http.Request) (limit, offset int, ok bool) {
	limit = 50
	for key, target := range map[string]*int{"limit": &limit, "offset": &offset} {
		if value := r.URL.Query().Get(key); value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil || len(value) > 10 || parsed < 0 {
				writeError(w, http.StatusBadRequest, "InvalidArgument", "Pagination requires non-negative integer values")
				return 0, 0, false
			}
			*target = parsed
		}
	}
	if limit < 1 || limit > 200 || offset > 1000000 {
		writeError(w, http.StatusBadRequest, "InvalidArgument", "Limit must be 1-200 and offset must be at most 1000000")
		return 0, 0, false
	}
	return limit, offset, true
}

type listResponse[T any] struct {
	Items   []T  `json:"items"`
	Count   int  `json:"count"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"hasMore"`
}

func writeList[T any](w http.ResponseWriter, items []T, limit, offset int) {
	if items == nil {
		items = []T{}
	}
	writeJSON(w, http.StatusOK, listResponse[T]{Items: items, Count: len(items), Limit: limit, Offset: offset, HasMore: len(items) == limit})
}

func (h *handler) tasks(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.scope(w, r)
	if !ok {
		return
	}
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	items, err := h.service.Tasks(r.Context(), repo, limit, offset)
	if err != nil {
		respondError(w, err)
		return
	}
	writeList(w, items, limit, offset)
}

func (h *handler) audits(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.scope(w, r)
	if !ok {
		return
	}
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	items, err := h.service.Audits(r.Context(), repo, limit, offset)
	if err != nil {
		respondError(w, err)
		return
	}
	writeList(w, items, limit, offset)
}

func (h *handler) policy(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.scope(w, r)
	if !ok {
		return
	}
	policy, err := h.service.GetPolicy(r.Context(), repo)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

type policyRequest struct {
	Mode          string `json:"mode"`
	BlockSeverity string `json:"blockSeverity"`
}

func (h *handler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.scope(w, r)
	if !ok {
		return
	}
	var input policyRequest
	if !decodeBody(w, r, &input) {
		return
	}
	if (input.Mode != "enforce" && input.Mode != "audit") || (input.BlockSeverity != "low" && input.BlockSeverity != "medium" && input.BlockSeverity != "high" && input.BlockSeverity != "critical") {
		writeError(w, http.StatusBadRequest, "InvalidArgument", "A valid policy mode and block severity are required")
		return
	}
	policy, err := h.service.UpdatePolicy(r.Context(), repo, domainsecurity.Policy{Mode: input.Mode, BlockSeverity: input.BlockSeverity})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidJSON", "A bounded JSON object with supported fields is required")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "InvalidJSON", "Exactly one JSON object is required")
		return false
	}
	return true
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Errorf("encode security API response: %v", err)
	}
}

func writeError(w http.ResponseWriter, code int, machineCode, message string) {
	writeJSON(w, code, apiError{Code: machineCode, Message: message})
}

func respondError(w http.ResponseWriter, err error) {
	var admission *domainsecurity.AdmissionError
	if errors.As(err, &admission) {
		code := http.StatusConflict
		switch admission.Code {
		case "Unauthenticated", "Unauthorized":
			code = http.StatusUnauthorized
		case "PermissionDenied", "Forbidden", "AccessDenied", "RevisionBlocked", "RawGitDisabled":
			code = http.StatusForbidden
		case "AuthorizationUnavailable", "SecurityUnavailable", "RevisionFailed":
			code = http.StatusServiceUnavailable
		case "NotFound", "ReportNotFound":
			code = http.StatusNotFound
		case "InvalidArgument":
			code = http.StatusBadRequest
		}
		writeError(w, code, admission.Code, admission.Message)
		return
	}
	if errors.Is(err, fs.ErrNotExist) {
		writeError(w, http.StatusNotFound, "NotFound", "Model repository or revision not found")
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		writeError(w, http.StatusGatewayTimeout, "DeadlineExceeded", "Security request timed out")
		return
	}
	if grpcStatus, ok := status.FromError(err); ok {
		code := http.StatusInternalServerError
		switch grpcStatus.Code() {
		case codes.Unauthenticated:
			code = http.StatusUnauthorized
		case codes.PermissionDenied:
			code = http.StatusForbidden
		case codes.InvalidArgument:
			code = http.StatusBadRequest
		case codes.NotFound:
			code = http.StatusNotFound
		case codes.DeadlineExceeded:
			code = http.StatusGatewayTimeout
		case codes.Unavailable:
			code = http.StatusServiceUnavailable
		}
		if code != http.StatusInternalServerError {
			writeError(w, code, grpcStatus.Code().String(), grpcStatus.Message())
			return
		}
	}
	log.Errorf("security API operation failed: %v", err)
	writeError(w, http.StatusInternalServerError, "InternalError", "Security request failed")
}
