// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security

import (
	"net/http"

	domainsecurity "github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func (h *handler) reviewScope(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	repo, ok := h.scope(w, r)
	if !ok {
		return "", "", false
	}
	id := r.PathValue("reportId")
	if len(id) > 64 || !reportIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "InvalidArgument", "An immutable task-attempt report ID is required")
		return "", "", false
	}
	return repo, id, true
}

func (h *handler) addReview(w http.ResponseWriter, r *http.Request) {
	repo, id, ok := h.reviewScope(w, r)
	if !ok {
		return
	}
	var input domainsecurity.ReviewInput
	if !decodeBody(w, r, &input) {
		return
	}
	if err := domainsecurity.ValidateReviewInput(input); err != nil {
		respondError(w, err)
		return
	}
	review, err := h.service.AddReview(r.Context(), repo, id, input)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, review)
}

func (h *handler) reviews(w http.ResponseWriter, r *http.Request) {
	repo, id, ok := h.reviewScope(w, r)
	if !ok {
		return
	}
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	items, err := h.service.Reviews(r.Context(), repo, id, limit, offset)
	if err != nil {
		respondError(w, err)
		return
	}
	writeList(w, items, limit, offset)
}
