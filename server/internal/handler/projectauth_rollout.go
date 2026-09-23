package handler

import (
	"net/http"
)

// requireProjectAuthorizationEnabled keeps mutation endpoints unavailable until
// the authorization system is active. Business permissions decide who may write.
// 2026-09-17 coder(lq): Stop treating rollout phases as user authorization.
func (h *Handler) requireProjectAuthorizationEnabled(w http.ResponseWriter) bool {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		h.Metrics.RecordProjectAuthorizationDecision("write", "disabled")
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return false
	}
	h.Metrics.RecordProjectAuthorizationDecision("write", "allow")
	return true
}
