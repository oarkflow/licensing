package licensing

import "net/http"

func (s *Server) handleAppVaultBundleKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondClientError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}
	var req AppVaultKeyReleaseRequest
	if !s.decodeJSONBody(w, r, &req, maxActivationPayloadBytes) {
		return
	}
	resp, err := s.lm.ReleaseAppVaultBundleKey(r.Context(), req)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.respondJSON(w, http.StatusOK, resp)
}
