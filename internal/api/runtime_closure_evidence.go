package api

import (
	"io"
	"net/http"

	"platform.4so.io/factory/internal/evidence"
)

const maxRuntimeClosureReportBytes = 2 << 20

func (s *Server) verifyRuntimeClosureReport(w http.ResponseWriter, r *http.Request) {
	reader := http.MaxBytesReader(w, r.Body, maxRuntimeClosureReportBytes)
	raw, err := io.ReadAll(reader)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "RUNTIME_CLOSURE_REPORT_TOO_LARGE", "runtime closure report must be at most 2 MiB")
		return
	}
	result, err := evidence.VerifyRuntimeClosureReport(raw)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "RUNTIME_CLOSURE_REPORT_INVALID", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}
