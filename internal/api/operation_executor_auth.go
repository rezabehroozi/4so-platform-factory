package api

import (
	"errors"
	"net/http"
	"strings"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

var (
	errOperationExecutorRequired = errors.New("operation executor service-account permission is required")
	errWorkerIdentityMismatch    = errors.New("workerId must match the authenticated operation executor identity")
)

// operationExecutorIdentity is the execution-plane authorization boundary for
// generic durable Operation internals. Human OIDC principals deliberately
// cannot claim leases, advance raw state, write execution traces, or complete
// compensation steps. Production execution requires a service-account API
// token carrying operation.execute. Direct Handler tests and the explicit
// single-user local-development mode retain a narrow compatibility path.
func (s *Server) operationExecutorIdentity(r *http.Request, requestedWorker string) (string, error) {
	requestedWorker = strings.TrimSpace(requestedWorker)
	principal, authenticated := requestPrincipal(r)
	if !authenticated {
		if requestedWorker != "" {
			return requestedWorker, nil
		}
		return actorID(r)
	}
	if principal.Subject == "local-development" && principal.Authentication == "local" {
		if requestedWorker != "" {
			return requestedWorker, nil
		}
		return principal.Subject, nil
	}
	allowed := principal.Authentication == "api-token" && principalHasPermission(principal, controlplane.APITokenPermissionOperationExecute)
	decision, reason, status := "DENY", "OPERATION_EXECUTOR_PERMISSION_REQUIRED", http.StatusForbidden
	if allowed {
		decision, reason, status = "ALLOW", "OPERATION_EXECUTOR_AUTHORIZED", http.StatusOK
	}
	if _, err := s.store.AppendSecurityAudit(r.Context(), controlplane.SecurityAuditInput{
		Category: "OPERATION_EXECUTOR_AUTHORIZATION", Decision: decision, ActorID: principal.Subject,
		Authentication: principal.Authentication, Method: r.Method, Path: r.URL.Path, StatusCode: status,
		ReasonCode: reason, RequestID: r.Header.Get("X-Request-ID"), EffectiveRole: auth.CanonicalRole(principal.Roles),
		MappingDigest: principal.MappingDigest,
	}); err != nil {
		return "", err
	}
	if !allowed {
		return "", errOperationExecutorRequired
	}
	worker := strings.TrimSpace(principal.Subject)
	if worker == "" {
		return "", errOperationExecutorRequired
	}
	if requestedWorker != "" && requestedWorker != worker {
		return "", errWorkerIdentityMismatch
	}
	return worker, nil
}

func writeOperationExecutorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errOperationExecutorRequired):
		writeError(w, http.StatusForbidden, "OPERATION_EXECUTOR_REQUIRED", "operation execution requires an authenticated service-account token with operation.execute permission")
	case errors.Is(err, errWorkerIdentityMismatch):
		writeError(w, http.StatusForbidden, "WORKER_IDENTITY_MISMATCH", "workerId must match the authenticated operation executor identity")
	default:
		writeError(w, http.StatusServiceUnavailable, "SECURITY_AUDIT_UNAVAILABLE", "operation executor authorization could not be durably audited")
	}
}

func (s *Server) operationForExecution(w http.ResponseWriter, r *http.Request, requestedWorker string, requireRevision bool) (controlplane.Operation, string, int64, bool) {
	op, err := s.store.GetOperation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return controlplane.Operation{}, "", 0, false
	}
	if _, err = s.requireProjectAccess(r, op.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return controlplane.Operation{}, "", 0, false
	}
	worker, err := s.operationExecutorIdentity(r, requestedWorker)
	if err != nil {
		writeOperationExecutorError(w, err)
		return controlplane.Operation{}, "", 0, false
	}
	if !requireRevision {
		return op, worker, 0, true
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return controlplane.Operation{}, "", 0, false
	}
	return op, worker, rev, true
}
