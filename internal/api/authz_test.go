package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"platform.4so.io/factory/internal/auth"
)

func approvalRequest(subject string, roles []string) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/test/approve", nil)
	r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Subject: subject, Roles: roles}))
	return r
}

func TestApprovalPolicyRequiresAdminAndSeparationOfDuties(t *testing.T) {
	tests := []struct {
		name        string
		subject     string
		roles       []string
		requestedBy string
		wantActor   string
		wantErr     error
	}{
		{name: "different admin approves", subject: "admin-2", roles: []string{"platform-admin"}, requestedBy: "operator-1", wantActor: "admin-2"},
		{name: "operator cannot approve", subject: "operator-2", roles: []string{"platform-operator"}, requestedBy: "operator-1", wantErr: errPlatformAdminRequired},
		{name: "requester cannot self approve", subject: "admin-1", roles: []string{"platform-admin"}, requestedBy: "admin-1", wantErr: errSeparationOfDuties},
		{name: "local single user exception", subject: "local-development", roles: []string{"platform-admin"}, requestedBy: "local-development", wantActor: "local-development"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actor, err := approvalActor(approvalRequest(tt.subject, tt.roles), tt.requestedBy)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("actor=%q err=%v want=%v", actor, err, tt.wantErr)
				}
				return
			}
			if err != nil || actor != tt.wantActor {
				t.Fatalf("actor=%q err=%v", actor, err)
			}
		})
	}
}

func TestActorIDPrefersAuthenticatedPrincipalOverHeader(t *testing.T) {
	r := approvalRequest("trusted-admin", []string{"platform-admin"})
	r.Header.Set("X-Actor-ID", "spoofed-user")
	actor, err := actorID(r)
	if err != nil || actor != "trusted-admin" {
		t.Fatalf("actor=%q err=%v", actor, err)
	}
}

func TestNotificationProcessCredentialRequiresPlatformAdmin(t *testing.T) {
	input := notificationDestinationInput{AuthorizationEnv: "PLATFORM_FACTORY_NOTIFICATION_SECRET_SHARED"}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/notification-destinations", nil)
	r.Header.Set("X-Actor-Role", "organization-admin")
	w := httptest.NewRecorder()
	if requireNotificationCredentialAuthority(w, r, input) {
		t.Fatal("organization-admin unexpectedly received process credential authority")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("organization-admin status=%d body=%s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodPost, "/api/v1/notification-destinations", nil)
	r.Header.Set("X-Actor-Role", "platform-admin")
	w = httptest.NewRecorder()
	if !requireNotificationCredentialAuthority(w, r, input) {
		t.Fatalf("platform-admin credential authority rejected: status=%d body=%s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodPost, "/api/v1/notification-destinations", nil)
	r.Header.Set("X-Actor-Role", "organization-admin")
	w = httptest.NewRecorder()
	if !requireNotificationCredentialAuthority(w, r, notificationDestinationInput{}) {
		t.Fatalf("credentialless organization destination unexpectedly rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}
