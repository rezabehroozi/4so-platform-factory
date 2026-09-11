package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

func validServiceAccountRole(role string) bool {
	return role == "platform-viewer" || role == "platform-operator"
}

func normalizeTokenPermissions(role string, in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		permission := strings.ToLower(strings.TrimSpace(raw))
		if permission == "" || seen[permission] {
			continue
		}
		switch permission {
		case APITokenPermissionRead, APITokenPermissionMCPRead:
		case APITokenPermissionOperate, APITokenPermissionMCPOperate, APITokenPermissionAIDiagnose, APITokenPermissionOperationExecute:
			if role != "platform-operator" {
				return nil, fmt.Errorf("%w: %s permission requires platform-operator service account", ErrValidation, permission)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported API token permission %q", ErrValidation, permission)
		}
		seen[permission] = true
		out = append(out, permission)
	}
	if len(out) == 0 {
		out = append(out, APITokenPermissionRead)
	}
	if !seen[APITokenPermissionRead] {
		out = append(out, APITokenPermissionRead)
	}
	sort.Strings(out)
	return out, nil
}

func (s *MemoryStore) CreateServiceAccount(_ context.Context, account ServiceAccount, actor string) (ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account.OrganizationID = strings.TrimSpace(account.OrganizationID)
	account.ProjectID = strings.TrimSpace(account.ProjectID)
	account.Name = normalizeName(account.Name)
	account.DisplayName = strings.TrimSpace(account.DisplayName)
	account.ProductRole = strings.TrimSpace(account.ProductRole)
	if _, ok := s.organizations[account.OrganizationID]; !ok {
		return ServiceAccount{}, ErrNotFound
	}
	if account.ProjectID != "" {
		project, ok := s.projects[account.ProjectID]
		if !ok || project.OrganizationID != account.OrganizationID {
			return ServiceAccount{}, fmt.Errorf("%w: project is outside service account organization", ErrValidation)
		}
	}
	if account.Name == "" || account.DisplayName == "" || !validServiceAccountRole(account.ProductRole) {
		return ServiceAccount{}, fmt.Errorf("%w: organization, name, displayName and viewer/operator productRole are required", ErrValidation)
	}
	for _, existing := range s.serviceAccounts {
		if existing.OrganizationID == account.OrganizationID && existing.ProjectID == account.ProjectID && existing.Name == account.Name {
			return ServiceAccount{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	account.ResourceMeta = ResourceMeta{ID: s.id("svc"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	account.State = ServiceAccountActive
	account.CreatedBy = strings.TrimSpace(actor)
	account.RevokedBy, account.RevokedAt = "", nil
	s.serviceAccounts[account.ID] = account
	s.appendAuditLocked(actor, "service_account.created", "serviceAccount", account.ID, account.Revision, map[string]any{"organizationId": account.OrganizationID, "projectId": account.ProjectID, "productRole": account.ProductRole})
	s.appendOutboxLocked("serviceAccount", account.ID, "service_account.created", account)
	return account, nil
}

func (s *MemoryStore) GetServiceAccount(_ context.Context, id string) (ServiceAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.serviceAccounts[strings.TrimSpace(id)]
	if !ok {
		return ServiceAccount{}, ErrNotFound
	}
	return v, nil
}

func (s *MemoryStore) ListServiceAccounts(_ context.Context, organizationID string) ([]ServiceAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	organizationID = strings.TrimSpace(organizationID)
	out := []ServiceAccount{}
	for _, v := range s.serviceAccounts {
		if organizationID == "" || v.OrganizationID == organizationID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OrganizationID == out[j].OrganizationID {
			return out[i].Name < out[j].Name
		}
		return out[i].OrganizationID < out[j].OrganizationID
	})
	return out, nil
}

func (s *MemoryStore) RevokeServiceAccount(_ context.Context, id string, expected int64, actor string) (ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	current, ok := s.serviceAccounts[id]
	if !ok {
		return ServiceAccount{}, ErrNotFound
	}
	if current.Revision != expected {
		return ServiceAccount{}, ErrConflict
	}
	if current.State == ServiceAccountRevoked {
		return current, nil
	}
	now := nowUTC(s.now)
	current.State = ServiceAccountRevoked
	current.Revision++
	current.UpdatedAt = now
	current.RevokedBy = strings.TrimSpace(actor)
	current.RevokedAt = &now
	s.serviceAccounts[id] = current
	for tokenID, token := range s.apiTokens {
		if token.ServiceAccountID == id && token.State == APITokenActive {
			token.State = APITokenRevoked
			token.Revision++
			token.UpdatedAt = now
			token.RevokedBy = strings.TrimSpace(actor)
			token.RevokedAt = &now
			s.apiTokens[tokenID] = token
			s.appendAuditLocked(actor, "api_token.revoked", "apiToken", token.ID, token.Revision, map[string]any{"serviceAccountId": id, "reason": "service-account-revoked"})
		}
	}
	s.appendAuditLocked(actor, "service_account.revoked", "serviceAccount", id, current.Revision, map[string]any{"organizationId": current.OrganizationID, "projectId": current.ProjectID})
	s.appendOutboxLocked("serviceAccount", id, "service_account.revoked", current)
	return current, nil
}

func (s *MemoryStore) CreateAPIToken(_ context.Context, token APIToken, actor string) (APIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account, ok := s.serviceAccounts[strings.TrimSpace(token.ServiceAccountID)]
	if !ok {
		return APIToken{}, ErrNotFound
	}
	if account.State != ServiceAccountActive {
		return APIToken{}, fmt.Errorf("%w: service account is revoked", ErrValidation)
	}
	if token.ExpiresAt.IsZero() || !token.ExpiresAt.After(nowUTC(s.now)) || token.ExpiresAt.After(nowUTC(s.now).Add(366*24*time.Hour)) {
		return APIToken{}, fmt.Errorf("%w: token expiry must be in the future and within 366 days", ErrValidation)
	}
	permissions, err := normalizeTokenPermissions(account.ProductRole, token.Permissions)
	if err != nil {
		return APIToken{}, err
	}
	if strings.TrimSpace(token.TokenDigest) == "" || strings.TrimSpace(token.TokenPrefix) == "" {
		return APIToken{}, fmt.Errorf("%w: token digest and prefix are required", ErrValidation)
	}
	token.IdempotencyKey = strings.TrimSpace(token.IdempotencyKey)
	if token.IdempotencyKey == "" || len(token.IdempotencyKey) > 200 {
		return APIToken{}, fmt.Errorf("%w: idempotency key is required and must be at most 200 characters", ErrValidation)
	}
	for _, existing := range s.apiTokens {
		if existing.ServiceAccountID == account.ID && existing.IdempotencyKey == token.IdempotencyKey {
			return APIToken{}, ErrConflict
		}
	}
	now := nowUTC(s.now)
	token.ResourceMeta = ResourceMeta{ID: strings.TrimSpace(token.ID), Revision: 1, CreatedAt: now, UpdatedAt: now}
	if token.ID == "" {
		token.ID = s.id("tok")
	}
	token.ServiceAccountID = account.ID
	token.OrganizationID = account.OrganizationID
	token.ProjectID = account.ProjectID
	token.Permissions = permissions
	token.State = APITokenActive
	token.CreatedBy = strings.TrimSpace(actor)
	token.RevokedAt = nil
	token.RevokedBy = ""
	s.apiTokens[token.ID] = token
	s.appendAuditLocked(actor, "api_token.issued", "apiToken", token.ID, token.Revision, map[string]any{"serviceAccountId": account.ID, "organizationId": account.OrganizationID, "projectId": account.ProjectID, "expiresAt": token.ExpiresAt, "permissions": permissions})
	s.appendOutboxLocked("apiToken", token.ID, "api_token.issued", redactedAPIToken(token))
	return token, nil
}

func (s *MemoryStore) GetAPIToken(_ context.Context, id string) (APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.apiTokens[strings.TrimSpace(id)]
	if !ok {
		return APIToken{}, ErrNotFound
	}
	v.Permissions = append([]string(nil), v.Permissions...)
	return v, nil
}
func (s *MemoryStore) GetAPITokenByIdempotencyKey(_ context.Context, serviceAccountID, key string) (APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	serviceAccountID = strings.TrimSpace(serviceAccountID)
	key = strings.TrimSpace(key)
	for _, v := range s.apiTokens {
		if v.ServiceAccountID == serviceAccountID && v.IdempotencyKey == key {
			v.Permissions = append([]string(nil), v.Permissions...)
			return v, nil
		}
	}
	return APIToken{}, ErrNotFound
}

func (s *MemoryStore) ListAPITokens(_ context.Context, serviceAccountID string) ([]APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []APIToken{}
	for _, v := range s.apiTokens {
		if strings.TrimSpace(serviceAccountID) == "" || v.ServiceAccountID == strings.TrimSpace(serviceAccountID) {
			v.Permissions = append([]string(nil), v.Permissions...)
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) RevokeAPIToken(_ context.Context, id string, expected int64, actor string) (APIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.apiTokens[strings.TrimSpace(id)]
	if !ok {
		return APIToken{}, ErrNotFound
	}
	if current.Revision != expected {
		return APIToken{}, ErrConflict
	}
	if current.State == APITokenRevoked {
		return current, nil
	}
	now := nowUTC(s.now)
	current.State = APITokenRevoked
	current.Revision++
	current.UpdatedAt = now
	current.RevokedBy = strings.TrimSpace(actor)
	current.RevokedAt = &now
	s.apiTokens[current.ID] = current
	s.appendAuditLocked(actor, "api_token.revoked", "apiToken", current.ID, current.Revision, map[string]any{"serviceAccountId": current.ServiceAccountID})
	s.appendOutboxLocked("apiToken", current.ID, "api_token.revoked", redactedAPIToken(current))
	return current, nil
}

func (s *MemoryStore) RotateAPIToken(_ context.Context, oldID string, expected int64, replacement APIToken, actor string) (APIToken, APIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.apiTokens[strings.TrimSpace(oldID)]
	if !ok {
		return APIToken{}, APIToken{}, ErrNotFound
	}
	if old.Revision != expected {
		return APIToken{}, APIToken{}, ErrConflict
	}
	if old.State != APITokenActive {
		return APIToken{}, APIToken{}, fmt.Errorf("%w: only active token can be rotated", ErrValidation)
	}
	account, ok := s.serviceAccounts[old.ServiceAccountID]
	if !ok || account.State != ServiceAccountActive {
		return APIToken{}, APIToken{}, fmt.Errorf("%w: service account is not active", ErrValidation)
	}
	now := nowUTC(s.now)
	if replacement.ExpiresAt.IsZero() {
		replacement.ExpiresAt = old.ExpiresAt
	}
	if !replacement.ExpiresAt.After(now) || replacement.ExpiresAt.After(now.Add(366*24*time.Hour)) {
		return APIToken{}, APIToken{}, fmt.Errorf("%w: replacement token expiry must be in the future and within 366 days", ErrValidation)
	}
	permissions := replacement.Permissions
	if len(permissions) == 0 {
		permissions = old.Permissions
	}
	permissions, err := normalizeTokenPermissions(account.ProductRole, permissions)
	if err != nil {
		return APIToken{}, APIToken{}, err
	}
	if strings.TrimSpace(replacement.TokenDigest) == "" || strings.TrimSpace(replacement.TokenPrefix) == "" {
		return APIToken{}, APIToken{}, fmt.Errorf("%w: replacement token digest and prefix are required", ErrValidation)
	}
	replacement.IdempotencyKey = strings.TrimSpace(replacement.IdempotencyKey)
	if replacement.IdempotencyKey == "" || len(replacement.IdempotencyKey) > 200 {
		return APIToken{}, APIToken{}, fmt.Errorf("%w: idempotency key is required and must be at most 200 characters", ErrValidation)
	}
	for _, existing := range s.apiTokens {
		if existing.ServiceAccountID == account.ID && existing.IdempotencyKey == replacement.IdempotencyKey {
			return APIToken{}, APIToken{}, ErrConflict
		}
	}
	old.State = APITokenRevoked
	old.Revision++
	old.UpdatedAt = now
	old.RevokedBy = strings.TrimSpace(actor)
	old.RevokedAt = &now
	s.apiTokens[old.ID] = old
	replacement.ResourceMeta = ResourceMeta{ID: strings.TrimSpace(replacement.ID), Revision: 1, CreatedAt: now, UpdatedAt: now}
	if replacement.ID == "" {
		replacement.ID = s.id("tok")
	}
	replacement.ServiceAccountID = account.ID
	replacement.OrganizationID = account.OrganizationID
	replacement.ProjectID = account.ProjectID
	replacement.Permissions = permissions
	replacement.State = APITokenActive
	replacement.CreatedBy = strings.TrimSpace(actor)
	replacement.RotatedFromID = old.ID
	replacement.RevokedAt = nil
	replacement.RevokedBy = ""
	s.apiTokens[replacement.ID] = replacement
	s.appendAuditLocked(actor, "api_token.rotated", "apiToken", replacement.ID, replacement.Revision, map[string]any{"serviceAccountId": account.ID, "rotatedFromId": old.ID, "expiresAt": replacement.ExpiresAt})
	s.appendOutboxLocked("apiToken", replacement.ID, "api_token.rotated", redactedAPIToken(replacement))
	return old, replacement, nil
}

func redactedAPIToken(token APIToken) APIToken {
	token.TokenDigest = ""
	token.IdempotencyKey = ""
	token.Permissions = append([]string(nil), token.Permissions...)
	return token
}
