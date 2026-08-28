package controlplane

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func normalizeSecretRef(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("%w: secretRef is required", ErrValidation)
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "env" && u.Scheme != "file") {
		return "", fmt.Errorf("%w: secretRef must use env:// or file://", ErrValidation)
	}
	if u.Scheme == "env" && strings.Trim(strings.TrimPrefix(v, "env://"), "/") == "" {
		return "", fmt.Errorf("%w: env secretRef requires a variable name", ErrValidation)
	}
	if u.Scheme == "file" && !strings.HasPrefix(strings.TrimPrefix(v, "file://"), "/") {
		return "", fmt.Errorf("%w: file secretRef must be absolute", ErrValidation)
	}
	return v, nil
}

func normalizeGitProviderURL(v string) (string, error) {
	v = strings.TrimRight(strings.TrimSpace(v), "/")
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("%w: git provider baseUrl must be http(s)", ErrValidation)
	}
	return v, nil
}

func (s *MemoryStore) CreateGitCredential(_ context.Context, v GitCredential, actor string) (GitCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Name = normalizeName(v.Name)
	v.Username = strings.TrimSpace(v.Username)
	ref, err := normalizeSecretRef(v.SecretRef)
	if err != nil {
		return GitCredential{}, err
	}
	v.SecretRef = ref
	if v.Name == "" || v.Username == "" {
		return GitCredential{}, fmt.Errorf("%w: name and username are required", ErrValidation)
	}
	for _, x := range s.gitCredentials {
		if x.Name == v.Name && x.State == GitCredentialActive {
			return GitCredential{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("gitcred"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = GitCredentialActive
	v.CreatedBy = strings.TrimSpace(actor)
	s.gitCredentials[v.ID] = v
	s.appendAuditLocked(actor, "git_credential.created", "gitCredential", v.ID, v.Revision, map[string]any{"name": v.Name, "username": v.Username, "secretRef": v.SecretRef, "secretMaterialPersisted": false})
	s.appendOutboxLocked("gitCredential", v.ID, "git_credential.created", v)
	return v, nil
}
func (s *MemoryStore) GetGitCredential(_ context.Context, id string) (GitCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.gitCredentials[strings.TrimSpace(id)]
	if !ok {
		return GitCredential{}, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) ListGitCredentials(_ context.Context) ([]GitCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]GitCredential, 0, len(s.gitCredentials))
	for _, v := range s.gitCredentials {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *MemoryStore) RotateGitCredential(_ context.Context, id string, expected int64, repl GitCredential, actor string) (GitCredential, GitCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.gitCredentials[strings.TrimSpace(id)]
	if !ok {
		return GitCredential{}, GitCredential{}, ErrNotFound
	}
	if old.Revision != expected {
		return GitCredential{}, GitCredential{}, ErrConflict
	}
	if old.State != GitCredentialActive {
		return GitCredential{}, GitCredential{}, fmt.Errorf("%w: credential is not active", ErrValidation)
	}
	repl.Name = normalizeName(repl.Name)
	if repl.Name == "" {
		repl.Name = old.Name
	}
	repl.Username = strings.TrimSpace(repl.Username)
	if repl.Username == "" {
		repl.Username = old.Username
	}
	ref, err := normalizeSecretRef(repl.SecretRef)
	if err != nil {
		return GitCredential{}, GitCredential{}, err
	}
	repl.SecretRef = ref
	now := nowUTC(s.now)
	repl.ResourceMeta = ResourceMeta{ID: s.id("gitcred"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	repl.State = GitCredentialActive
	repl.CreatedBy = strings.TrimSpace(actor)
	repl.RotatedFromID = old.ID
	old.Revision++
	old.State = GitCredentialRevoked
	old.RevokedBy = strings.TrimSpace(actor)
	old.RevokedAt = &now
	old.UpdatedAt = now
	s.gitCredentials[old.ID] = old
	s.gitCredentials[repl.ID] = repl
	rebound := 0
	for k, p := range s.gitProviders {
		if p.CredentialID == old.ID {
			p.Revision++
			p.CredentialID = repl.ID
			p.UpdatedAt = now
			s.gitProviders[k] = p
			rebound++
		}
	}
	s.appendAuditLocked(actor, "git_credential.rotated", "gitCredential", repl.ID, repl.Revision, map[string]any{"rotatedFromId": old.ID, "providerBindingsRebound": rebound, "secretRef": repl.SecretRef, "secretMaterialPersisted": false})
	s.appendOutboxLocked("gitCredential", repl.ID, "git_credential.rotated", repl)
	return old, repl, nil
}
func (s *MemoryStore) RevokeGitCredential(_ context.Context, id string, expected int64, actor string) (GitCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.gitCredentials[strings.TrimSpace(id)]
	if !ok {
		return GitCredential{}, ErrNotFound
	}
	if v.Revision != expected {
		return GitCredential{}, ErrConflict
	}
	if v.State == GitCredentialRevoked {
		return v, nil
	}
	now := nowUTC(s.now)
	v.Revision++
	v.State = GitCredentialRevoked
	v.RevokedBy = strings.TrimSpace(actor)
	v.RevokedAt = &now
	v.UpdatedAt = now
	s.gitCredentials[v.ID] = v
	s.appendAuditLocked(actor, "git_credential.revoked", "gitCredential", v.ID, v.Revision, map[string]any{"secretRef": v.SecretRef})
	s.appendOutboxLocked("gitCredential", v.ID, "git_credential.revoked", v)
	return v, nil
}

func (s *MemoryStore) CreateGitProvider(_ context.Context, v GitProvider, actor string) (GitProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Name = normalizeName(v.Name)
	v.Kind = strings.ToUpper(strings.TrimSpace(v.Kind))
	if v.Kind == "" {
		v.Kind = "FORGEJO"
	}
	if v.Kind != "FORGEJO" {
		return GitProvider{}, fmt.Errorf("%w: only FORGEJO is supported", ErrValidation)
	}
	base, err := normalizeGitProviderURL(v.BaseURL)
	if err != nil {
		return GitProvider{}, err
	}
	v.BaseURL = base
	cred, ok := s.gitCredentials[strings.TrimSpace(v.CredentialID)]
	if !ok || cred.State != GitCredentialActive {
		return GitProvider{}, fmt.Errorf("%w: active git credential is required", ErrValidation)
	}
	for _, x := range s.gitProviders {
		if x.Name == v.Name {
			return GitProvider{}, ErrDuplicateName
		}
	}
	now := nowUTC(s.now)
	v.ResourceMeta = ResourceMeta{ID: s.id("gitp"), Revision: 1, CreatedAt: now, UpdatedAt: now}
	v.State = GitProviderActive
	v.CreatedBy = strings.TrimSpace(actor)
	if v.Default {
		for k, x := range s.gitProviders {
			if x.Default {
				x.Default = false
				x.Revision++
				x.UpdatedAt = now
				s.gitProviders[k] = x
			}
		}
	}
	s.gitProviders[v.ID] = v
	s.appendAuditLocked(actor, "git_provider.created", "gitProvider", v.ID, v.Revision, map[string]any{"name": v.Name, "kind": v.Kind, "baseUrl": v.BaseURL, "credentialId": v.CredentialID, "default": v.Default})
	s.appendOutboxLocked("gitProvider", v.ID, "git_provider.created", v)
	return v, nil
}
func (s *MemoryStore) GetGitProvider(_ context.Context, id string) (GitProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.gitProviders[strings.TrimSpace(id)]
	if !ok {
		return GitProvider{}, ErrNotFound
	}
	return v, nil
}
func (s *MemoryStore) ListGitProviders(_ context.Context) ([]GitProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]GitProvider, 0, len(s.gitProviders))
	for _, v := range s.gitProviders {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Default != out[j].Default {
			return out[i].Default
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}
func (s *MemoryStore) GetDefaultGitProvider(_ context.Context) (GitProvider, GitCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.gitProviders {
		if p.Default && p.State == GitProviderActive {
			c, ok := s.gitCredentials[p.CredentialID]
			if !ok {
				return GitProvider{}, GitCredential{}, ErrNotFound
			}
			if c.State != GitCredentialActive {
				return GitProvider{}, GitCredential{}, fmt.Errorf("%w: default git provider credential is revoked", ErrValidation)
			}
			return p, c, nil
		}
	}
	return GitProvider{}, GitCredential{}, ErrNotFound
}
func (s *MemoryStore) UpdateGitProviderCredential(_ context.Context, id string, expected int64, credentialID string, actor string) (GitProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.gitProviders[strings.TrimSpace(id)]
	if !ok {
		return GitProvider{}, ErrNotFound
	}
	if p.Revision != expected {
		return GitProvider{}, ErrConflict
	}
	c, ok := s.gitCredentials[strings.TrimSpace(credentialID)]
	if !ok || c.State != GitCredentialActive {
		return GitProvider{}, fmt.Errorf("%w: active git credential is required", ErrValidation)
	}
	p.Revision++
	p.CredentialID = c.ID
	p.UpdatedAt = nowUTC(s.now)
	s.gitProviders[p.ID] = p
	s.appendAuditLocked(actor, "git_provider.credential_rebound", "gitProvider", p.ID, p.Revision, map[string]any{"credentialId": c.ID})
	s.appendOutboxLocked("gitProvider", p.ID, "git_provider.credential_rebound", p)
	return p, nil
}
