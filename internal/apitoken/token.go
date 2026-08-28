package apitoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/auth"
	"platform.4so.io/factory/internal/controlplane"
)

const tokenMarker = "pft"

func Generate(tokenID string) (raw, prefix, digest string, err error) {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" || strings.Contains(tokenID, ".") {
		return "", "", "", errors.New("token ID is invalid")
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return "", "", "", err
	}
	prefix = tokenMarker + "." + tokenID
	raw = prefix + "." + base64.RawURLEncoding.EncodeToString(secret)
	digest = Digest(raw)
	return raw, prefix, digest, nil
}

func Digest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TokenID(raw string) (string, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 || parts[0] != tokenMarker || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return "", errors.New("API token is malformed")
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return "", errors.New("API token secret encoding is invalid")
	}
	return parts[1], nil
}

func IsToken(raw string) bool { return strings.HasPrefix(strings.TrimSpace(raw), tokenMarker+".") }

type Authenticator struct {
	Store controlplane.Store
	Now   func() time.Time
}

func (a Authenticator) Authenticate(ctx context.Context, raw string) (auth.Principal, error) {
	if a.Store == nil {
		return auth.Principal{}, errors.New("API token authority unavailable")
	}
	id, err := TokenID(raw)
	if err != nil {
		return auth.Principal{}, err
	}
	token, err := a.Store.GetAPIToken(ctx, id)
	if err != nil {
		return auth.Principal{}, errors.New("API token rejected")
	}
	expected := []byte(strings.TrimSpace(token.TokenDigest))
	actual := []byte(Digest(strings.TrimSpace(raw)))
	if len(expected) == 0 || len(expected) != len(actual) || subtle.ConstantTimeCompare(expected, actual) != 1 {
		return auth.Principal{}, errors.New("API token rejected")
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if token.State != controlplane.APITokenActive || !token.ExpiresAt.After(now().UTC()) {
		return auth.Principal{}, errors.New("API token is expired or revoked")
	}
	account, err := a.Store.GetServiceAccount(ctx, token.ServiceAccountID)
	if err != nil || account.State != controlplane.ServiceAccountActive {
		return auth.Principal{}, errors.New("service account is revoked")
	}
	if account.OrganizationID != token.OrganizationID || account.ProjectID != token.ProjectID {
		return auth.Principal{}, errors.New("API token scope mismatch")
	}
	if account.ProductRole != "platform-viewer" && account.ProductRole != "platform-operator" {
		return auth.Principal{}, fmt.Errorf("unsupported service-account product role %q", account.ProductRole)
	}
	return auth.Principal{
		Subject:          "service-account:" + account.ID,
		Name:             account.DisplayName,
		Roles:            []string{account.ProductRole},
		Expires:          token.ExpiresAt.Unix(),
		Authentication:   "api-token",
		ServiceAccountID: account.ID,
		CredentialID:     token.ID,
		OrganizationID:   account.OrganizationID,
		ProjectID:        account.ProjectID,
		Permissions:      append([]string(nil), token.Permissions...),
	}, nil
}
