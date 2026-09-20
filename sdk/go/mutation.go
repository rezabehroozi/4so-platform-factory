package factorysdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// DeterministicMutationKey returns a stable client-side idempotency key for one
// explicitly fenced Product API mutation. It contains no retry policy and does
// not authorize a mutation; Product API RBAC, approval, revision checks and
// durable-operation semantics remain authoritative.
//
// namespace must identify the external automation surface (for example
// "terraform-saml" or "crossplane-saml") so independent clients cannot
// accidentally share replay identity.
func DeterministicMutationKey(namespace, action, id string, revision int64, desired any) (string, error) {
	namespace = strings.TrimSpace(namespace)
	action = strings.TrimSpace(action)
	id = strings.TrimSpace(id)
	if namespace == "" {
		return "", fmt.Errorf("mutation key namespace is required")
	}
	if action == "" {
		return "", fmt.Errorf("mutation key action is required")
	}
	if revision < 0 {
		return "", fmt.Errorf("mutation key revision cannot be negative")
	}

	raw, err := json.Marshal(struct {
		Namespace string `json:"namespace"`
		Action    string `json:"action"`
		ID        string `json:"id,omitempty"`
		Revision  int64  `json:"revision,omitempty"`
		Desired   any    `json:"desired,omitempty"`
	}{
		Namespace: namespace,
		Action:    action,
		ID:        id,
		Revision:  revision,
		Desired:   desired,
	})
	if err != nil {
		return "", fmt.Errorf("encode deterministic mutation identity: %w", err)
	}
	sum := sha256.Sum256(raw)
	return namespace + "-" + action + "-" + hex.EncodeToString(sum[:16]), nil
}
