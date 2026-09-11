package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"platform.4so.io/factory/internal/redaction"
)

func canonicalAIRunOutput(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func AIRunOutputDigest(raw json.RawMessage) (string, error) {
	canonical, err := canonicalAIRunOutput(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func cloneAIRun(v AIRun) AIRun {
	v.Output = append(json.RawMessage(nil), v.Output...)
	return v
}

func ValidateAIRun(v *AIRun) error {
	v.ProjectID = strings.TrimSpace(v.ProjectID)
	v.Purpose = strings.TrimSpace(v.Purpose)
	v.Provider = strings.TrimSpace(v.Provider)
	v.Model = strings.TrimSpace(v.Model)
	v.PromptID = strings.TrimSpace(v.PromptID)
	v.PromptDigest = strings.TrimSpace(v.PromptDigest)
	v.ContextDigest = strings.TrimSpace(v.ContextDigest)
	v.OutputDigest = strings.TrimSpace(v.OutputDigest)
	v.LinkedResourceType = strings.TrimSpace(v.LinkedResourceType)
	v.LinkedResourceID = strings.TrimSpace(v.LinkedResourceID)
	v.IdempotencyKey = strings.TrimSpace(v.IdempotencyKey)
	v.RequestDigest = strings.TrimSpace(v.RequestDigest)
	if v.ProjectID == "" || v.Purpose == "" || v.Provider == "" || v.PromptID == "" || v.IdempotencyKey == "" {
		return fmt.Errorf("%w: projectId, purpose, provider, promptId and idempotencyKey are required", ErrValidation)
	}
	if len(v.IdempotencyKey) > 200 || len(v.Purpose) > 100 || len(v.Provider) > 100 || len(v.Model) > 200 || len(v.PromptID) > 200 {
		return fmt.Errorf("%w: AI run identifier fields exceed limits", ErrValidation)
	}
	for name, digest := range map[string]string{"promptDigest": v.PromptDigest, "contextDigest": v.ContextDigest, "outputDigest": v.OutputDigest, "requestDigest": v.RequestDigest} {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
			return fmt.Errorf("%w: %s must be a sha256 digest", ErrValidation, name)
		}
	}
	if v.RedactionCount < 0 || v.InputBytes < 0 || v.InputTokens < 0 || v.CachedTokens < 0 || v.OutputTokens < 0 {
		return fmt.Errorf("%w: AI run usage counters cannot be negative", ErrValidation)
	}
	if len(v.Output) == 0 || len(v.Output) > 64*1024 || !json.Valid(v.Output) {
		return fmt.Errorf("%w: AI run output must be one JSON value up to 64KiB", ErrValidation)
	}
	computedOutputDigest, err := AIRunOutputDigest(v.Output)
	if err != nil || v.OutputDigest != computedOutputDigest {
		return fmt.Errorf("%w: AI run outputDigest does not match canonical output", ErrValidation)
	}
	if findings := redaction.Detect(v.Output); len(findings) != 0 {
		return fmt.Errorf("%w: AI run output contains secret-like content", ErrValidation)
	}
	if v.LinkedResourceType == "" && v.LinkedResourceID != "" || v.LinkedResourceType != "" && v.LinkedResourceID == "" {
		return fmt.Errorf("%w: linked resource type and id must be supplied together", ErrValidation)
	}
	if v.LinkedResourceType != "" && v.LinkedResourceType != "operation" && v.LinkedResourceType != "managedCluster" {
		return fmt.Errorf("%w: unsupported AI linked resource type", ErrValidation)
	}
	return nil
}

func (s *MemoryStore) GetAIRun(_ context.Context, id string) (AIRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.aiRuns[id]
	if !ok {
		return AIRun{}, ErrNotFound
	}
	return cloneAIRun(v), nil
}

func (s *MemoryStore) GetAIRunByIdempotencyKey(_ context.Context, projectID, key string) (AIRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	projectID, key = strings.TrimSpace(projectID), strings.TrimSpace(key)
	for _, v := range s.aiRuns {
		if v.ProjectID == projectID && v.IdempotencyKey == key {
			return cloneAIRun(v), nil
		}
	}
	return AIRun{}, ErrNotFound
}

func (s *MemoryStore) ListAIRuns(_ context.Context, projectID string) ([]AIRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []AIRun{}
	for _, v := range s.aiRuns {
		if projectID == "" || v.ProjectID == projectID {
			out = append(out, cloneAIRun(v))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}
