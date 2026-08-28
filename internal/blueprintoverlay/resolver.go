package blueprintoverlay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/domain"
)

const (
	BlueprintOnly           = "BLUEPRINT_ONLY"
	ProviderOnly            = "PROVIDER_ONLY"
	EnvironmentOnly         = "ENVIRONMENT_ONLY"
	ProviderThenEnvironment = "PROVIDER_THEN_ENVIRONMENT"
)

var policies = map[string]bool{BlueprintOnly: true, ProviderOnly: true, EnvironmentOnly: true, ProviderThenEnvironment: true}

func sha(raw []byte) string    { s := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(s[:]) }
func valueDigest(v any) string { raw, _ := json.Marshal(v); return sha(raw) }

func Resolve(base domain.Blueprint, provider, environment *controlplane.BlueprintOverlay) (domain.Blueprint, controlplane.BlueprintResolution, error) {
	baseRaw, err := json.Marshal(base)
	if err != nil {
		return domain.Blueprint{}, controlplane.BlueprintResolution{}, err
	}
	var root any
	if err = json.Unmarshal(baseRaw, &root); err != nil {
		return domain.Blueprint{}, controlplane.BlueprintResolution{}, err
	}

	rules := map[string]string{}
	for _, rule := range base.Spec.FieldOwnership {
		path := strings.TrimSpace(rule.Path)
		policy := strings.TrimSpace(rule.Policy)
		if !strings.HasPrefix(path, "/spec/") || strings.HasPrefix(path, "/spec/fieldOwnership") || !policies[policy] {
			return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("FIELD_OWNERSHIP_RULE_INVALID: %s", path)
		}
		if _, ok := rules[path]; ok {
			return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("FIELD_OWNERSHIP_RULE_DUPLICATE: %s", path)
		}
		if _, ok := pointerGet(root, path); !ok {
			return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("FIELD_OWNERSHIP_PATH_NOT_FOUND: %s", path)
		}
		rules[path] = policy
	}

	providerChanges := map[string]controlplane.BlueprintOverlayChange{}
	environmentChanges := map[string]controlplane.BlueprintOverlayChange{}
	if provider != nil {
		if provider.Scope != controlplane.BlueprintOverlayProvider {
			return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("OVERLAY_SCOPE_MISMATCH: provider overlay must have PROVIDER scope")
		}
		for _, change := range provider.Changes {
			providerChanges[change.Path] = change
		}
	}
	if environment != nil {
		if environment.Scope != controlplane.BlueprintOverlayEnvironment {
			return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("OVERLAY_SCOPE_MISMATCH: environment overlay must have ENVIRONMENT scope")
		}
		for _, change := range environment.Changes {
			environmentChanges[change.Path] = change
		}
	}

	paths := map[string]bool{}
	for p := range rules {
		paths[p] = true
	}
	for p := range providerChanges {
		paths[p] = true
	}
	for p := range environmentChanges {
		paths[p] = true
	}
	ordered := make([]string, 0, len(paths))
	for p := range paths {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	fields := make([]controlplane.BlueprintFieldResolution, 0, len(ordered))
	for _, path := range ordered {
		policy := rules[path]
		if policy == "" {
			policy = BlueprintOnly
		}
		pchange, pok := providerChanges[path]
		echange, eok := environmentChanges[path]
		if pok && policy != ProviderOnly && policy != ProviderThenEnvironment {
			return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("FIELD_OWNERSHIP_CONFLICT: provider cannot modify %s under %s", path, policy)
		}
		if eok && policy != EnvironmentOnly && policy != ProviderThenEnvironment {
			return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("FIELD_OWNERSHIP_CONFLICT: environment cannot modify %s under %s", path, policy)
		}
		current, ok := pointerGet(root, path)
		if !ok {
			return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("OVERLAY_PATH_NOT_FOUND: %s", path)
		}
		record := controlplane.BlueprintFieldResolution{Path: path, Policy: policy, EffectiveOwner: "BLUEPRINT_BASE", ValueDigest: valueDigest(current)}
		if pok {
			var value any
			if err := json.Unmarshal(pchange.Value, &value); err != nil {
				return domain.Blueprint{}, controlplane.BlueprintResolution{}, err
			}
			if err := pointerSet(root, path, value); err != nil {
				return domain.Blueprint{}, controlplane.BlueprintResolution{}, err
			}
			record.EffectiveOwner = "PROVIDER:" + provider.ScopeKey
			record.ProviderOverlayID = provider.ID
			record.ValueDigest = valueDigest(value)
		}
		if eok {
			var value any
			if err := json.Unmarshal(echange.Value, &value); err != nil {
				return domain.Blueprint{}, controlplane.BlueprintResolution{}, err
			}
			if err := pointerSet(root, path, value); err != nil {
				return domain.Blueprint{}, controlplane.BlueprintResolution{}, err
			}
			record.EffectiveOwner = "ENVIRONMENT:" + environment.ScopeKey
			record.EnvironmentOverlayID = environment.ID
			record.ValueDigest = valueDigest(value)
			if pok {
				record.ProviderOverlayID = provider.ID
			}
		}
		fields = append(fields, record)
	}
	resolvedRaw, err := json.Marshal(root)
	if err != nil {
		return domain.Blueprint{}, controlplane.BlueprintResolution{}, err
	}
	var resolved domain.Blueprint
	if err = json.Unmarshal(resolvedRaw, &resolved); err != nil {
		return domain.Blueprint{}, controlplane.BlueprintResolution{}, fmt.Errorf("resolved blueprint decode: %w", err)
	}
	ruleRaw, _ := json.Marshal(base.Spec.FieldOwnership)
	overlayIdentity := []string{}
	resolution := controlplane.BlueprintResolution{BaseBlueprintDigest: sha(baseRaw), OwnershipDigest: sha(ruleRaw), Fields: fields}
	if provider != nil {
		resolution.ProviderOverlayID = provider.ID
		overlayIdentity = append(overlayIdentity, provider.Digest)
	}
	if environment != nil {
		resolution.EnvironmentOverlayID = environment.ID
		overlayIdentity = append(overlayIdentity, environment.Digest)
	}
	overlayRaw, _ := json.Marshal(overlayIdentity)
	resolution.OverlayDigest = sha(overlayRaw)
	return resolved, resolution, nil
}

func pointerGet(root any, path string) (any, bool) {
	parts, err := decodePointer(path)
	if err != nil {
		return nil, false
	}
	current := root
	for _, part := range parts {
		switch node := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = node[part]
			if !ok {
				return nil, false
			}
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			current = node[idx]
		default:
			return nil, false
		}
	}
	return current, true
}
func pointerSet(root any, path string, value any) error {
	parts, err := decodePointer(path)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return fmt.Errorf("root replacement forbidden")
	}
	current := root
	for i, part := range parts {
		last := i == len(parts)-1
		switch node := current.(type) {
		case map[string]any:
			if last {
				if _, ok := node[part]; !ok {
					return fmt.Errorf("OVERLAY_PATH_NOT_FOUND: %s", path)
				}
				node[part] = value
				return nil
			}
			next, ok := node[part]
			if !ok {
				return fmt.Errorf("OVERLAY_PATH_NOT_FOUND: %s", path)
			}
			current = next
		case []any:
			idx, e := strconv.Atoi(part)
			if e != nil || idx < 0 || idx >= len(node) {
				return fmt.Errorf("OVERLAY_PATH_NOT_FOUND: %s", path)
			}
			if last {
				node[idx] = value
				return nil
			}
			current = node[idx]
		default:
			return fmt.Errorf("OVERLAY_PATH_NOT_FOUND: %s", path)
		}
	}
	return nil
}
func decodePointer(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("invalid JSON pointer")
	}
	raw := strings.Split(path[1:], "/")
	out := make([]string, len(raw))
	for i, p := range raw {
		p = strings.ReplaceAll(p, "~1", "/")
		p = strings.ReplaceAll(p, "~0", "~")
		out[i] = p
	}
	return out, nil
}
