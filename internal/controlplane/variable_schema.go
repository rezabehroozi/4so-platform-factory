package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

type VariableType string

const (
	VariableSchemaAuthority = "VARIABLE_SCHEMA_AUTHORITY_V1"

	VariableTypeString     VariableType = "STRING"
	VariableTypeInteger    VariableType = "INTEGER"
	VariableTypeBoolean    VariableType = "BOOLEAN"
	VariableTypeStringList VariableType = "STRING_LIST"
)

type VariableDefinition struct {
	Name          string          `json:"name"`
	DisplayName   string          `json:"displayName,omitempty"`
	Description   string          `json:"description,omitempty"`
	Type          VariableType    `json:"type"`
	Required      bool            `json:"required,omitempty"`
	Sensitive     bool            `json:"sensitive,omitempty"`
	Default       json.RawMessage `json:"default,omitempty"`
	AllowedValues []string        `json:"allowedValues,omitempty"`
	Pattern       string          `json:"pattern,omitempty"`
	Minimum       *int64          `json:"minimum,omitempty"`
	Maximum       *int64          `json:"maximum,omitempty"`
}

type VariableSchema struct {
	ResourceMeta
	ProjectID string               `json:"projectId"`
	Name      string               `json:"name"`
	Version   string               `json:"version"`
	Digest    string               `json:"digest"`
	Variables []VariableDefinition `json:"variables"`
	CreatedBy string               `json:"createdBy"`
}

var variableNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
var schemaVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

func cloneVariableSchema(in VariableSchema) VariableSchema {
	out := in
	out.Variables = make([]VariableDefinition, len(in.Variables))
	for i, v := range in.Variables {
		out.Variables[i] = v
		out.Variables[i].Default = append(json.RawMessage(nil), v.Default...)
		out.Variables[i].AllowedValues = append([]string(nil), v.AllowedValues...)
		if v.Minimum != nil {
			n := *v.Minimum
			out.Variables[i].Minimum = &n
		}
		if v.Maximum != nil {
			n := *v.Maximum
			out.Variables[i].Maximum = &n
		}
	}
	return out
}

func NormalizeVariableSchema(in VariableSchema) (VariableSchema, error) {
	out := cloneVariableSchema(in)
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.Version = strings.TrimSpace(out.Version)
	out.CreatedBy = strings.TrimSpace(out.CreatedBy)
	if out.ProjectID == "" || out.Name == "" || out.Version == "" {
		return VariableSchema{}, fmt.Errorf("%w: projectId, name and version are required", ErrValidation)
	}
	if !variableNamePattern.MatchString(out.Name) {
		return VariableSchema{}, fmt.Errorf("%w: schema name must be a canonical lower-case resource name", ErrValidation)
	}
	if !schemaVersionPattern.MatchString(out.Version) {
		return VariableSchema{}, fmt.Errorf("%w: schema version must be semver-like", ErrValidation)
	}
	if len(out.Variables) == 0 || len(out.Variables) > 128 {
		return VariableSchema{}, fmt.Errorf("%w: variable schema requires 1..128 variables", ErrValidation)
	}
	seen := map[string]bool{}
	for i := range out.Variables {
		v := &out.Variables[i]
		v.Name = strings.ToLower(strings.TrimSpace(v.Name))
		v.DisplayName = strings.TrimSpace(v.DisplayName)
		v.Description = strings.TrimSpace(v.Description)
		v.Pattern = strings.TrimSpace(v.Pattern)
		if !variableNamePattern.MatchString(v.Name) || len(v.Name) > 96 {
			return VariableSchema{}, fmt.Errorf("%w: invalid variable name %q", ErrValidation, v.Name)
		}
		if seen[v.Name] {
			return VariableSchema{}, fmt.Errorf("%w: duplicate variable %q", ErrValidation, v.Name)
		}
		seen[v.Name] = true
		switch v.Type {
		case VariableTypeString, VariableTypeInteger, VariableTypeBoolean, VariableTypeStringList:
		default:
			return VariableSchema{}, fmt.Errorf("%w: variable %q has unsupported type %q", ErrValidation, v.Name, v.Type)
		}
		if v.Sensitive && len(v.Default) > 0 {
			return VariableSchema{}, fmt.Errorf("%w: sensitive variable %q cannot define a default", ErrValidation, v.Name)
		}
		if v.Type != VariableTypeString && (v.Pattern != "" || len(v.AllowedValues) > 0) {
			return VariableSchema{}, fmt.Errorf("%w: pattern/allowedValues are valid only for STRING variable %q", ErrValidation, v.Name)
		}
		if v.Type != VariableTypeInteger && (v.Minimum != nil || v.Maximum != nil) {
			return VariableSchema{}, fmt.Errorf("%w: minimum/maximum are valid only for INTEGER variable %q", ErrValidation, v.Name)
		}
		if v.Minimum != nil && v.Maximum != nil && *v.Minimum > *v.Maximum {
			return VariableSchema{}, fmt.Errorf("%w: variable %q minimum exceeds maximum", ErrValidation, v.Name)
		}
		if v.Pattern != "" {
			if _, err := regexp.Compile(v.Pattern); err != nil {
				return VariableSchema{}, fmt.Errorf("%w: variable %q pattern is invalid", ErrValidation, v.Name)
			}
		}
		if len(v.AllowedValues) > 64 {
			return VariableSchema{}, fmt.Errorf("%w: variable %q has too many allowedValues", ErrValidation, v.Name)
		}
		normalizedAllowed := make([]string, 0, len(v.AllowedValues))
		allowedSeen := map[string]bool{}
		for _, value := range v.AllowedValues {
			value = strings.TrimSpace(value)
			if value == "" || allowedSeen[value] {
				return VariableSchema{}, fmt.Errorf("%w: variable %q allowedValues must be unique non-empty strings", ErrValidation, v.Name)
			}
			allowedSeen[value] = true
			normalizedAllowed = append(normalizedAllowed, value)
		}
		sort.Strings(normalizedAllowed)
		v.AllowedValues = normalizedAllowed
		if len(v.Default) > 0 {
			canonical, err := validateVariableValue(*v, v.Default)
			if err != nil {
				return VariableSchema{}, err
			}
			v.Default = canonical
		}
	}
	sort.Slice(out.Variables, func(i, j int) bool { return out.Variables[i].Name < out.Variables[j].Name })
	material := struct {
		Name      string               `json:"name"`
		Version   string               `json:"version"`
		Variables []VariableDefinition `json:"variables"`
	}{out.Name, out.Version, out.Variables}
	raw, _ := json.Marshal(material)
	sum := sha256.Sum256(raw)
	out.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return out, nil
}

func validateVariableValue(def VariableDefinition, raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("%w: variable %q value is invalid JSON", ErrValidation, def.Name)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: variable %q value has trailing JSON", ErrValidation, def.Name)
	}
	switch def.Type {
	case VariableTypeString:
		s, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: variable %q requires STRING", ErrValidation, def.Name)
		}
		if def.Pattern != "" && !regexp.MustCompile(def.Pattern).MatchString(s) {
			return nil, fmt.Errorf("%w: variable %q does not match pattern", ErrValidation, def.Name)
		}
		if len(def.AllowedValues) > 0 {
			found := false
			for _, allowed := range def.AllowedValues {
				if s == allowed {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("%w: variable %q is not an allowed value", ErrValidation, def.Name)
			}
		}
	case VariableTypeInteger:
		n, ok := value.(json.Number)
		if !ok {
			return nil, fmt.Errorf("%w: variable %q requires INTEGER", ErrValidation, def.Name)
		}
		integer, err := n.Int64()
		if err != nil {
			return nil, fmt.Errorf("%w: variable %q requires INTEGER", ErrValidation, def.Name)
		}
		if def.Minimum != nil && integer < *def.Minimum {
			return nil, fmt.Errorf("%w: variable %q is below minimum", ErrValidation, def.Name)
		}
		if def.Maximum != nil && integer > *def.Maximum {
			return nil, fmt.Errorf("%w: variable %q exceeds maximum", ErrValidation, def.Name)
		}
		value = integer
	case VariableTypeBoolean:
		if _, ok := value.(bool); !ok {
			return nil, fmt.Errorf("%w: variable %q requires BOOLEAN", ErrValidation, def.Name)
		}
	case VariableTypeStringList:
		list, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("%w: variable %q requires STRING_LIST", ErrValidation, def.Name)
		}
		for _, item := range list {
			if _, ok := item.(string); !ok {
				return nil, fmt.Errorf("%w: variable %q requires STRING_LIST", ErrValidation, def.Name)
			}
		}
	}
	canonical, _ := json.Marshal(value)
	return canonical, nil
}

// ResolveVariableValues applies defaults and validates an exact input map. Unknown
// variables fail closed, required values must be present, and sensitive defaults
// are impossible by schema construction. The result contains canonical JSON bytes.
func ResolveVariableValues(schema VariableSchema, supplied map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	normalized, err := NormalizeVariableSchema(schema)
	if err != nil {
		return nil, err
	}
	defs := map[string]VariableDefinition{}
	for _, def := range normalized.Variables {
		defs[def.Name] = def
	}
	for name := range supplied {
		if _, ok := defs[name]; !ok {
			return nil, fmt.Errorf("%w: unknown variable %q", ErrValidation, name)
		}
	}
	out := map[string]json.RawMessage{}
	for _, def := range normalized.Variables {
		raw, ok := supplied[def.Name]
		if !ok || len(raw) == 0 {
			if len(def.Default) > 0 {
				out[def.Name] = append(json.RawMessage(nil), def.Default...)
				continue
			}
			if def.Required {
				return nil, fmt.Errorf("%w: required variable %q is missing", ErrValidation, def.Name)
			}
			continue
		}
		canonical, err := validateVariableValue(def, raw)
		if err != nil {
			return nil, err
		}
		out[def.Name] = canonical
	}
	return out, nil
}
