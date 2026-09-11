package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestVariableSchemaNormalizesAndResolvesTypedValues(t *testing.T) {
	min := int64(1)
	max := int64(9)
	schema, err := NormalizeVariableSchema(VariableSchema{
		ProjectID: "prj-1",
		Name:      " Production_Profile ",
		Version:   "1.2.0",
		Variables: []VariableDefinition{
			{Name: "replicas", Type: VariableTypeInteger, Required: true, Minimum: &min, Maximum: &max},
			{Name: "region", Type: VariableTypeString, Default: json.RawMessage(`"hel1"`), AllowedValues: []string{"hel2", "hel1"}},
			{Name: "features", Type: VariableTypeStringList, Default: json.RawMessage(`["audit","backup"]`)},
			{Name: "enabled", Type: VariableTypeBoolean, Default: json.RawMessage(`true`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if schema.Name != "production_profile" || !strings.HasPrefix(schema.Digest, "sha256:") || len(schema.Digest) != 71 {
		t.Fatalf("unexpected normalized schema: %#v", schema)
	}
	if got := schema.Variables[2].AllowedValues; len(got) != 2 || got[0] != "hel1" || got[1] != "hel2" {
		t.Fatalf("allowedValues not canonical: %#v", got)
	}
	values, err := ResolveVariableValues(schema, map[string]json.RawMessage{"replicas": json.RawMessage(`3`)})
	if err != nil {
		t.Fatal(err)
	}
	if string(values["replicas"]) != "3" || string(values["region"]) != `"hel1"` || string(values["enabled"]) != "true" {
		t.Fatalf("unexpected resolved values: %#v", values)
	}
}

func TestVariableSchemaFailsClosedForSecretsUnknownAndInvalidValues(t *testing.T) {
	_, err := NormalizeVariableSchema(VariableSchema{ProjectID: "prj", Name: "bad", Version: "1.0.0", Variables: []VariableDefinition{{Name: "password", Type: VariableTypeString, Sensitive: true, Default: json.RawMessage(`"secret"`)}}})
	if err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("sensitive default accepted: %v", err)
	}
	min := int64(2)
	schema, err := NormalizeVariableSchema(VariableSchema{ProjectID: "prj", Name: "safe", Version: "1.0.0", Variables: []VariableDefinition{{Name: "replicas", Type: VariableTypeInteger, Required: true, Minimum: &min}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveVariableValues(schema, map[string]json.RawMessage{"unknown": json.RawMessage(`true`)}); err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown variable accepted: %v", err)
	}
	if _, err := ResolveVariableValues(schema, map[string]json.RawMessage{"replicas": json.RawMessage(`1`)}); err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("minimum violation accepted: %v", err)
	}
	if _, err := ResolveVariableValues(schema, nil); err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("missing required variable accepted: %v", err)
	}
}

func TestVariableSchemaFileStoreIsImmutableAndSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, project := bootstrap(t, store)
	created, err := store.CreateVariableSchema(context.Background(), VariableSchema{
		ProjectID: project.ID,
		Name:      "production",
		Version:   "1.0.0",
		Variables: []VariableDefinition{{Name: "region", Type: VariableTypeString, Required: true}},
	}, "architect")
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.CreatedBy != "architect" || created.Digest == "" {
		t.Fatalf("unexpected created schema: %#v", created)
	}
	if _, err := store.CreateVariableSchema(context.Background(), VariableSchema{ProjectID: project.ID, Name: "production", Version: "1.0.0", Variables: []VariableDefinition{{Name: "other", Type: VariableTypeString}}}, "architect"); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate immutable identity err=%v", err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetVariableSchema(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != created.Digest || got.ProjectID != project.ID || len(got.Variables) != 1 {
		t.Fatalf("variable schema did not survive restart: before=%#v after=%#v", created, got)
	}
	snap, err := reopened.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.VariableSchemas) != 1 || snap.VariableSchemas[0].ID != created.ID {
		t.Fatalf("snapshot variableSchemas=%#v", snap.VariableSchemas)
	}
}
