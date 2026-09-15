package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"platform.4so.io/factory/internal/reliability"
)

func TestIncidentOperationLinkRequiresSameProjectAndSurvivesTransitions(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, err := store.CreateOrganization(ctx, Organization{Name: "rel-ev", DisplayName: "Reliability Evidence"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "a", DisplayName: "A"}, "admin")
	projectB, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "b", DisplayName: "B"}, "admin")
	opA, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: projectA.ID, Kind: "TEST", TargetRef: "service/api", DesiredRevision: "rev-a", Risk: "medium"}, "op-a", "operator", "req-a")
	if err != nil {
		t.Fatal(err)
	}
	opB, _, err := store.CreateOperation(ctx, OperationRequest{ProjectID: projectB.ID, Kind: "TEST", TargetRef: "service/api", DesiredRevision: "rev-b", Risk: "medium"}, "op-b", "operator", "req-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: projectA.ID, OperationID: opB.ID, Severity: "CRITICAL"}, "operator"); !errors.Is(err, ErrValidation) {
		t.Fatalf("cross-project operation link err=%v", err)
	}
	incident, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: projectA.ID, OperationID: opA.ID, Severity: "CRITICAL"}, "operator")
	if err != nil || incident.OperationID != opA.ID {
		t.Fatalf("incident=%+v err=%v", incident, err)
	}
	ack, err := store.TransitionIncident(ctx, incident.ID, incident.Revision, reliability.IncidentActionAcknowledge, "operator", "")
	if err != nil || ack.OperationID != opA.ID {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	if _, err = store.AppendEvidence(ctx, EvidenceMetadata{OperationID: opA.ID, Kind: "diagnostic", Digest: "sha256:" + strings.Repeat("a", 64), MediaType: "text/plain", Location: "evidence://incident", Size: 12}, "operator"); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListEvidencePageByOperation(ctx, opA.ID, 10)
	if err != nil || len(page) != 1 || page[0].OperationID != opA.ID {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestIncidentOperationLinkRejectsMissingOperation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	org, _ := store.CreateOrganization(ctx, Organization{Name: "rel-missing", DisplayName: "Reliability Missing"}, "admin")
	project, _ := store.CreateProject(ctx, Project{OrganizationID: org.ID, Name: "p", DisplayName: "P"}, "admin")
	_, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: project.ID, OperationID: "op_missing", Severity: "WARNING"}, "operator")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing operation err=%v", err)
	}
}
