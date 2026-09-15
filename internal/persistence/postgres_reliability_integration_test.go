//go:build integration && cgo && linux

package persistence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/reliability"
)

func insertReliabilityIntegrationCluster(t *testing.T, db *sql.DB, projectID, suffix string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	importID := "imp_rel_" + suffix
	clusterID := "clu_rel_" + suffix
	token := "sha256:" + strings.Repeat(suffix, 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO cluster_imports(id,project_id,revision,name,display_name,state,token_digest,expires_at,requested_by,created_at,updated_at) VALUES($1,$2,1,$3,$3,'APPROVED',$4,$5,'integration-admin',$6,$6)`, importID, projectID, "reliability-"+suffix, token, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO managed_clusters(id,project_id,import_id,revision,name,display_name,external_uid,connection_state,created_at,updated_at) VALUES($1,$2,$3,1,$4,$4,$5,'CONNECTED',$6,$6)`, clusterID, projectID, importID, "reliability-"+suffix, "uid-rel-"+suffix, now); err != nil {
		t.Fatal(err)
	}
	return clusterID
}

func TestPostgresIntegrationReliabilityAuthority(t *testing.T) {
	store, db := openPostgresIntegrationStore(t)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "reliability-org", DisplayName: "Reliability Org"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "reliability-a", DisplayName: "Reliability A"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "reliability-b", DisplayName: "Reliability B"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	clusterA := insertReliabilityIntegrationCluster(t, db, projectA.ID, "a")
	clusterB := insertReliabilityIntegrationCluster(t, db, projectB.ID, "b")
	now := time.Now().UTC().Truncate(time.Second)
	obsA := reliability.HealthObservation{OrganizationID: org.ID, ProjectID: projectA.ID, ClusterID: clusterA, Health: "HEALTHY", ObservedAt: now, SourceDigest: "sha256:" + strings.Repeat("c", 64)}
	createdObs, created, err := store.CreateHealthObservation(ctx, obsA)
	if err != nil || !created {
		t.Fatalf("first observation created=%v err=%v", created, err)
	}
	replayedObs, created, err := store.CreateHealthObservation(ctx, obsA)
	if err != nil || created || replayedObs.ID != createdObs.ID {
		t.Fatalf("observation replay created=%v err=%v id=%q original=%q", created, err, replayedObs.ID, createdObs.ID)
	}
	_, _, err = store.CreateHealthObservation(ctx, reliability.HealthObservation{OrganizationID: org.ID, ProjectID: projectB.ID, ClusterID: clusterB, Health: "CRITICAL", ObservedAt: now, SourceDigest: "sha256:" + strings.Repeat("d", 64)})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListHealthObservations(ctx, projectA.ID, "", now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil || len(rows) != 1 || rows[0].ProjectID != projectA.ID {
		t.Fatalf("project-scoped observations leaked or lost rows=%#v err=%v", rows, err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE health_observations SET health='WARNING' WHERE id=$1`, createdObs.ID); err == nil {
		t.Fatal("database accepted mutation of immutable health observation")
	}
	incident, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: projectA.ID, ClusterID: clusterA, Service: "kubernetes-api", Severity: "CRITICAL"}, "integration-admin")
	if err != nil || incident.Revision != 1 || incident.State != reliability.IncidentOpen {
		t.Fatalf("incident create=%#v err=%v", incident, err)
	}
	ack, err := store.TransitionIncident(ctx, incident.ID, incident.Revision, reliability.IncidentActionAcknowledge, "integration-operator", "")
	if err != nil || ack.Revision != 2 || ack.State != reliability.IncidentAcknowledged {
		t.Fatalf("incident acknowledge=%#v err=%v", ack, err)
	}
	if _, err = store.TransitionIncident(ctx, incident.ID, 1, reliability.IncidentActionResolve, "integration-operator", "recovered"); !errors.Is(err, controlplane.ErrConflict) {
		t.Fatalf("stale incident revision must conflict, got %v", err)
	}
	resolved, err := store.TransitionIncident(ctx, incident.ID, ack.Revision, reliability.IncidentActionResolve, "integration-operator", "recovered")
	if err != nil || resolved.Revision != 3 || resolved.State != reliability.IncidentResolved {
		t.Fatalf("incident resolve=%#v err=%v", resolved, err)
	}

	policy, err := store.CreateSLOPolicy(ctx, reliability.SLOPolicy{OrganizationID: org.ID, ProjectID: projectA.ID, ClusterID: clusterA, Name: "api-availability", ObjectiveBasisPoints: 9990, WindowSeconds: 3600, ObservationIntervalSeconds: 60}, "integration-admin")
	if err != nil || policy.Revision != 1 || policy.ClusterID != clusterA {
		t.Fatalf("SLO create=%#v err=%v", policy, err)
	}
	revised, err := store.CreateSLOPolicyRevision(ctx, policy.ID, policy.Revision, reliability.SLOPolicy{ObjectiveBasisPoints: 9995, WindowSeconds: 7200, ObservationIntervalSeconds: 60}, "integration-admin")
	if err != nil || revised.Revision != 2 || revised.ID == policy.ID || revised.ClusterID != clusterA {
		t.Fatalf("SLO revision=%#v err=%v", revised, err)
	}
	if _, err = store.CreateSLOPolicyRevision(ctx, policy.ID, policy.Revision, reliability.SLOPolicy{ObjectiveBasisPoints: 9999, WindowSeconds: 7200, ObservationIntervalSeconds: 60}, "integration-admin"); !errors.Is(err, controlplane.ErrConflict) {
		t.Fatalf("stale SLO predecessor must conflict, got %v", err)
	}
	policies, err := store.ListSLOPolicies(ctx, projectA.ID, "api-availability", 10)
	if err != nil || len(policies) != 2 || policies[0].ProjectID != projectA.ID || policies[1].ProjectID != projectA.ID || policies[0].ClusterID != clusterA || policies[1].ClusterID != clusterA {
		t.Fatalf("project-scoped SLO revisions invalid rows=%#v err=%v", policies, err)
	}
	if _, err = db.ExecContext(ctx, `DELETE FROM slo_policies WHERE id=$1`, policy.ID); err == nil {
		t.Fatal("database accepted deletion of immutable SLO revision")
	}
}

func TestPostgresIntegrationIncidentOperationEvidenceBoundary(t *testing.T) {
	store, db := openPostgresIntegrationStore(t)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "incident-evidence-org", DisplayName: "Incident Evidence Org"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "incident-a", DisplayName: "Incident A"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "incident-b", DisplayName: "Incident B"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	opA, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: projectA.ID, Kind: "reliability.remediation", TargetRef: "project:" + projectA.ID, DesiredRevision: "sha256:" + strings.Repeat("a", 64), Risk: "medium", Class: controlplane.OperationClassMutating}, "pg-rel-op-a", "integration-admin", "pg-rel-req-a")
	if err != nil {
		t.Fatal(err)
	}
	opB, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: projectB.ID, Kind: "reliability.remediation", TargetRef: "project:" + projectB.ID, DesiredRevision: "sha256:" + strings.Repeat("b", 64), Risk: "medium", Class: controlplane.OperationClassMutating}, "pg-rel-op-b", "integration-admin", "pg-rel-req-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: projectA.ID, OperationID: opB.ID, Severity: "CRITICAL"}, "integration-admin"); !errors.Is(err, controlplane.ErrValidation) {
		t.Fatalf("foreign-project operation link must be rejected, got %v", err)
	}
	if _, err = store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: projectA.ID, OperationID: "op_missing", Severity: "WARNING"}, "integration-admin"); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("missing operation link must be rejected, got %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err = db.ExecContext(ctx, `INSERT INTO incidents(id,organization_id,project_id,operation_id,cluster_id,service,severity,state,revision,acknowledged_by,resolved_by,resolution_summary,created_at,updated_at) VALUES('inc_foreign_db',$1,$2,$3,'','','CRITICAL','OPEN',1,'','','',$4,$4)`, org.ID, projectA.ID, opB.ID, now); err == nil {
		t.Fatal("database accepted foreign-project incident operation link")
	}
	incident, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: projectA.ID, OperationID: opA.ID, Severity: "CRITICAL"}, "integration-admin")
	if err != nil || incident.OperationID != opA.ID {
		t.Fatalf("linked incident=%+v err=%v", incident, err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE incidents SET operation_id=$1 WHERE id=$2`, opB.ID, incident.ID); err == nil {
		t.Fatal("database accepted mutation of immutable incident operation_id")
	}
	ack, err := store.TransitionIncident(ctx, incident.ID, incident.Revision, reliability.IncidentActionAcknowledge, "integration-operator", "")
	if err != nil || ack.OperationID != opA.ID {
		t.Fatalf("ack operation link changed ack=%+v err=%v", ack, err)
	}
	resolved, err := store.TransitionIncident(ctx, ack.ID, ack.Revision, reliability.IncidentActionResolve, "integration-operator", "recovered")
	if err != nil || resolved.OperationID != opA.ID || resolved.State != reliability.IncidentResolved {
		t.Fatalf("resolve operation link changed resolved=%+v err=%v", resolved, err)
	}
	if _, err = store.TransitionIncident(ctx, resolved.ID, resolved.Revision, reliability.IncidentActionAcknowledge, "integration-operator", ""); err == nil {
		t.Fatal("resolved incident was not terminal")
	}
	for i := 0; i < 7; i++ {
		_, err = store.AppendEvidence(ctx, controlplane.EvidenceMetadata{OperationID: opA.ID, Phase: controlplane.OperationStepPhaseForward, StepKey: "incident-check", Attempt: i + 1, TraceID: "pg-secret-trace", Kind: "diagnostic", Digest: "sha256:" + fmt.Sprintf("%064x", i+101), MediaType: "application/json", Location: "file:///pg-secret/evidence", Size: int64(i + 1), HasPayload: true, Sealed: true}, "integration-operator")
		if err != nil {
			t.Fatalf("append evidence %d: %v", i, err)
		}
	}
	page, err := store.ListEvidencePageByOperation(ctx, opA.ID, 5)
	if err != nil || len(page) != 5 {
		t.Fatalf("bounded evidence page len=%d err=%v", len(page), err)
	}
	for _, evidence := range page {
		if evidence.OperationID != opA.ID {
			t.Fatalf("foreign evidence leaked into operation page: %+v", evidence)
		}
	}
}

func TestPostgresIntegrationIncidentOperationEvidenceLink(t *testing.T) {
	store, db := openPostgresIntegrationStore(t)
	ctx := context.Background()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "incident-evidence-org", DisplayName: "Incident Evidence Org"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "incident-evidence-a", DisplayName: "Incident Evidence A"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "incident-evidence-b", DisplayName: "Incident Evidence B"}, "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	opA, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: projectA.ID, Kind: "reliability.remediation", TargetRef: "cluster:a", DesiredRevision: "sha256:" + strings.Repeat("1", 64), Risk: "medium", Class: controlplane.OperationClassMutating}, "incident-evidence-a", "integration-admin", "sha256:"+strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	opB, _, err := store.CreateOperation(ctx, controlplane.OperationRequest{ProjectID: projectB.ID, Kind: "reliability.remediation", TargetRef: "cluster:b", DesiredRevision: "sha256:" + strings.Repeat("3", 64), Risk: "medium", Class: controlplane.OperationClassMutating}, "incident-evidence-b", "integration-admin", "sha256:"+strings.Repeat("4", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: projectA.ID, OperationID: opB.ID, Severity: "CRITICAL"}, "integration-admin"); !errors.Is(err, controlplane.ErrValidation) {
		t.Fatalf("cross-project operation link must fail validation, got %v", err)
	}
	incident, err := store.CreateIncident(ctx, reliability.Incident{OrganizationID: org.ID, ProjectID: projectA.ID, OperationID: opA.ID, Severity: "CRITICAL"}, "integration-admin")
	if err != nil || incident.OperationID != opA.ID {
		t.Fatalf("linked incident=%#v err=%v", incident, err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE incidents SET operation_id=$2,state='ACKNOWLEDGED',revision=revision+1,acknowledged_by='tamper',updated_at=now() WHERE id=$1`, incident.ID, opB.ID); err == nil {
		t.Fatal("database accepted mutation of immutable incident operation link")
	}
	opA, err = store.TransitionOperation(ctx, opA.ID, opA.Revision, controlplane.OperationPlanning, "", "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	opA, err = store.TransitionOperation(ctx, opA.ID, opA.Revision, controlplane.OperationQueued, "", "integration-admin")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, opA.ID, "integration-worker", time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := store.AppendOperationEvidencePayload(ctx, controlplane.EvidenceMetadata{OperationID: opA.ID, Kind: "diagnostic", MediaType: "application/json", Location: "authority://private/evidence"}, []byte(`{"status":"recovered"}`), "integration-worker", claim.FenceToken, "integration-worker")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListEvidencePageByOperation(ctx, opA.ID, 10)
	if err != nil || len(rows) != 1 || rows[0].ID != sealed.ID || rows[0].OperationID != opA.ID || !rows[0].Sealed {
		t.Fatalf("bounded operation evidence rows=%#v err=%v", rows, err)
	}
}
