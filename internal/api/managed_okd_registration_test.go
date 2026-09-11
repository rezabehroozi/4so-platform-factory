package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/managedinstall"
)

type claimingRegistrationApplier struct {
	store controlplane.Store
	key   []byte
}

func (a claimingRegistrationApplier) ApplyRegistrationManifest(ctx context.Context, req managedinstall.Request, operationToken, manifest string) (map[string]any, error) {
	opID, _ := managedInstallOperationID(operationToken)
	digest, _ := managedinstall.DigestRequest(req)
	enrollment := managedOKDEnrollmentToken(a.key, opID, digest)
	imports, err := a.store.ListClusterImports(ctx, req.ProjectID)
	if err != nil {
		return nil, err
	}
	for _, imp := range imports {
		if imp.Name != req.ClusterName {
			continue
		}
		_, cluster, err := a.store.ClaimClusterImport(ctx, imp.ID, credentialDigest(enrollment), credentialDigest("agent-runtime-token"), "uid-managed-okd-1", "test-agent")
		if err != nil {
			return nil, err
		}
		return map[string]any{"applied": true, "clusterId": cluster.ID, "manifestHasSecret": strings.Contains(manifest, enrollment)}, nil
	}
	return nil, controlplane.ErrNotFound
}

func TestManagedOKDRegistrarConvergesNestedImportWithoutSecondHumanApproval(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "managed", DisplayName: "Managed"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "primary", DisplayName: "Primary"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	req := managedInstallTestRequest(org.ID, project.ID)
	raw, digest, err := managedinstall.MarshalCanonicalRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := store.CreateOperationAwaitingApprovalWithPayload(ctx, controlplane.OperationRequest{ProjectID: project.ID, Kind: managedOKDInstallOperationKind, TargetRef: "managed-okd-install/" + req.ClusterName, DesiredRevision: digest, Risk: "critical", Class: controlplane.OperationClassMutating}, "registration", "requester", "req", managedinstall.PayloadMediaType, raw)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.ApproveOperationAndQueue(ctx, op.ID, op.Revision, "independent-admin")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimOperation(ctx, op.ID, managedOKDInstallWorkerID, time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.GetOperation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	op, err = store.StartOperationAttempt(ctx, op.ID, op.Revision, managedOKDInstallWorkerID, claim.FenceToken, managedOKDInstallWorkerID)
	if err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, nil, store)
	server.ConfigureFleetImport("registry.example/fleet-agent@sha256:"+strings.Repeat("a", 64), "registry.example/runtime-probe@sha256:"+strings.Repeat("b", 64), "https://factory.example.test", "")
	key := []byte(strings.Repeat("r", 32))
	registrar, err := server.NewManagedOKDRegistrar(claimingRegistrationApplier{store: store, key: key}, key, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	registrar.Poll = time.Millisecond
	result, err := registrar.RegisterManagedCluster(ctx, req, managedInstallOperationToken(op))
	if err != nil {
		t.Fatal(err)
	}
	if result["connected"] != true || result["clusterId"] == "" {
		t.Fatalf("unexpected registration result %#v", result)
	}
	imports, err := store.ListClusterImports(ctx, project.ID)
	if err != nil || len(imports) != 1 || imports[0].State != controlplane.ClusterImportClaimed {
		t.Fatalf("imports=%#v err=%v", imports, err)
	}
	replay, err := registrar.RegisterManagedCluster(ctx, req, managedInstallOperationToken(op))
	if err != nil {
		t.Fatal(err)
	}
	if replay["idempotentReplay"] != true {
		t.Fatalf("registration retry was not idempotent: %#v", replay)
	}
	imports, _ = store.ListClusterImports(ctx, project.ID)
	if len(imports) != 1 {
		t.Fatalf("retry created duplicate import: %#v", imports)
	}
}

func TestManagedOKDRegistrarRejectsSameNameImportOwnedByDifferentOperation(t *testing.T) {
	ctx := context.Background()
	store := controlplane.NewMemoryStore()
	org, err := store.CreateOrganization(ctx, controlplane.Organization{Name: "managed-owner", DisplayName: "Managed Owner"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	project, err := store.CreateProject(ctx, controlplane.Project{OrganizationID: org.ID, Name: "primary-owner", DisplayName: "Primary Owner"}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	req := managedInstallTestRequest(org.ID, project.ID)
	enrollment := "deterministic-enrollment"
	_, err = store.CreateClusterImport(ctx, controlplane.ClusterImport{
		ProjectID:   project.ID,
		Name:        req.ClusterName,
		DisplayName: req.ClusterName,
		TokenDigest: credentialDigest(enrollment),
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}, "managed-okd-install/different-operation")
	if err != nil {
		t.Fatal(err)
	}
	server := New("test", nil, nil, store)
	registrar := &ManagedOKDRegistrar{server: server}
	_, err = registrar.findOrCreateImport(ctx, req, "expected-operation", enrollment)
	if err == nil || !strings.Contains(err.Error(), "different managed-install operation") {
		t.Fatalf("expected ownership conflict, got %v", err)
	}
}
