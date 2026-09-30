package daprruntime

import (
	"strings"
	"testing"

	"platform.4so.io/factory/internal/targetmodel"
)

func lifecycleTestDigest(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }

func TestLifecycleRequestCanonicalDigestIsStable(t *testing.T) {
	in := LifecycleRequest{
		ProjectID: " prj_1 ", ClusterID: " clu_1 ", Action: "install",
		RuntimeLockDigest: lifecycleTestDigest("a"),
		RuntimeVersion: "v1.18.4",
		UpstreamCommit: "6d1c53f430205c0c0f3bc3589ce5a3ec3f6f1647",
	}
	raw, digest, err := MarshalLifecycleRequest(in)
	if err != nil { t.Fatal(err) }
	got, err := ParseLifecycleRequest(raw, digest)
	if err != nil { t.Fatal(err) }
	if got.ProjectID != "prj_1" || got.ClusterID != "clu_1" || got.Action != ActionInstall {
		t.Fatalf("canonical Dapr lifecycle request drift: %#v", got)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("invalid lifecycle request digest: %s", digest)
	}
	if _, err := ParseLifecycleRequest(append(raw, []byte("{}")...), digest); err == nil {
		t.Fatal("Dapr lifecycle request trailing JSON accepted")
	}
}

func TestLifecycleTransitionRequiresObservedAuthority(t *testing.T) {
	target := lifecycleTestDigest("a")
	old := lifecycleTestDigest("b")
	if err := ValidateLifecycleTransition(ActionInstall, nil, target); err != nil {
		t.Fatalf("fresh install rejected: %v", err)
	}
	observed := &ObservedState{Installed: true, RuntimeLockDigest: old}
	if err := ValidateLifecycleTransition(ActionInstall, observed, target); err == nil || err.Error() != "DAPR_ALREADY_INSTALLED" {
		t.Fatalf("duplicate install accepted: %v", err)
	}
	if err := ValidateLifecycleTransition(ActionUpgrade, observed, target); err != nil {
		t.Fatalf("fenced upgrade rejected: %v", err)
	}
	observed.RuntimeLockDigest = target
	if err := ValidateLifecycleTransition(ActionUpgrade, observed, target); err == nil || err.Error() != "DAPR_UPGRADE_TARGET_EQUALS_OBSERVED" {
		t.Fatalf("same-lock upgrade accepted: %v", err)
	}
	if err := ValidateLifecycleTransition(ActionRemove, observed, target); err != nil {
		t.Fatalf("observed remove rejected: %v", err)
	}
	if err := ValidateLifecycleTransition(ActionRemove, nil, target); err == nil || err.Error() != "DAPR_REMOVE_REQUIRES_OBSERVED_INSTALL" {
		t.Fatalf("remove without observed install accepted: %v", err)
	}
}

func TestLifecycleDispatchFenceRejectsObservedDrift(t *testing.T) {
	target := lifecycleTestDigest("a")
	old := lifecycleTestDigest("b")
	observed := &ObservedState{Installed: true, RuntimeLockDigest: old}
	if err := ValidateLifecycleDispatchFence(ActionUpgrade, observed, target, old); err != nil {
		t.Fatalf("matching Dapr observed fence rejected: %v", err)
	}
	if err := ValidateLifecycleDispatchFence(ActionUpgrade, observed, target, lifecycleTestDigest("c")); err == nil || err.Error() != "DAPR_OBSERVED_FENCE_CHANGED" {
		t.Fatalf("Dapr observed fence drift accepted: %v", err)
	}
}


func daprLifecycleTestLock(t *testing.T) RuntimeLock {
	t.Helper()
	plan := targetmodel.DaprRuntimeSourcePlanModel()
	chars := []string{"a", "b", "c", "d"}
	images := make([]targetmodel.DaprRuntimeImageLock, 0, len(plan.RequiredImages))
	for i, image := range plan.RequiredImages {
		digest := lifecycleTestDigest(chars[i])
		images = append(images, targetmodel.DaprRuntimeImageLock{
			Role: image.Role, SourceRepository: image.Repository, SourceDigest: digest,
			MirrorReference: "zot.internal.example/dapr/" + image.Role + "@" + digest, MirrorDigest: digest,
		})
	}
	lock := RuntimeLock{
		Authority: targetmodel.DaprRuntimeSupplyChainAuthority, SourcePlanAuthority: plan.Authority,
		Version: plan.Version, UpstreamRepository: plan.UpstreamRepository, UpstreamRef: plan.UpstreamRef,
		UpstreamCommit: plan.UpstreamCommit, SourceArchiveDigest: lifecycleTestDigest("e"),
		HelmChartDigest: lifecycleTestDigest("f"), HelmPackageDigest: lifecycleTestDigest("0"),
		HelmRenderDigest: lifecycleTestDigest("1"),
		HelmMirrorReference: "zot.internal.example/dapr-charts/dapr@" + lifecycleTestDigest("4"),
		HelmMirrorManifestDigest: lifecycleTestDigest("4"),
		AcquisitionReceiptDigest: lifecycleTestDigest("2"), MirrorEvidenceDigest: lifecycleTestDigest("3"),
		ExecutorEvidenceDigest: lifecycleTestDigest("5"),
		ExecutorSourceReleaseDigest: lifecycleTestDigest("7"),
		ExecutorImageReference: "zot.internal.example/4so/dapr-runtime@" + lifecycleTestDigest("6"),
		ExecutorImageDigest: lifecycleTestDigest("6"),
		RegistryAuthority: "zot", RegistryScheme: "https", MirrorRegistry: "zot.internal.example",
		ImageLocks: images, ZotMirrorVerified: true, OfflineReplayReady: true, Admitted: true,
	}
	if err := ValidateRuntimeLock(lock); err != nil {
		t.Fatalf("fixture Dapr runtime lock invalid: %v", err)
	}
	return lock
}

func daprLifecycleMirrorEvidence(t *testing.T, lock RuntimeLock, clusterID, operationID string, fence int64) TargetMirrorPullEvidence {
	t.Helper()
	lockDigest, err := RuntimeLockDigest(lock)
	if err != nil { t.Fatal(err) }
	refs := map[string]string{}
	for _, image := range lock.ImageLocks {
		refs[image.Role] = image.MirrorReference
	}
	return TargetMirrorPullEvidence{
		Authority: TargetMirrorPullEvidenceAuthority,
		ClusterID: clusterID, OperationID: operationID, FenceToken: fence,
		RuntimeLockDigest: lockDigest, MirrorRegistry: lock.MirrorRegistry,
		RuntimeImages: []TargetMirrorPullObservation{
			{Role: "operator", WorkloadKind: "Deployment", Namespace: "dapr-system", WorkloadName: "dapr-operator", Container: "dapr-operator", ImageReference: refs["operator"], Ready: true},
			{Role: "injector", WorkloadKind: "Deployment", Namespace: "dapr-system", WorkloadName: "dapr-sidecar-injector", Container: "dapr-sidecar-injector", ImageReference: refs["injector"], Ready: true},
			{Role: "sentry", WorkloadKind: "Deployment", Namespace: "dapr-system", WorkloadName: "dapr-sentry", Container: "dapr-sentry", ImageReference: refs["sentry"], Ready: true},
		},
		SidecarImageReference: refs["sidecar"],
		SidecarPullInferred: false,
		WorkloadSidecarPullEvidenceRequired: true,
		ObservedAt: "2026-09-30T12:00:00Z",
	}
}

func TestTargetMirrorPullEvidenceBindsExactRuntimeWithoutInferringWorkloadSidecarPull(t *testing.T) {
	lock := daprLifecycleTestLock(t)
	lockDigest, err := RuntimeLockDigest(lock)
	if err != nil { t.Fatal(err) }
	evidence := daprLifecycleMirrorEvidence(t, lock, "clu_1", "op_1", 17)
	first, err := TargetMirrorPullEvidenceDigest(evidence, lock, "clu_1", "op_1", 17, lockDigest)
	if err != nil { t.Fatalf("exact target mirror-pull evidence rejected: %v", err) }
	evidence.RuntimeImages[0], evidence.RuntimeImages[2] = evidence.RuntimeImages[2], evidence.RuntimeImages[0]
	second, err := TargetMirrorPullEvidenceDigest(evidence, lock, "clu_1", "op_1", 17, lockDigest)
	if err != nil { t.Fatalf("reordered exact target mirror-pull evidence rejected: %v", err) }
	if first != second {
		t.Fatalf("canonical Dapr target mirror evidence digest depends on observation order: %s != %s", first, second)
	}
	if evidence.SidecarPullInferred || !evidence.WorkloadSidecarPullEvidenceRequired {
		t.Fatalf("runtime install proof inflated into workload sidecar pull proof: %#v", evidence)
	}
}

func TestTargetMirrorPullEvidenceRejectsSidecarInferenceAndRuntimeSubstitution(t *testing.T) {
	lock := daprLifecycleTestLock(t)
	lockDigest, err := RuntimeLockDigest(lock)
	if err != nil { t.Fatal(err) }
	evidence := daprLifecycleMirrorEvidence(t, lock, "clu_1", "op_1", 17)
	evidence.SidecarPullInferred = true
	if err := ValidateTargetMirrorPullEvidence(evidence, lock, "clu_1", "op_1", 17, lockDigest); err == nil {
		t.Fatal("workload sidecar pull was inferred from cluster runtime installation")
	}
	evidence = daprLifecycleMirrorEvidence(t, lock, "clu_1", "op_1", 17)
	evidence.RuntimeImages[0].ImageReference = "zot.internal.example/dapr/operator@" + lifecycleTestDigest("9")
	if err := ValidateTargetMirrorPullEvidence(evidence, lock, "clu_1", "op_1", 17, lockDigest); err == nil {
		t.Fatal("target runtime image substitution entered Dapr mirror-pull evidence")
	}
	if err := ValidateTargetMirrorPullEvidence(daprLifecycleMirrorEvidence(t, lock, "clu_1", "op_1", 17), lock, "clu_1", "op_1", 17, lifecycleTestDigest("9")); err == nil {
		t.Fatal("mirror-pull evidence was accepted against a foreign runtime-lock digest")
	}
}
