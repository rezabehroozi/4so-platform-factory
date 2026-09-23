package controlplane

import (
	"testing"
	"time"

	"platform.4so.io/factory/internal/virtualcluster"
)

func TestLifecycleUndispatchedLeaseCanReclaimButDispatchedLeaseCannot(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Second)
	v := VirtualCluster{ResourceMeta: ResourceMeta{ID: "vcl-1", Revision: 4}, State: virtualcluster.StateSuspending, PendingAction: virtualcluster.ActionSuspend, LifecycleAction: virtualcluster.ActionSuspend, TaskAction: "SUSPEND", TaskLeaseExpiresAt: &expired}
	if !VirtualClusterTaskClaimable(v, now) || VirtualClusterExpiredDispatchedMutation(v, now) {
		t.Fatalf("undispatched lifecycle task was not reclaimable: %#v", v)
	}
	stamp := now.Add(-time.Minute)
	v.TaskDispatchedAt = &stamp
	if !VirtualClusterExpiredDispatchedMutation(v, now) {
		t.Fatalf("dispatched expired lifecycle task did not fail closed: %#v", v)
	}
}

func TestLifecycleTaskResultMovesToInspectThenStable(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	lease := now.Add(time.Minute)
	dispatched := now.Add(-time.Second)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	v := VirtualCluster{ResourceMeta: ResourceMeta{ID: "vcl-1", Revision: 8}, State: virtualcluster.StateSuspending, PendingAction: virtualcluster.ActionSuspend, LifecycleAction: virtualcluster.ActionSuspend, DesiredDigest: digest, TaskAction: "SUSPEND", TaskFenceToken: 7, TaskLeaseExpiresAt: &lease, TaskDispatchedAt: &dispatched}
	next, err := ApplyVirtualClusterTaskResult(v, VirtualClusterTaskResult{TaskFenceToken: 7, Action: "SUSPEND", LifecycleAction: virtualcluster.ActionSuspend, Success: true, Ready: false, ObservedDigest: digest, Phase: "SuspendReconciling"}, now)
	if err != nil || next.TaskAction != "LIFECYCLE_INSPECT" || next.State != virtualcluster.StateSuspending || next.TaskDispatchedAt != nil {
		t.Fatalf("post-mutation inspect transition=%#v err=%v", next, err)
	}
	lease2 := now.Add(2*time.Minute)
	next.TaskLeaseExpiresAt = &lease2
	next.TaskAction = "LIFECYCLE_INSPECT"
	stable, err := ApplyVirtualClusterTaskResult(next, VirtualClusterTaskResult{TaskFenceToken: 7, Action: "LIFECYCLE_INSPECT", LifecycleAction: virtualcluster.ActionSuspend, Success: true, Ready: true, ObservedDigest: digest, Phase: "Suspended"}, now.Add(time.Second))
	if err != nil || stable.State != virtualcluster.StateSuspended || stable.PendingAction != "" {
		t.Fatalf("inspect convergence=%#v err=%v", stable, err)
	}
}
