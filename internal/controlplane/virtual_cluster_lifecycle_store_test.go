package controlplane

import (
	"testing"
	"time"

	"platform.4so.io/factory/internal/virtualcluster"
)

func TestVirtualClusterLifecycleExactReplayPrecedesRevisionGate(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	v := VirtualCluster{ResourceMeta: ResourceMeta{ID: "vcl-1", Revision: 7, UpdatedAt: now}, State: virtualcluster.StateActive}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	first, replay, err := PrepareVirtualClusterLifecycleRequest(v, 7, virtualcluster.ActionSuspend, "suspend-1", digest, now)
	if err != nil || replay || first.State != virtualcluster.StateSuspending || first.Revision != 8 {
		t.Fatalf("first lifecycle request=%#v replay=%v err=%v", first, replay, err)
	}
	second, replay, err := PrepareVirtualClusterLifecycleRequest(first, 7, virtualcluster.ActionSuspend, "suspend-1", digest, now.Add(time.Second))
	if err != nil || !replay || second.Revision != first.Revision {
		t.Fatalf("exact replay=%#v replay=%v err=%v", second, replay, err)
	}
	if _, _, err = PrepareVirtualClusterLifecycleRequest(first, 8, virtualcluster.ActionSuspend, "suspend-1", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now); err != ErrIdempotencyConflict {
		t.Fatalf("changed digest replay err=%v", err)
	}
}

func TestVirtualClusterDispatchAckIsDurableAndIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	lease := now.Add(time.Minute)
	v := VirtualCluster{ResourceMeta: ResourceMeta{ID: "vcl-1", Revision: 11, UpdatedAt: now}, TaskFenceToken: 4, TaskAction: "SUSPEND", TaskLeaseExpiresAt: &lease}
	acked, replay, err := ApplyVirtualClusterTaskDispatch(v, 11, 4, "SUSPEND", now)
	if err != nil || replay || acked.TaskDispatchedAt == nil || acked.Revision != 12 {
		t.Fatalf("dispatch=%#v replay=%v err=%v", acked, replay, err)
	}
	retry, replay, err := ApplyVirtualClusterTaskDispatch(acked, 11, 4, "SUSPEND", now.Add(time.Second))
	if err != nil || !replay || retry.Revision != acked.Revision {
		t.Fatalf("dispatch replay=%#v replay=%v err=%v", retry, replay, err)
	}
}
