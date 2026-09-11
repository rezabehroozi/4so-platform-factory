package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

func TestExactCAPIMachineReplacePersistsRecoveryBeforeUIDPreconditionDelete(t *testing.T) {
	tokenFile := t.TempDir() + "/token"
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()

	const namespace = "4so-provider-system"
	const providerName = "pf-customer-123456"
	providerPath := "/apis/cluster.x-k8s.io/v1beta2/namespaces/" + namespace + "/clusters/" + providerName
	machinePath := "/apis/cluster.x-k8s.io/v1beta1/namespaces/" + namespace + "/machines/machine-old"
	machineCollection := "/apis/cluster.x-k8s.io/v1beta1/namespaces/" + namespace + "/machines"

	provider := map[string]any{"metadata": map[string]any{"name": providerName, "namespace": namespace, "uid": "provider-uid", "resourceVersion": "10", "annotations": map[string]any{}}}
	oldMachine := map[string]any{
		"metadata": map[string]any{"name": "machine-old", "namespace": namespace, "uid": "machine-uid-old", "resourceVersion": "44", "labels": map[string]any{"cluster.x-k8s.io/cluster-name": providerName, "cluster.x-k8s.io/set-name": "md-0-abc", "cluster.x-k8s.io/deployment-name": "md-0"}},
		"status":   map[string]any{"nodeRef": map[string]any{"name": "worker-1", "uid": "node-uid-1"}, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
	}
	replacement := map[string]any{
		"metadata": map[string]any{"name": "machine-new", "namespace": namespace, "uid": "machine-uid-new", "resourceVersion": "1", "labels": map[string]any{"cluster.x-k8s.io/cluster-name": providerName, "cluster.x-k8s.io/set-name": "md-0-def", "cluster.x-k8s.io/deployment-name": "md-0"}},
		"status":   map[string]any{"nodeRef": map[string]any{"name": "worker-9", "uid": "node-uid-9"}, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
	}
	recoveryPersisted := false
	deleted := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == providerPath:
			return jsonResponse(http.StatusOK, provider), nil
		case r.Method == http.MethodPatch && r.URL.Path == providerPath:
			var patch map[string]any
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Fatal(err)
			}
			meta, _ := patch["metadata"].(map[string]any)
			annotations, _ := meta["annotations"].(map[string]any)
			raw, _ := annotations[targetNodeMutationRecoveryAnnotation].(string)
			if !strings.Contains(raw, `"machineUid":"machine-uid-old"`) || !strings.Contains(raw, `"nodeUid":"node-uid-1"`) {
				t.Fatalf("recovery evidence did not pin machine/node identity: %s", raw)
			}
			providerMeta, _ := provider["metadata"].(map[string]any)
			providerAnnotations, _ := providerMeta["annotations"].(map[string]any)
			providerAnnotations[targetNodeMutationRecoveryAnnotation] = raw
			recoveryPersisted = true
			return jsonResponse(http.StatusOK, provider), nil
		case r.Method == http.MethodGet && r.URL.Path == machineCollection:
			if deleted {
				return jsonResponse(http.StatusOK, map[string]any{"items": []any{replacement}}), nil
			}
			return jsonResponse(http.StatusOK, map[string]any{"items": []any{oldMachine}}), nil
		case r.Method == http.MethodGet && r.URL.Path == machinePath:
			if deleted {
				return jsonResponse(http.StatusNotFound, map[string]any{}), nil
			}
			return jsonResponse(http.StatusOK, oldMachine), nil
		case r.Method == http.MethodDelete && r.URL.Path == machinePath:
			if !recoveryPersisted {
				t.Fatal("Machine deletion occurred before recovery evidence was persisted")
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			var options map[string]any
			if err = json.Unmarshal(body, &options); err != nil {
				t.Fatal(err)
			}
			pre, _ := options["preconditions"].(map[string]any)
			if pre["uid"] != "machine-uid-old" || pre["resourceVersion"] != "44" {
				t.Fatalf("delete preconditions=%#v", pre)
			}
			deleted = true
			return jsonResponse(http.StatusOK, map[string]any{}), nil
		default:
			t.Fatalf("unexpected kube request %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			return nil, nil
		}
	})}

	task := controlplane.ProviderClusterTask{
		ProviderClusterID: "pcl-1", ClusterRevision: 7, TaskFenceToken: 9, LeaseExpiresAt: time.Now().Add(time.Hour),
		Action: "APPLY", Namespace: namespace, ResourceName: providerName, DesiredDigest: "sha256:" + strings.Repeat("d", 64),
		TargetNodeMutation: controlplane.TargetNodeProviderMutation{Authority: controlplane.TargetNodeProviderMachineLifecycleAuthority, Action: controlplane.TargetNodeActionReplace, TargetClusterID: "clu-target", NodeName: "worker-1", NodeUID: "node-uid-1", InventoryDigest: "sha256:" + strings.Repeat("a", 64), WindowID: "cmw-1", WindowEndsAt: time.Now().Add(time.Hour)},
	}
	resolved, err := (&agent{kube: client}).applyTargetNodeProviderMutation(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted || resolved.MachineName != "machine-old" || resolved.MachineUID != "machine-uid-old" || resolved.MachineResourceVersion != "44" || resolved.MachineSetName != "md-0-abc" || resolved.MachineDeploymentName != "md-0" || !strings.HasPrefix(resolved.EvidenceDigest, "sha256:") {
		t.Fatalf("resolved mutation=%#v deleted=%v", resolved, deleted)
	}
	task.Action = "INSPECT"
	task.TargetNodeMutation = resolved
	ready, err := (&agent{kube: client}).inspectTargetNodeProviderMutation(context.Background(), task)
	if err != nil || !ready {
		t.Fatalf("replacement inspect ready=%v err=%v", ready, err)
	}
}

func TestValidateProviderClusterTaskAcceptsProviderReplacementActions(t *testing.T) {
	base := controlplane.ProviderClusterTask{
		ProviderClusterID: "pcl-1", ClusterRevision: 7, TaskFenceToken: 9, LeaseExpiresAt: time.Now().Add(time.Hour),
		Action: "APPLY", Namespace: "4so-provider-system", ResourceName: "pf-customer-123456", DesiredDigest: "sha256:" + strings.Repeat("d", 64),
		Resource: map[string]any{
			"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster",
			"metadata": map[string]any{
				"name": "pf-customer-123456", "namespace": "4so-provider-system",
				"labels":      map[string]any{"platform.4so.io/provider-cluster-id": "pcl-1", "platform.4so.io/managed": "true"},
				"annotations": map[string]any{"platform.4so.io/desired-digest": "sha256:" + strings.Repeat("d", 64)},
			},
		},
	}
	for _, action := range []controlplane.TargetNodeLifecycleAction{controlplane.TargetNodeActionReplace, controlplane.TargetNodeActionCertificateRenewal, controlplane.TargetNodeActionRemediate} {
		t.Run(string(action), func(t *testing.T) {
			task := base
			task.TargetNodeMutation = controlplane.TargetNodeProviderMutation{Authority: controlplane.TargetNodeProviderMachineLifecycleAuthority, Action: action, TargetClusterID: "clu-target", NodeName: "worker-1", NodeUID: "node-uid-1", InventoryDigest: "sha256:" + strings.Repeat("a", 64), WindowID: "cmw-1", WindowEndsAt: time.Now().Add(time.Hour)}
			if err := validateProviderClusterTask(task); err != nil {
				t.Fatalf("replacement-backed action %s rejected: %v", action, err)
			}
			if !controlplane.IsTargetNodeProviderReplacementAction(action) {
				t.Fatalf("action %s is not routed through exact replacement executor", action)
			}
		})
	}
}
