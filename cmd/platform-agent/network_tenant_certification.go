package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
)

const networkCertificationPort = "18080"

func blockedNetworkChecks(detail string) []controlplane.RuntimeCheck {
	keys := []string{"network-namespaces", "network-default-deny", "network-dns-tenant-a", "network-dns-tenant-b", "network-intra-tenant-allow", "network-cross-tenant-deny", "network-cross-tenant-explicit-allow"}
	out := make([]controlplane.RuntimeCheck, 0, len(keys))
	for _, key := range keys {
		out = append(out, controlplane.RuntimeCheck{Key: "target-runtime/" + key, Status: "BLOCKED", Detail: detail})
	}
	return out
}

func stringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func networkPolicyAPIServed(resources []controlplane.ClusterAPIResourceObservation) bool {
	for _, item := range resources {
		if item.Group == "networking.k8s.io" && item.Version == "v1" && item.Kind == "NetworkPolicy" && item.Resource == "networkpolicies" {
			return stringSliceContains(item.Verbs, "get") && stringSliceContains(item.Verbs, "create") && stringSliceContains(item.Verbs, "delete")
		}
	}
	return false
}

func (a *agent) networkTenantIsolationCapabilities(resources []controlplane.ClusterAPIResourceObservation) ([]string, bool) {
	if !strings.Contains(a.cfg.RuntimeProbeImage, "@sha256:") || !networkPolicyAPIServed(resources) {
		return nil, false
	}
	return []string{"cert.network", "cert.tenant-isolation"}, true
}

func certificationNamespace(prefix, runID string) string {
	return certName(prefix, runID)
}

func runtimeCertLabels(runID, tenant string) map[string]any {
	return map[string]any{
		"platform.4so.io/runtime-certification": runID,
		"platform.4so.io/cert-tenant":           tenant,
	}
}

func (a *agent) applyCertificationNamespace(ctx context.Context, name, runID, tenant, cleanupToken string) error {
	path := "/api/v1/namespaces/" + name
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   name,
			"labels": runtimeCertLabels(runID, tenant),
		},
	}
	_, err := a.ensureRuntimeCertificationEphemeralObject(ctx, path, obj, runID, cleanupToken)
	return err
}

func podIsReady(obj map[string]any) bool {
	status, _ := obj["status"].(map[string]any)
	if objectString(obj, "status", "phase") != "Running" {
		return false
	}
	items, _ := status["containerStatuses"].([]any)
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if ready, _ := item["ready"].(bool); ready {
			return true
		}
	}
	return false
}

func (a *agent) runNetworkServerPod(ctx context.Context, namespace, runID, cleanupToken string) (string, string, error) {
	if !strings.Contains(a.cfg.RuntimeProbeImage, "@sha256:") {
		return "", "", fmt.Errorf("digest-pinned runtime probe image is required for network certification")
	}
	name := certName("4so-cert-net-server", runID)
	path := "/api/v1/namespaces/" + namespace + "/pods/" + name
	pod := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": name, "namespace": namespace,
			"labels": map[string]any{
				"platform.4so.io/runtime-certification": runID,
				"platform.4so.io/network-role":          "server",
			},
		},
		"spec": map[string]any{
			"restartPolicy": "Never", "automountServiceAccountToken": false,
			"containers": []any{map[string]any{
				"name": "probe", "image": a.cfg.RuntimeProbeImage, "imagePullPolicy": "IfNotPresent",
				"env":   []any{map[string]any{"name": "PLATFORM_PROBE_LISTEN_PORT", "value": networkCertificationPort}},
				"ports": []any{map[string]any{"containerPort": 18080, "protocol": "TCP"}},
			}},
		},
	}
	if _, err := a.ensureRuntimeCertificationEphemeralObject(ctx, path, pod, runID, cleanupToken); err != nil {
		return path, "", err
	}
	obj, err := a.waitKubeObject(ctx, path, 90*time.Second, podIsReady)
	if err != nil {
		return path, "", err
	}
	ip := strings.TrimSpace(objectString(obj, "status", "podIP"))
	if ip == "" {
		return path, "", fmt.Errorf("network certification server pod has no podIP")
	}
	return path, ip, nil
}

func (a *agent) runNetworkClientPod(ctx context.Context, namespace, runID, suffix, host, port string, expectSuccess bool, cleanupToken string) (string, error) {
	if !strings.Contains(a.cfg.RuntimeProbeImage, "@sha256:") {
		return "", fmt.Errorf("digest-pinned runtime probe image is required for network certification")
	}
	name := certName("4so-cert-net-client", runID+"-"+suffix)
	path := "/api/v1/namespaces/" + namespace + "/pods/" + name
	pod := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": name, "namespace": namespace,
			"labels": map[string]any{
				"platform.4so.io/runtime-certification": runID,
				"platform.4so.io/network-role":          "client",
			},
		},
		"spec": map[string]any{
			"restartPolicy": "Never", "automountServiceAccountToken": false,
			"containers": []any{map[string]any{
				"name": "probe", "image": a.cfg.RuntimeProbeImage, "imagePullPolicy": "IfNotPresent",
				"env": []any{
					map[string]any{"name": "PLATFORM_PROBE_HOST", "value": host},
					map[string]any{"name": "PLATFORM_PROBE_PORT", "value": port},
				},
			}},
		},
	}
	if _, err := a.ensureRuntimeCertificationEphemeralObject(ctx, path, pod, runID, cleanupToken); err != nil {
		return path, err
	}
	deadline := time.Now().Add(45 * time.Second)
	for {
		obj, found, err := a.getKubeObject(ctx, path)
		if err != nil {
			return path, err
		}
		if found {
			phase := objectString(obj, "status", "phase")
			if phase == "Succeeded" {
				if expectSuccess {
					return path, nil
				}
				return path, fmt.Errorf("network probe unexpectedly succeeded")
			}
			if phase == "Failed" {
				if expectSuccess {
					return path, fmt.Errorf("network probe failed")
				}
				output, readErr := probeOutputFromPodTermination(obj)
				if readErr != nil {
					return path, fmt.Errorf("network deny proof is not authoritative: %w", readErr)
				}
				if !output.DNSResolved || output.TCPConnected || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(output.Error)), "tcp connection failed:") {
					return path, fmt.Errorf("network deny proof is not authoritative: dnsResolved=%v tcpConnected=%v error=%q", output.DNSResolved, output.TCPConnected, output.Error)
				}
				return path, nil
			}
		}
		if time.Now().After(deadline) {
			return path, fmt.Errorf("timed out waiting for network probe pod %s", name)
		}
		select {
		case <-ctx.Done():
			return path, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func networkDefaultDenyPolicy(namespace, runID string) map[string]any {
	return map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
		"metadata": map[string]any{"name": "4so-cert-default-deny", "namespace": namespace, "labels": map[string]any{"platform.4so.io/runtime-certification": runID}},
		"spec":     map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}},
	}
}

func networkAllowTenantPolicy(namespace, runID, name, tenant string) map[string]any {
	return map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
		"metadata": map[string]any{"name": name, "namespace": namespace, "labels": map[string]any{"platform.4so.io/runtime-certification": runID}},
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": map[string]any{"platform.4so.io/network-role": "server"}},
			"policyTypes": []any{"Ingress"},
			"ingress": []any{map[string]any{
				"from":  []any{map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"platform.4so.io/cert-tenant": tenant}}}},
				"ports": []any{map[string]any{"protocol": "TCP", "port": 18080}},
			}},
		},
	}
}

func (a *agent) verifyNetworkTenantIsolationRuntime(ctx context.Context, task controlplane.RuntimeCertificationTask) (checks []controlplane.RuntimeCheck, success bool, blocked bool, detail string) {
	if !strings.Contains(a.cfg.RuntimeProbeImage, "@sha256:") {
		detail := "digest-pinned runtime probe image is required for network/tenant isolation certification"
		return blockedNetworkChecks(detail), false, true, detail
	}
	if !a.kubeDiscoveryAvailable(ctx, "/apis/networking.k8s.io/v1") {
		detail := "networking.k8s.io/v1 NetworkPolicy API is required"
		return blockedNetworkChecks(detail), false, true, detail
	}

	executionID := runtimeCertificationExecutionID(task)
	nsA := certificationNamespace("4so-cert-net-a", executionID)
	nsB := certificationNamespace("4so-cert-net-b", executionID)
	checks = []controlplane.RuntimeCheck{}
	cleanupRefs := []runtimeCertificationCleanupRef{}
	track := func(path, owner string) error {
		ref, err := a.runtimeCertificationCleanupRef(ctx, path, owner, task.CleanupToken)
		if err != nil {
			return err
		}
		cleanupRefs = append(cleanupRefs, ref)
		return nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		var cleanupErrs []string
		for i := len(cleanupRefs) - 1; i >= 0; i-- {
			if err := a.cleanupRuntimeCertificationEphemeralObject(cleanup, cleanupRefs[i], 10*time.Second); err != nil {
				cleanupErrs = append(cleanupErrs, cleanupRefs[i].Path+": "+err.Error())
			}
		}
		if len(cleanupErrs) > 0 {
			cleanupDetail := "runtime certification network cleanup failed: " + strings.Join(cleanupErrs, "; ")
			checks = append(checks, check("target-runtime/network-cleanup", time.Now(), false, cleanupDetail))
			success = false
			if detail == "" {
				detail = cleanupDetail
			} else {
				detail += "; " + cleanupDetail
			}
		}
	}()

	started := time.Now()
	if err := a.applyCertificationNamespace(ctx, nsA, task.RunID, "tenant-a", task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/network-namespaces", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if err := track("/api/v1/namespaces/"+nsA, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	if err := a.applyCertificationNamespace(ctx, nsB, task.RunID, "tenant-b", task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/network-namespaces", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if err := track("/api/v1/namespaces/"+nsB, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	checks = append(checks, check("target-runtime/network-namespaces", started, true, "isolated certification namespaces created with distinct tenant labels"))

	defaultDenyPath := "/apis/networking.k8s.io/v1/namespaces/" + nsA + "/networkpolicies/4so-cert-default-deny"
	sameTenantPath := "/apis/networking.k8s.io/v1/namespaces/" + nsA + "/networkpolicies/4so-cert-allow-same-tenant"
	crossTenantPath := "/apis/networking.k8s.io/v1/namespaces/" + nsA + "/networkpolicies/4so-cert-allow-tenant-b"
	started = time.Now()
	if _, err := a.ensureRuntimeCertificationEphemeralObject(ctx, defaultDenyPath, networkDefaultDenyPolicy(nsA, task.RunID), task.RunID, task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/network-default-deny", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if err := track(defaultDenyPath, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	if _, err := a.ensureRuntimeCertificationEphemeralObject(ctx, sameTenantPath, networkAllowTenantPolicy(nsA, task.RunID, "4so-cert-allow-same-tenant", "tenant-a"), task.RunID, task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/network-default-deny", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if err := track(sameTenantPath, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	checks = append(checks, check("target-runtime/network-default-deny", started, true, "default deny ingress plus explicit same-tenant allow policy applied"))

	serverPath, serverIP, err := a.runNetworkServerPod(ctx, nsA, executionID, task.CleanupToken)
	if err != nil {
		checks = append(checks, check("target-runtime/network-intra-tenant-allow", time.Now(), false, err.Error()))
		return checks, false, false, err.Error()
	}
	if err := track(serverPath, executionID); err != nil {
		return checks, false, false, err.Error()
	}

	started = time.Now()
	path, err := a.runNetworkClientPod(ctx, nsA, executionID, "dns-a", "kubernetes.default.svc", "443", true, task.CleanupToken)
	if path != "" {
		if trackErr := track(path, executionID); trackErr != nil {
			return checks, false, false, trackErr.Error()
		}
	}
	checks = append(checks, check("target-runtime/network-dns-tenant-a", started, err == nil, "tenant A resolved kubernetes.default.svc and established TCP/443"))
	if err != nil {
		return checks, false, false, err.Error()
	}
	started = time.Now()
	path, err = a.runNetworkClientPod(ctx, nsB, executionID, "dns-b", "kubernetes.default.svc", "443", true, task.CleanupToken)
	if path != "" {
		if trackErr := track(path, executionID); trackErr != nil {
			return checks, false, false, trackErr.Error()
		}
	}
	checks = append(checks, check("target-runtime/network-dns-tenant-b", started, err == nil, "tenant B resolved kubernetes.default.svc and established TCP/443"))
	if err != nil {
		return checks, false, false, err.Error()
	}

	started = time.Now()
	path, err = a.runNetworkClientPod(ctx, nsA, executionID, "same-tenant", serverIP, networkCertificationPort, true, task.CleanupToken)
	if path != "" {
		if trackErr := track(path, executionID); trackErr != nil {
			return checks, false, false, trackErr.Error()
		}
	}
	checks = append(checks, check("target-runtime/network-intra-tenant-allow", started, err == nil, "same-tenant client reached the certified server through explicit allow policy"))
	if err != nil {
		return checks, false, false, err.Error()
	}

	started = time.Now()
	path, err = a.runNetworkClientPod(ctx, nsB, executionID, "cross-denied", serverIP, networkCertificationPort, false, task.CleanupToken)
	if path != "" {
		if trackErr := track(path, executionID); trackErr != nil {
			return checks, false, false, trackErr.Error()
		}
	}
	checks = append(checks, check("target-runtime/network-cross-tenant-deny", started, err == nil, "cross-tenant client was denied while same-tenant connectivity remained healthy"))
	if err != nil {
		return checks, false, false, err.Error()
	}

	started = time.Now()
	if _, err = a.ensureRuntimeCertificationEphemeralObject(ctx, crossTenantPath, networkAllowTenantPolicy(nsA, task.RunID, "4so-cert-allow-tenant-b", "tenant-b"), task.RunID, task.CleanupToken); err != nil {
		checks = append(checks, check("target-runtime/network-cross-tenant-explicit-allow", started, false, err.Error()))
		return checks, false, false, err.Error()
	}
	if err := track(crossTenantPath, task.RunID); err != nil {
		return checks, false, false, err.Error()
	}
	path, err = a.runNetworkClientPod(ctx, nsB, executionID, "cross-allowed", serverIP, networkCertificationPort, true, task.CleanupToken)
	if path != "" {
		if trackErr := track(path, executionID); trackErr != nil {
			return checks, false, false, trackErr.Error()
		}
	}
	checks = append(checks, check("target-runtime/network-cross-tenant-explicit-allow", started, err == nil, "the same cross-tenant path became reachable only after an explicit narrow allow policy"))
	if err != nil {
		return checks, false, false, err.Error()
	}

	return checks, true, false, ""
}

func networkCertificationEvidenceSummary(checks []controlplane.RuntimeCheck) string {
	keys := []string{}
	for _, item := range checks {
		if item.Status == "PASS" {
			keys = append(keys, item.Key)
		}
	}
	sort.Strings(keys)
	return "network/tenant-isolation executable checks=" + strings.Join(keys, ",")
}
