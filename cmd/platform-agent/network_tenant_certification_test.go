package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestNetworkTenantIsolationCertificationProtocol(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()

	var mu sync.Mutex
	objects := map[string]map[string]any{}
	crossAllowed := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		mu.Lock()
		defer mu.Unlock()
		response := func(code int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		if request.Method == http.MethodGet && path == "/apis/networking.k8s.io/v1" {
			return response(http.StatusOK, `{"groupVersion":"networking.k8s.io/v1","resources":[{"name":"networkpolicies","kind":"NetworkPolicy","namespaced":true,"verbs":["get","create","delete"]}]}`)
		}
		switch request.Method {
		case http.MethodPost:
			raw, _ := io.ReadAll(request.Body)
			var obj map[string]any
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatal(err)
			}
			metadata, _ := obj["metadata"].(map[string]any)
			name, _ := metadata["name"].(string)
			objectPath := strings.TrimRight(path, "/") + "/" + name
			if strings.Contains(objectPath, "/networkpolicies/4so-cert-allow-tenant-b") {
				crossAllowed = true
			}
			if _, exists := objects[objectPath]; exists {
				return response(http.StatusConflict, `{}`)
			}
			metadata["uid"] = "uid-" + name
			metadata["resourceVersion"] = "1"
			if strings.Contains(objectPath, "/pods/") {
				labels, _ := metadata["labels"].(map[string]any)
				if labels["platform.4so.io/runtime-cleanup-token"] != "cleanup-token-real" {
					t.Fatalf("network probe pod %s missing real cleanup token: labels=%v", objectPath, labels)
				}
				namespace, _ := metadata["namespace"].(string)
				spec, _ := obj["spec"].(map[string]any)
				containers, _ := spec["containers"].([]any)
				container, _ := containers[0].(map[string]any)
				env, _ := container["env"].([]any)
				values := map[string]string{}
				for _, rawEnv := range env {
					item, _ := rawEnv.(map[string]any)
					n, _ := item["name"].(string)
					v, _ := item["value"].(string)
					values[n] = v
				}
				status := map[string]any{}
				if values["PLATFORM_PROBE_LISTEN_PORT"] != "" {
					status = map[string]any{"phase": "Running", "podIP": "10.42.0.50", "containerStatuses": []any{map[string]any{"ready": true}}}
				} else {
					phase := "Failed"
					if values["PLATFORM_PROBE_HOST"] == "kubernetes.default.svc" || strings.Contains(namespace, "net-a") || crossAllowed {
						phase = "Succeeded"
					}
					status = map[string]any{"phase": phase}
					if phase == "Failed" {
						status["containerStatuses"] = []any{map[string]any{"name": "probe", "state": map[string]any{"terminated": map[string]any{"message": `{"dnsResolved":true,"addresses":["10.42.0.50"],"tcpConnected":false,"error":"tcp connection failed: i/o timeout","durationMillis":10000}`}}}}
					}
				}
				obj["status"] = status
			}
			objects[objectPath] = obj
			return response(http.StatusCreated, `{}`)
		case http.MethodPatch:
			raw, _ := io.ReadAll(request.Body)
			var obj map[string]any
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(path, "/networkpolicies/4so-cert-allow-tenant-b") {
				crossAllowed = true
			}
			if strings.Contains(path, "/pods/") {
				metadata, _ := obj["metadata"].(map[string]any)
				namespace, _ := metadata["namespace"].(string)
				spec, _ := obj["spec"].(map[string]any)
				containers, _ := spec["containers"].([]any)
				container, _ := containers[0].(map[string]any)
				env, _ := container["env"].([]any)
				values := map[string]string{}
				for _, rawEnv := range env {
					item, _ := rawEnv.(map[string]any)
					name, _ := item["name"].(string)
					value, _ := item["value"].(string)
					values[name] = value
				}
				status := map[string]any{}
				if values["PLATFORM_PROBE_LISTEN_PORT"] != "" {
					status = map[string]any{"phase": "Running", "podIP": "10.42.0.50", "containerStatuses": []any{map[string]any{"ready": true}}}
				} else {
					phase := "Failed"
					if values["PLATFORM_PROBE_HOST"] == "kubernetes.default.svc" || strings.Contains(namespace, "net-a") || crossAllowed {
						phase = "Succeeded"
					}
					status = map[string]any{"phase": phase}
					if phase == "Failed" {
						status["containerStatuses"] = []any{map[string]any{"name": "probe", "state": map[string]any{"terminated": map[string]any{"message": `{"dnsResolved":true,"addresses":["10.42.0.50"],"tcpConnected":false,"error":"tcp connection failed: i/o timeout","durationMillis":10000}`}}}}
					}
				}
				obj["status"] = status
			}
			objects[path] = obj
			return response(http.StatusOK, `{}`)
		case http.MethodGet:
			obj, ok := objects[path]
			if !ok {
				return response(http.StatusNotFound, `{}`)
			}
			raw, _ := json.Marshal(obj)
			return response(http.StatusOK, string(raw))
		case http.MethodDelete:
			delete(objects, path)
			return response(http.StatusOK, `{}`)
		default:
			t.Fatalf("unexpected request %s %s", request.Method, path)
			return response(http.StatusInternalServerError, `{}`)
		}
	})}

	a := &agent{kube: client, cfg: config{RuntimeProbeImage: "registry.local/platform-probe@sha256:" + strings.Repeat("a", 64)}}
	task := controlplane.RuntimeCertificationTask{RunID: "rtc_network_test", Profile: controlplane.RuntimeCertificationTargetV1, Namespace: "4so-cert-root", CleanupToken: "cleanup-token-real"}
	checks, ok, blocked, errText := a.verifyNetworkTenantIsolationRuntime(context.Background(), task)
	if !ok || blocked || errText != "" {
		t.Fatalf("network certification failed: ok=%v blocked=%v err=%s checks=%+v", ok, blocked, errText, checks)
	}
	if len(checks) != 7 {
		t.Fatalf("expected 7 network checks, got %d: %+v", len(checks), checks)
	}
	for _, item := range checks {
		if item.Status != "PASS" {
			t.Fatalf("non-pass network check: %+v", item)
		}
	}
	if !crossAllowed {
		t.Fatal("explicit cross-tenant allow policy was never exercised")
	}
}

func TestNetworkDenyRejectsGenericPodFailureWithoutTCPProof(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()

	var pod map[string]any
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		response := func(code int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		switch {
		case request.Method == http.MethodGet && strings.Contains(path, "/pods/"):
			if pod == nil {
				return response(http.StatusNotFound, `{}`)
			}
			raw, _ := json.Marshal(pod)
			return response(http.StatusOK, string(raw))
		case request.Method == http.MethodPost && strings.HasSuffix(path, "/pods"):
			if err := json.NewDecoder(request.Body).Decode(&pod); err != nil {
				t.Fatal(err)
			}
			meta, _ := pod["metadata"].(map[string]any)
			meta["uid"] = "uid-deny"
			meta["resourceVersion"] = "1"
			pod["status"] = map[string]any{"phase": "Failed", "containerStatuses": []any{map[string]any{"name": "probe", "state": map[string]any{"terminated": map[string]any{"message": `{"dnsResolved":false,"tcpConnected":false,"error":"dns lookup failed: temporary resolver failure"}`}}}}}
			return response(http.StatusCreated, `{}`)
		default:
			t.Fatalf("unexpected request %s %s", request.Method, path)
			return response(http.StatusInternalServerError, `{}`)
		}
	})}
	a := &agent{kube: client, cfg: config{RuntimeProbeImage: "registry.local/platform-probe@sha256:" + strings.Repeat("a", 64)}}
	_, err := a.runNetworkClientPod(context.Background(), "tenant-test", "rtc_test", "deny", "10.42.0.50", networkCertificationPort, false, "cleanup-token-test")
	if err == nil || !strings.Contains(err.Error(), "not authoritative") {
		t.Fatalf("generic pod failure was accepted as network deny proof: %v", err)
	}
}

func TestNetworkTenantIsolationCapabilitiesRequireProbeAndNetworkPolicyAPI(t *testing.T) {
	a := &agent{cfg: config{RuntimeProbeImage: "registry.local/platform-probe@sha256:" + strings.Repeat("b", 64)}}
	resources := []controlplane.ClusterAPIResourceObservation{{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy", Resource: "networkpolicies", Verbs: []string{"get", "create", "delete"}}}
	caps, ok := a.networkTenantIsolationCapabilities(resources)
	if !ok || len(caps) != 2 || caps[0] != "cert.network" || caps[1] != "cert.tenant-isolation" {
		t.Fatalf("unexpected caps: %v ok=%v", caps, ok)
	}
	a.cfg.RuntimeProbeImage = "registry.local/platform-probe:latest"
	if caps, ok = a.networkTenantIsolationCapabilities(resources); ok || len(caps) != 0 {
		t.Fatalf("mutable probe image advertised network certification: %v", caps)
	}
}
