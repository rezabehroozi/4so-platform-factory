package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"platform.4so.io/factory/catalog"
	"platform.4so.io/factory/internal/agentpki"
	"platform.4so.io/factory/internal/baseline"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/targetmodel"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCredentialSecretPersistenceAndEnrollmentClear(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	var requests []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		var body []byte
		if request.Body != nil {
			body, _ = io.ReadAll(request.Body)
		}
		if request.Method == http.MethodGet {
			body = []byte(`{"data":{"token":"` + base64.StdEncoding.EncodeToString([]byte("agent-token")) + `","clusterId":"` + base64.StdEncoding.EncodeToString([]byte("cluster-1")) + `"}}`)
		} else if !strings.Contains(string(body), `"data"`) {
			t.Fatalf("patch does not use Secret.data: %s", body)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
	})}
	a := &agent{cfg: config{Namespace: "4so-platform-agent", CredentialSecret: "credential", BootstrapSecret: "bootstrap"}, kube: client}
	credential, ok, err := a.readSecretCredential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ok || credential.Token != "agent-token" || credential.ClusterID != "cluster-1" {
		t.Fatalf("credential=%+v ok=%v", credential, ok)
	}
	if err := a.persistSecretCredential(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	if err := a.clearEnrollmentToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 3 || requests[0] != "GET /api/v1/namespaces/4so-platform-agent/secrets/credential" || requests[2] != "PATCH /api/v1/namespaces/4so-platform-agent/secrets/bootstrap" {
		t.Fatalf("requests=%v", requests)
	}
}

func TestCredentialSecretReadFailsClosedOnKubernetesAPIError(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Body: io.NopCloser(strings.NewReader(`{"message":"forbidden"}`)), Header: make(http.Header)}, nil
	})}
	a := &agent{cfg: config{Namespace: "4so-platform-agent", CertificateSecret: "cert", CredentialSecret: "credential"}, kube: client}
	if _, _, err := a.readSecretCredential(context.Background()); err == nil {
		t.Fatal("Kubernetes Secret authorization failure must not fall back to enrollment")
	}
}
func TestBaselineTaskAllowlist(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	resources := []controlplane.BaselineTaskResource{
		{APIVersion: "v1", Kind: "ResourceQuota", Namespace: "4so-platform-baseline", Name: "4so-baseline-quota", Object: map[string]any{"metadata": map[string]any{"name": "4so-baseline-quota", "namespace": "4so-platform-baseline", "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}},
		{APIVersion: "v1", Kind: "LimitRange", Namespace: "4so-platform-baseline", Name: "4so-baseline-limits", Object: map[string]any{"metadata": map[string]any{"name": "4so-baseline-limits", "namespace": "4so-platform-baseline", "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}},
		{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: "4so-platform-baseline", Name: "4so-default-deny-ingress", Object: map[string]any{"metadata": map[string]any{"name": "4so-default-deny-ingress", "namespace": "4so-platform-baseline", "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "4so-platform-baseline", Name: "4so-baseline-observer", Object: map[string]any{"metadata": map[string]any{"name": "4so-baseline-observer", "namespace": "4so-platform-baseline", "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}},
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: "4so-platform-baseline", Name: "4so-baseline-revision", Object: map[string]any{"metadata": map[string]any{"name": "4so-baseline-revision", "namespace": "4so-platform-baseline", "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}},
	}
	task := controlplane.BaselineTask{TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "APPLY", BaselineID: "secure-namespace-foundation", BaselineVersion: "1.0.0", TargetNamespace: "4so-platform-baseline", DesiredDigest: digest, Resources: resources}
	if err := validateBaselineTask(task); err != nil {
		t.Fatal(err)
	}
	task.Resources[0].Namespace = "default"
	if err := validateBaselineTask(task); err == nil {
		t.Fatal("task escaped managed namespace")
	}
}

func TestApplyBaselineUsesAllowlistedServerSideApplyAndVerifiesDigest(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	digest := "sha256:" + strings.Repeat("b", 64)
	resources := baseline.Resources("bld_1", digest)
	objects := map[string]map[string]any{}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		switch request.Method {
		case http.MethodPost:
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			metadata, _ := object["metadata"].(map[string]any)
			name, _ := metadata["name"].(string)
			if name == "" {
				t.Fatal("created baseline object has no name")
			}
			objects[strings.TrimSuffix(path, "/")+"/"+name] = object
			return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodPatch:
			if request.Header.Get("Content-Type") != "application/apply-patch+yaml" {
				t.Fatalf("content-type=%q", request.Header.Get("Content-Type"))
			}
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			objects[path] = object
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodGet:
			object, ok := objects[path]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			raw, _ := json.Marshal(object)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected method %s", request.Method)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	inv := controlplane.ClusterInventory{SchemaDiscoveryVersion: "OPENAPI_V3", SchemaDiscoveryDigest: "sha256:" + strings.Repeat("7", 64), SchemaDiscoveryComplete: true, APIResources: []controlplane.ClusterAPIResourceObservation{
		{APIVersion: "v1", Version: "v1", Kind: "ResourceQuota", Resource: "resourcequotas", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
		{APIVersion: "v1", Version: "v1", Kind: "LimitRange", Resource: "limitranges", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
		{APIVersion: "v1", Version: "v1", Kind: "ServiceAccount", Resource: "serviceaccounts", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
		{APIVersion: "v1", Version: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
		{APIVersion: "networking.k8s.io/v1", Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy", Resource: "networkpolicies", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
	}}
	rollback := make([]controlplane.PlanRollbackResource, 0, len(resources))
	for _, resource := range resources {
		rollback = append(rollback, controlplane.PlanRollbackResource{Resource: resource.Kind + "/" + resource.Name, ChangeAction: "ADD", Strategy: "DELETE_CREATED_RESOURCE", Status: "PASS", AuthorizationStatus: "PASS", DryRunStatus: "NOT_APPLICABLE"})
	}
	task := controlplane.BaselineTask{DeploymentID: "bld_1", DeploymentRev: 1, Action: "APPLY", BaselineID: baseline.SecureNamespaceID, BaselineVersion: baseline.SecureNamespaceVersion, TargetNamespace: baseline.ManagedNamespace, DesiredDigest: digest, Inventory: inv, Resources: resources, Rollback: rollback, PlanImpactDigest: "sha256:" + strings.Repeat("8", 64)}
	plan, err := a.baselineEvidenceCollectionPlan(task)
	if err != nil {
		t.Fatal(err)
	}
	task.EvidencePlan = plan
	result := a.applyBaseline(context.Background(), task)
	if !result.Success || result.ObservedDigest != digest {
		t.Fatalf("result=%+v", result)
	}
	if len(objects) != 5 {
		t.Fatalf("applied objects=%d", len(objects))
	}
	if len(result.Evidence) != 6 {
		t.Fatalf("completion evidence=%d want=6", len(result.Evidence))
	}
	for _, item := range result.Evidence {
		if item.Digest == "" || item.Size <= 0 || !strings.HasPrefix(item.Location, "/api/v1/baseline-deployments/bld_1/evidence/") || item.RetentionDays != controlplane.PlanEvidenceRetentionDays {
			t.Fatalf("invalid evidence artifact=%+v", item)
		}
	}
}

func TestApplyBaselineRejectsMissingEvidenceContractBeforeMutation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	patches := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPatch {
			patches++
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	task := controlplane.BaselineTask{DeploymentID: "legacy-bld", Action: "APPLY", BaselineID: baseline.SecureNamespaceID, BaselineVersion: baseline.SecureNamespaceVersion, TargetNamespace: baseline.ManagedNamespace, DesiredDigest: digest, Resources: baseline.Resources("legacy-bld", digest)}
	result := a.applyBaseline(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "evidence collection contract is invalid") || patches != 0 {
		t.Fatalf("result=%+v patches=%d", result, patches)
	}
}

func TestRuntimeVerificationRunsDigestPinnedProbeJob(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	digest := "sha256:" + strings.Repeat("c", 64)
	probeImage := "registry.local/platform-probe@sha256:" + strings.Repeat("d", 64)
	objects := map[string]string{}
	for key, path := range baselineResourcePaths {
		name := strings.SplitN(key, "/", 2)[1]
		obj := map[string]any{"metadata": map[string]any{"name": name, "namespace": "4so-platform-baseline", "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}
		if strings.HasPrefix(key, "ConfigMap/") {
			obj["data"] = map[string]any{"desiredDigest": digest}
		}
		raw, _ := json.Marshal(obj)
		objects[path] = string(raw)
	}
	jobCreated := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		body := "{}"
		code := http.StatusOK
		switch {
		case request.Method == http.MethodGet && path == "/api/v1/nodes":
			body = `{"items":[{"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`
		case request.Method == http.MethodGet && objects[path] != "":
			body = objects[path]
		case request.Method == http.MethodPost && path == "/apis/batch/v1/namespaces/4so-platform-baseline/jobs":
			jobCreated = true
			body = `{"metadata":{"uid":"job-uid-current","resourceVersion":"1"}}`
			var job map[string]any
			if err := json.NewDecoder(request.Body).Decode(&job); err != nil {
				t.Fatal(err)
			}
			spec := job["spec"].(map[string]any)
			template := spec["template"].(map[string]any)
			podSpec := template["spec"].(map[string]any)
			containers := podSpec["containers"].([]any)
			container := containers[0].(map[string]any)
			if container["image"] != probeImage {
				t.Fatalf("probe image=%v", container["image"])
			}
		case request.Method == http.MethodGet && strings.HasPrefix(path, "/apis/batch/v1/namespaces/4so-platform-baseline/jobs/"):
			if !jobCreated {
				code = http.StatusNotFound
			} else {
				body = `{"metadata":{"uid":"job-uid-current","resourceVersion":"2","labels":{"platform.4so.io/runtime-verification":"rtv_1234567890"}},"status":{"succeeded":1}}`
			}
		case request.Method == http.MethodGet && path == "/api/v1/namespaces/4so-platform-baseline/pods":
			body = `{"items":[{"metadata":{"name":"probe-pod","ownerReferences":[{"uid":"job-uid-current"}]},"status":{"containerStatuses":[{"name":"probe","state":{"terminated":{"message":"{\"dnsResolved\":true,\"addresses\":[\"10.43.0.1\"],\"tcpConnected\":true,\"durationMillis\":4}"}}}]}}]}`
		case request.Method == http.MethodDelete && strings.Contains(path, "/jobs/"):
			if !jobCreated {
				code = http.StatusNotFound
			} else {
				jobCreated = false
				code = http.StatusOK
			}
		default:
			t.Fatalf("unexpected request %s %s?%s", request.Method, path, request.URL.RawQuery)
		}
		return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	a := &agent{cfg: config{RuntimeProbeImage: probeImage}, kube: client}
	task := controlplane.RuntimeVerificationTask{VerificationID: "rtv_1234567890", VerificationRevision: 2, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), BaselineDeploymentID: "bld_1", TargetNamespace: "4so-platform-baseline", DesiredDigest: digest, ProbeImage: probeImage}
	result := a.runRuntimeVerification(context.Background(), task)
	if !result.Success || result.ObservedDigest != digest {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Checks) < 7 {
		t.Fatalf("checks=%+v", result.Checks)
	}
}

func TestRuntimeProbeWaitsForPriorJobDeletionBeforeRecreate(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	verificationID := "rtv_retry-delete-race"
	jobName := "4so-runtime-probe-" + strings.TrimPrefix(verificationID, "rtv_")
	jobPath := "/apis/batch/v1/namespaces/4so-platform-baseline/jobs/" + jobName
	deletionObservations := 0
	deletionRequested := false
	created := false
	createdOnce := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		status := http.StatusOK
		body := `{}`
		switch {
		case request.Method == http.MethodDelete && path == jobPath:
			deletionRequested = true
			if created {
				created = false
			}
			return &http.Response{StatusCode: status, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		case request.Method == http.MethodGet && path == jobPath && !created:
			deletionObservations++
			if !deletionRequested || deletionObservations < 3 {
				body = `{"metadata":{"name":"` + jobName + `","uid":"job-uid-old","resourceVersion":"7","labels":{"platform.4so.io/runtime-verification":"` + verificationID + `"}}}`
			} else {
				status = http.StatusNotFound
			}
		case request.Method == http.MethodPost && path == "/apis/batch/v1/namespaces/4so-platform-baseline/jobs":
			if deletionObservations < 2 {
				t.Fatalf("probe job recreated before prior deletion was observed")
			}
			created = true
			createdOnce = true
			status = http.StatusCreated
			body = `{"metadata":{"uid":"job-uid-retry","resourceVersion":"8"}}`
		case request.Method == http.MethodGet && path == jobPath && created:
			body = `{"metadata":{"name":"` + jobName + `","uid":"job-uid-retry","resourceVersion":"9","labels":{"platform.4so.io/runtime-verification":"` + verificationID + `"}},"status":{"succeeded":1}}`
		case request.Method == http.MethodGet && path == "/api/v1/namespaces/4so-platform-baseline/pods":
			body = `{"items":[{"metadata":{"name":"probe-pod","ownerReferences":[{"uid":"job-uid-retry"}]},"status":{"containerStatuses":[{"name":"probe","state":{"terminated":{"message":"{\"dnsResolved\":true,\"addresses\":[\"10.43.0.1\"],\"tcpConnected\":true,\"durationMillis\":2}"}}}]}}]}`
		default:
			t.Fatalf("unexpected request %s %s?%s", request.Method, path, request.URL.RawQuery)
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	checks, err := a.runProbeJob(context.Background(), controlplane.RuntimeVerificationTask{VerificationID: verificationID, ProbeImage: "registry.local/probe@sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("run probe: %v checks=%+v", err, checks)
	}
	if deletionObservations < 2 || !createdOnce || created {
		t.Fatalf("deletionObservations=%d createdOnce=%v createdAfterCleanup=%v", deletionObservations, createdOnce, created)
	}
}

func TestRuntimeProbeReadsTerminationMessageOnlyFromCurrentJobUID(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	verificationID := "rtv_retry-stale-pod"
	jobName := "4so-runtime-probe-" + strings.TrimPrefix(verificationID, "rtv_")
	jobPath := "/apis/batch/v1/namespaces/4so-platform-baseline/jobs/" + jobName
	created := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		status := http.StatusOK
		body := `{}`
		switch {
		case request.Method == http.MethodDelete && path == jobPath:
			if created {
				created = false
				status = http.StatusOK
			} else {
				status = http.StatusNotFound
			}
		case request.Method == http.MethodPost && path == "/apis/batch/v1/namespaces/4so-platform-baseline/jobs":
			created = true
			status = http.StatusCreated
			body = `{"metadata":{"uid":"job-uid-current","resourceVersion":"1"}}`
		case request.Method == http.MethodGet && path == jobPath:
			if !created {
				status = http.StatusNotFound
			} else {
				body = `{"metadata":{"uid":"job-uid-current","resourceVersion":"2","labels":{"platform.4so.io/runtime-verification":"` + verificationID + `"}},"status":{"succeeded":1}}`
			}
		case request.Method == http.MethodGet && path == "/api/v1/namespaces/4so-platform-baseline/pods":
			body = `{"items":[` +
				`{"metadata":{"name":"stale-pod","ownerReferences":[{"uid":"job-uid-old"}]},"status":{"containerStatuses":[{"name":"probe","state":{"terminated":{"message":"not-json"}}}]}},` +
				`{"metadata":{"name":"current-pod","ownerReferences":[{"uid":"job-uid-current"}]},"status":{"containerStatuses":[{"name":"probe","state":{"terminated":{"message":"{\"dnsResolved\":true,\"addresses\":[\"10.43.0.1\"],\"tcpConnected\":true,\"durationMillis\":2}"}}}]}}]}`
		default:
			t.Fatalf("unexpected request %s %s?%s", request.Method, path, request.URL.RawQuery)
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	checks, err := a.runProbeJob(context.Background(), controlplane.RuntimeVerificationTask{VerificationID: verificationID, ProbeImage: "registry.local/probe@sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("run probe: %v checks=%+v", err, checks)
	}
}

func TestRuntimeVerificationRejectsUnconfiguredProbeImage(t *testing.T) {
	task := controlplane.RuntimeVerificationTask{VerificationID: "rtv_1", VerificationRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), BaselineDeploymentID: "bld_1", TargetNamespace: "4so-platform-baseline", DesiredDigest: "sha256:" + strings.Repeat("a", 64), ProbeImage: "registry/probe@sha256:" + strings.Repeat("b", 64)}
	if err := validateRuntimeVerificationTask(task, "registry/probe@sha256:"+strings.Repeat("c", 64)); err == nil {
		t.Fatal("mismatched probe image accepted")
	}
}

func TestTenantTaskApplyAndDeleteOwnership(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	digest := "sha256:" + strings.Repeat("e", 64)
	tenantID := "ten_123"
	namespace := "tenant-customer-a-123456"
	storage := controlplane.TenantStoragePolicy{ClassSelector: "default", StorageClass: "replicated", RequestQuota: "1Ti", MaxPVCSize: "100Gi"}
	backup := controlplane.TenantBackupPolicy{Provider: "velero", Schedule: "0 2 * * *", Retention: "336h0m0s"}
	security := controlplane.TenantSecurityPolicy{PodSecurityLevel: "restricted", DefaultDenyIngress: true, DefaultDenyEgress: true, AllowDNS: true}
	makeResources := func(digest, plan string, cpu string) []controlplane.BaselineTaskResource {
		labels := map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID, "platform.4so.io/project-id": "prj_1", "platform.4so.io/tenant": "true", "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/audit": "restricted", "pod-security.kubernetes.io/warn": "restricted", "pod-security.kubernetes.io/enforce-version": "latest"}
		ann := map[string]any{"platform.4so.io/desired-digest": digest, "platform.4so.io/tenant-plan": plan, "platform.4so.io/storage-class": "replicated", "platform.4so.io/backup-provider": "velero"}
		return []controlplane.BaselineTaskResource{
			{APIVersion: "v1", Kind: "Namespace", Name: namespace, Object: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": namespace, "labels": labels, "annotations": ann}}},
			{APIVersion: "v1", Kind: "ResourceQuota", Namespace: namespace, Name: "tenant-quota", Object: map[string]any{"apiVersion": "v1", "kind": "ResourceQuota", "metadata": map[string]any{"name": "tenant-quota", "namespace": namespace, "labels": labels, "annotations": ann}, "spec": map[string]any{"hard": map[string]any{"requests.cpu": cpu, "requests.storage": "1Ti", "replicated.storageclass.storage.k8s.io/requests.storage": "1Ti"}}}},
			{APIVersion: "v1", Kind: "LimitRange", Namespace: namespace, Name: "tenant-default-limits", Object: map[string]any{"apiVersion": "v1", "kind": "LimitRange", "metadata": map[string]any{"name": "tenant-default-limits", "namespace": namespace, "labels": labels, "annotations": ann}, "spec": map[string]any{"limits": []any{map[string]any{"type": "PersistentVolumeClaim", "max": map[string]any{"storage": "100Gi"}}}}}},
			{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: namespace, Name: "tenant-default-deny-all", Object: map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "tenant-default-deny-all", "namespace": namespace, "labels": labels, "annotations": ann}, "spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress", "Egress"}}}},
			{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: namespace, Name: "tenant-allow-dns-egress", Object: map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "tenant-allow-dns-egress", "namespace": namespace, "labels": labels, "annotations": ann}, "spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Egress"}, "egress": []any{map[string]any{}}}}},
			{APIVersion: "velero.io/v1", Kind: "Schedule", Namespace: "velero", Name: controlplane.TenantBackupScheduleName(tenantID), Object: map[string]any{"apiVersion": "velero.io/v1", "kind": "Schedule", "metadata": map[string]any{"name": controlplane.TenantBackupScheduleName(tenantID), "namespace": "velero", "labels": labels, "annotations": ann}, "spec": map[string]any{"schedule": "0 2 * * *", "template": map[string]any{"includedNamespaces": []any{namespace}, "ttl": "336h0m0s", "snapshotVolumes": true}}}},
			{APIVersion: "v1", Kind: "ConfigMap", Namespace: namespace, Name: "tenant-platform-state", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "tenant-platform-state", "namespace": namespace, "labels": labels, "annotations": ann}, "data": map[string]any{"desiredDigest": digest, "plan": plan}}},
		}
	}
	objects := map[string]map[string]any{}
	pods := map[string]map[string]any{}
	deleteCalls := 0
	holdTenantNamespaceDelete := true
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		if request.Method == http.MethodPatch && strings.HasSuffix(path, "/pods/4so-tenant-psa-negative") {
			return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Body: io.NopCloser(strings.NewReader(`{"message":"violates PodSecurity restricted: privileged"}`)), Header: make(http.Header)}, nil
		}
		switch request.Method {
		case http.MethodPost:
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			meta, _ := object["metadata"].(map[string]any)
			name := fmt.Sprint(meta["name"])
			kind := fmt.Sprint(object["kind"])
			objectPath := strings.TrimRight(request.URL.Path, "/") + "/" + name
			if _, exists := objects[objectPath]; exists {
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			meta["uid"] = "uid-" + strings.ToLower(kind) + "-" + name
			meta["resourceVersion"] = "1"
			objects[objectPath] = object
			return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodPatch:
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			meta, _ := object["metadata"].(map[string]any)
			if existing, ok := objects[path]; ok {
				existingMeta, _ := existing["metadata"].(map[string]any)
				if uid, _ := existingMeta["uid"].(string); uid != "" {
					meta["uid"] = uid
				}
			}
			meta["resourceVersion"] = "2"
			objects[path] = object
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodGet:
			if path == "/api/v1/namespaces/"+namespace+"/pods" {
				items := make([]any, 0, len(pods))
				for _, pod := range pods {
					items = append(items, pod)
				}
				raw, _ := json.Marshal(map[string]any{"items": items})
				return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
			}
			podPrefix := "/api/v1/namespaces/" + namespace + "/pods/"
			if strings.HasPrefix(path, podPrefix) {
				pod, ok := pods[strings.TrimPrefix(path, podPrefix)]
				if !ok {
					return &http.Response{StatusCode: 404, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
				}
				raw, _ := json.Marshal(pod)
				return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
			}
			object, ok := objects[path]
			if !ok {
				return &http.Response{StatusCode: 404, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			raw, _ := json.Marshal(object)
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
		case http.MethodDelete:
			deleteCalls++
			podPrefix := "/api/v1/namespaces/" + namespace + "/pods/"
			if strings.HasPrefix(path, podPrefix) {
				delete(pods, strings.TrimPrefix(path, podPrefix))
			} else if !(holdTenantNamespaceDelete && path == "/api/v1/namespaces/"+namespace) {
				delete(objects, path)
			}
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected method %s", request.Method)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	apply := controlplane.TenantTask{TenantID: tenantID, TenantRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "PROVISION", Namespace: namespace, PlanName: "small", DesiredDigest: digest, Resources: makeResources(digest, "small", "4"), StoragePolicy: storage, BackupPolicy: backup, SecurityPolicy: security}
	objects["/api/v1/namespaces/"+namespace] = map[string]any{"metadata": map[string]any{"labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": "ten_other"}}}
	result := a.executeTenantTask(context.Background(), apply)
	if result.Success || !strings.Contains(result.Error, "not owned") {
		t.Fatalf("wrong-owner provision must fail before mutation: %+v", result)
	}
	if got := objects["/api/v1/namespaces/"+namespace]["metadata"].(map[string]any)["labels"].(map[string]any)["platform.4so.io/tenant-id"]; got != "ten_other" {
		t.Fatalf("wrong-owner namespace was mutated: %v", got)
	}
	delete(objects, "/api/v1/namespaces/"+namespace)
	result = a.executeTenantTask(context.Background(), apply)
	if !result.Success || result.ObservedDigest != digest || len(objects) != 7 || len(result.Evidence) != 8 || result.EvidenceDigest == "" {
		t.Fatalf("apply result=%+v objects=%d", result, len(objects))
	}
	legacySchedulePath := "/apis/velero.io/v1/namespaces/velero/schedules/tenant-platform-backup"
	objects[legacySchedulePath] = map[string]any{"metadata": map[string]any{"uid": "uid-legacy-schedule", "resourceVersion": "7", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}, "spec": map[string]any{"template": map[string]any{"includedNamespaces": []any{namespace}}}}
	resizeDigest := "sha256:" + strings.Repeat("f", 64)
	resizeTask := apply
	resizeTask.TenantRevision = 2
	resizeTask.Action = "RESIZE"
	resizeTask.PlanName = "medium"
	resizeTask.DesiredDigest = resizeDigest
	resizeTask.Resources = makeResources(resizeDigest, "medium", "12")
	result = a.executeTenantTask(context.Background(), resizeTask)
	if !result.Success || result.ObservedDigest != resizeDigest {
		t.Fatalf("resize result=%+v", result)
	}
	if _, found := objects[legacySchedulePath]; found {
		t.Fatalf("owned legacy tenant backup schedule was not removed during reconcile")
	}
	quotaObject := objects["/api/v1/namespaces/"+namespace+"/resourcequotas/tenant-quota"]
	quotaSpec, _ := quotaObject["spec"].(map[string]any)
	hard, _ := quotaSpec["hard"].(map[string]any)
	if hard["requests.cpu"] != "12" {
		t.Fatalf("resize quota not applied: %#v", quotaObject)
	}

	controlledPod := func(name string) map[string]any {
		return map[string]any{"metadata": map[string]any{"name": name, "uid": "uid-" + name, "resourceVersion": "1", "ownerReferences": []any{map[string]any{"uid": "controller-" + name, "controller": true}}}}
	}
	pods["web-1"] = controlledPod("web-1")
	pods["worker-1"] = controlledPod("worker-1")
	suspendDigest := "sha256:" + strings.Repeat("1", 64)
	suspendResources := makeResources(suspendDigest, "medium", "12")
	quotaSpecSuspend, _ := suspendResources[1].Object["spec"].(map[string]any)
	hardSuspend, _ := quotaSpecSuspend["hard"].(map[string]any)
	hardSuspend["pods"] = "0"
	suspendTask := controlplane.TenantTask{TenantID: tenantID, TenantRevision: 3, TaskFenceToken: 3, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "SUSPEND", Namespace: namespace, PlanName: "medium", DesiredDigest: suspendDigest, Resources: suspendResources, StoragePolicy: storage, BackupPolicy: backup, SecurityPolicy: security}
	result = a.executeTenantTask(context.Background(), suspendTask)
	if !result.Success || len(pods) != 0 {
		t.Fatalf("suspend did not stop tenant workloads: result=%+v pods=%#v", result, pods)
	}
	foundSuspendEvidence := false
	for _, item := range result.Evidence {
		if item.Key == "suspension/no-running-pods" && item.Status == "PASS" {
			foundSuspendEvidence = true
		}
	}
	if !foundSuspendEvidence {
		t.Fatalf("suspend zero-pod evidence missing: %+v", result.Evidence)
	}
	validatedSuspend := result
	validatedSuspend.TenantID = tenantID
	if err := controlplane.ValidateTenantTaskEvidence(validatedSuspend); err != nil {
		t.Fatalf("real agent suspend evidence rejected by control plane: %v evidence=%+v", err, result.Evidence)
	}

	pods["standalone"] = map[string]any{"metadata": map[string]any{"name": "standalone", "uid": "uid-standalone", "resourceVersion": "1"}}
	deletesBeforeStandalone := deleteCalls
	result = a.executeTenantTask(context.Background(), suspendTask)
	if result.Success || !strings.Contains(result.Error, "standalone pod") || deleteCalls != deletesBeforeStandalone {
		t.Fatalf("standalone pod suspend must fail before mutation: result=%+v deletes=%d/%d", result, deleteCalls, deletesBeforeStandalone)
	}
	delete(pods, "standalone")

	pods["referenced-only"] = map[string]any{"metadata": map[string]any{"name": "referenced-only", "uid": "uid-referenced-only", "resourceVersion": "1", "ownerReferences": []any{map[string]any{"uid": "not-a-controller", "controller": false}}}}
	deletesBeforeReferencedOnly := deleteCalls
	result = a.executeTenantTask(context.Background(), suspendTask)
	if result.Success || !strings.Contains(result.Error, "standalone pod") || deleteCalls != deletesBeforeReferencedOnly {
		t.Fatalf("non-controller ownerReference must not be treated as resumable controller ownership: result=%+v deletes=%d/%d", result, deleteCalls, deletesBeforeReferencedOnly)
	}
	delete(pods, "referenced-only")

	namespaceDeleteBase := deleteCalls
	deleteTask := controlplane.TenantTask{TenantID: tenantID, TenantRevision: 4, TaskFenceToken: 4, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "DELETE", Namespace: namespace, PlanName: "small"}
	result = a.executeTenantTask(context.Background(), deleteTask)
	if !result.Success || result.Deleted || deleteCalls != namespaceDeleteBase+2 {
		t.Fatalf("delete should remove the tenant backup schedule and stay in progress while namespace still exists: result=%+v calls=%d", result, deleteCalls)
	}
	schedulePath := "/apis/velero.io/v1/namespaces/velero/schedules/" + controlplane.TenantBackupScheduleName(tenantID)
	if _, found := objects[schedulePath]; found {
		t.Fatalf("tenant backup schedule remained after delete attempt: %s", schedulePath)
	}
	holdTenantNamespaceDelete = false
	result = a.executeTenantTask(context.Background(), deleteTask)
	if !result.Success || !result.Deleted || deleteCalls != namespaceDeleteBase+3 {
		t.Fatalf("delete should complete only after schedule and namespace are absent: result=%+v calls=%d", result, deleteCalls)
	}

	objects["/api/v1/namespaces/"+namespace] = map[string]any{"metadata": map[string]any{"uid": "uid-tenant-recreated", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}
	objects[schedulePath] = map[string]any{"metadata": map[string]any{"labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": "other-tenant"}}}
	deleteCalls = 0
	result = a.executeTenantTask(context.Background(), deleteTask)
	if result.Success || deleteCalls != 0 || !strings.Contains(result.Error, "backup schedule not owned") {
		t.Fatalf("wrong owner schedule delete result=%+v calls=%d", result, deleteCalls)
	}
	delete(objects, schedulePath)
	objects["/api/v1/namespaces/"+namespace] = map[string]any{"metadata": map[string]any{"labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": "other-tenant"}}}
	deleteCalls = 0
	result = a.executeTenantTask(context.Background(), deleteTask)
	if result.Success || deleteCalls != 0 || !strings.Contains(result.Error, "not owned") {
		t.Fatalf("wrong owner namespace delete result=%+v calls=%d", result, deleteCalls)
	}
}

func TestProviderProfileVerifiesExactClusterClassAndWorkerClass(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	class := map[string]any{
		"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "ClusterClass",
		"metadata": map[string]any{"name": "vsphere-standard", "namespace": "4so-provider-system"},
		"spec":     map[string]any{"workers": map[string]any{"machineDeployments": []any{map[string]any{"class": "worker-standard"}}}},
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/apis/cluster.x-k8s.io/v1beta2/namespaces/4so-provider-system/clusterclasses/vsphere-standard" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		raw, _ := json.Marshal(class)
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	result := a.executeProviderProfileTask(context.Background(), controlplane.ProviderProfileTask{ProfileID: "prv_123", ProfileRevision: 2, TaskFenceToken: 2, LeaseExpiresAt: time.Now().Add(time.Hour), Namespace: "4so-provider-system", ClusterClassName: "vsphere-standard", WorkerClassName: "worker-standard"})
	if !result.Success || result.ObservedVersion != "cluster.x-k8s.io/v1beta2" || !strings.HasPrefix(result.ObservedDigest, "sha256:") {
		t.Fatalf("result=%+v", result)
	}

	result = a.executeProviderProfileTask(context.Background(), controlplane.ProviderProfileTask{ProfileID: "prv_123", ProfileRevision: 3, TaskFenceToken: 3, LeaseExpiresAt: time.Now().Add(time.Hour), Namespace: "4so-provider-system", ClusterClassName: "vsphere-standard", WorkerClassName: "worker-missing"})
	if result.Success || !strings.Contains(result.Error, "not present") {
		t.Fatalf("missing class result=%+v", result)
	}
}

func TestProviderClusterApplyInspectDeleteAndOwnership(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	providerClusterID := "pcl_123"
	resourceName := "pf-customer-a-123456"
	digest := "sha256:" + strings.Repeat("f", 64)
	resource := map[string]any{
		"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster",
		"metadata": map[string]any{
			"name": resourceName, "namespace": "4so-provider-system",
			"labels":      map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/provider-cluster-id": providerClusterID},
			"annotations": map[string]any{"platform.4so.io/desired-digest": digest},
		},
		"spec": map[string]any{"topology": map[string]any{"classRef": map[string]any{"name": "vsphere-standard", "namespace": "4so-provider-system"}, "version": "v1.33.2"}},
	}
	objects := map[string]map[string]any{}
	deleteCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		switch request.Method {
		case http.MethodPost:
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			metadata, _ := object["metadata"].(map[string]any)
			name := fmt.Sprint(metadata["name"])
			objectPath := path + "/" + name
			if _, exists := objects[objectPath]; exists {
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			metadata["uid"] = "uid-provider-" + name
			metadata["resourceVersion"] = "1"
			object["status"] = map[string]any{"phase": "Provisioned", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}
			objects[objectPath] = object
			return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodPatch:
			if request.Header.Get("Content-Type") != "application/apply-patch+yaml" {
				t.Fatalf("content-type=%q", request.Header.Get("Content-Type"))
			}
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			metadata, _ := object["metadata"].(map[string]any)
			if existing, ok := objects[path]; ok {
				existingMeta, _ := existing["metadata"].(map[string]any)
				metadata["uid"] = existingMeta["uid"]
				metadata["resourceVersion"] = existingMeta["resourceVersion"]
			}
			metadata["resourceVersion"] = "2"
			object["status"] = map[string]any{"phase": "Provisioned", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}
			objects[path] = object
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodGet:
			object, ok := objects[path]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			raw, _ := json.Marshal(object)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
		case http.MethodDelete:
			deleteCalls++
			var options map[string]any
			if err := json.NewDecoder(request.Body).Decode(&options); err != nil {
				t.Fatal(err)
			}
			preconditions, _ := options["preconditions"].(map[string]any)
			current, ok := objects[path]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			currentMeta, _ := current["metadata"].(map[string]any)
			if preconditions["uid"] != currentMeta["uid"] || preconditions["resourceVersion"] != currentMeta["resourceVersion"] {
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"message":"identity precondition failed"}`)), Header: make(http.Header)}, nil
			}
			delete(objects, path)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected method %s", request.Method)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	apply := controlplane.ProviderClusterTask{ProviderClusterID: providerClusterID, ClusterRevision: 2, TaskFenceToken: 2, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "APPLY", Namespace: "4so-provider-system", ResourceName: resourceName, DesiredDigest: digest, Resource: resource}
	result := a.executeProviderClusterTask(context.Background(), apply)
	if !result.Success || result.ObservedDigest != digest || !result.Ready || result.Phase != "Provisioned" {
		t.Fatalf("apply result=%+v", result)
	}
	inspect := controlplane.ProviderClusterTask{ProviderClusterID: providerClusterID, ClusterRevision: 3, TaskFenceToken: 3, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "INSPECT", Namespace: "4so-provider-system", ResourceName: resourceName, DesiredDigest: digest}
	result = a.executeProviderClusterTask(context.Background(), inspect)
	if !result.Success || !result.Ready || result.ObservedDigest != digest {
		t.Fatalf("inspect result=%+v", result)
	}
	deleteTask := controlplane.ProviderClusterTask{ProviderClusterID: providerClusterID, ClusterRevision: 4, TaskFenceToken: 4, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "DELETE", Namespace: "4so-provider-system", ResourceName: resourceName, DesiredDigest: digest}
	result = a.executeProviderClusterTask(context.Background(), deleteTask)
	if !result.Success || !result.Deleted || deleteCalls != 1 {
		t.Fatalf("delete result=%+v calls=%d", result, deleteCalls)
	}

	objects[providerClusterPath(deleteTask)] = map[string]any{"metadata": map[string]any{"uid": "uid-provider-foreign", "resourceVersion": "9", "name": resourceName, "namespace": "4so-provider-system", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/provider-cluster-id": "other"}, "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}
	deleteCalls = 0
	result = a.executeProviderClusterTask(context.Background(), deleteTask)
	if result.Success || deleteCalls != 0 || !strings.Contains(result.Error, "not owned") {
		t.Fatalf("ownership result=%+v calls=%d", result, deleteCalls)
	}
}

func TestProviderClusterApplyRejectsConcurrentForeignOwner(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	providerClusterID := "pcl_race"
	resourceName := "pf-race-123456"
	digest := "sha256:" + strings.Repeat("a", 64)
	resource := map[string]any{
		"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster",
		"metadata": map[string]any{
			"name": resourceName, "namespace": "4so-provider-system",
			"labels":      map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/provider-cluster-id": providerClusterID},
			"annotations": map[string]any{"platform.4so.io/desired-digest": digest},
		},
	}
	task := controlplane.ProviderClusterTask{ProviderClusterID: providerClusterID, ClusterRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "APPLY", Namespace: "4so-provider-system", ResourceName: resourceName, DesiredDigest: digest, Resource: resource}
	getCount := 0
	patchCount := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodGet:
			getCount++
			if getCount == 1 {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			foreign := map[string]any{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "metadata": map[string]any{"uid": "uid-foreign", "name": resourceName, "namespace": "4so-provider-system", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/provider-cluster-id": "pcl_foreign"}, "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}
			raw, _ := json.Marshal(foreign)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
		case http.MethodPost:
			return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodPatch:
			patchCount++
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	result := a.executeProviderClusterTask(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "refusing to adopt concurrently created provider Cluster") {
		t.Fatalf("concurrent foreign Provider Cluster accepted: %+v", result)
	}
	if patchCount != 0 {
		t.Fatalf("foreign Provider Cluster was mutated after create conflict: patches=%d", patchCount)
	}
}

func TestTenantDeleteUIDPreconditionRejectsReplacement(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	tenantID := "ten_delete_race"
	namespace := "tenant-delete-race"
	nsPath := "/api/v1/namespaces/" + namespace
	legacyPath := "/apis/velero.io/v1/namespaces/velero/schedules/tenant-platform-backup"
	schedulePath := "/apis/velero.io/v1/namespaces/velero/schedules/" + controlplane.TenantBackupScheduleName(tenantID)
	owned := map[string]any{"metadata": map[string]any{"uid": "uid-old", "resourceVersion": "11", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}
	deleteCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodGet:
			switch request.URL.Path {
			case legacyPath, schedulePath:
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			case nsPath:
				raw, _ := json.Marshal(owned)
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
			default:
				t.Fatalf("unexpected GET %s", request.URL.Path)
				return nil, nil
			}
		case http.MethodDelete:
			deleteCalls++
			var options map[string]any
			if err := json.NewDecoder(request.Body).Decode(&options); err != nil {
				t.Fatal(err)
			}
			preconditions, _ := options["preconditions"].(map[string]any)
			if preconditions["uid"] != "uid-old" || preconditions["resourceVersion"] != "11" {
				t.Fatalf("delete did not carry the observed UID/resourceVersion preconditions: %#v", options)
			}
			// Simulate the original object disappearing and a different object taking
			// the same name before the DELETE reaches storage.
			owned = map[string]any{"metadata": map[string]any{"uid": "uid-foreign", "resourceVersion": "12", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": "ten_foreign"}}}
			return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"message":"UID precondition failed"}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	task := controlplane.TenantTask{TenantID: tenantID, TenantRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), Action: "DELETE", Namespace: namespace}
	result := a.executeTenantTask(context.Background(), task)
	if result.Success || deleteCalls != 1 || !strings.Contains(result.Error, "identity precondition conflict") {
		t.Fatalf("replacement race was not fenced: result=%+v deletes=%d", result, deleteCalls)
	}
	meta, _ := owned["metadata"].(map[string]any)
	if meta["uid"] != "uid-foreign" {
		t.Fatalf("replacement object was mutated: %#v", owned)
	}
}

func certificateCredentialForTest(t *testing.T, clusterID string, issuedAt time.Time, lifetime time.Duration) storedCredential {
	t.Helper()
	ca, caKey, err := agentpki.GenerateCA("agent-test-ca", issuedAt.Add(-time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpki.NewSigner(ca, caKey, func() time.Time { return issuedAt })
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent-cache-test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := signer.SignCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), clusterID, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return storedCredential{ClusterID: clusterID, CertificatePEM: string(issued.CertificatePEM), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), NotAfter: issued.NotAfter}
}

func TestCertificateOnlyFileCredentialLoadsAndExpiredCertificateIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	valid := certificateCredentialForTest(t, "cluster-cert-cache", time.Now().UTC().Add(-time.Minute), 24*time.Hour)
	raw, _ := json.Marshal(valid)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	a := &agent{cfg: config{TokenFile: path}, hub: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}}
	loaded, ok := a.readFileCredential()
	if !ok || loaded.Token != "" || loaded.ClusterID != valid.ClusterID {
		t.Fatalf("loaded=%+v ok=%v", loaded, ok)
	}
	if err := a.activateCertificate(loaded); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	if a.certificateNotAfter.IsZero() {
		t.Fatal("certificate expiry was not derived from X.509")
	}

	expired := certificateCredentialForTest(t, "cluster-expired", time.Now().UTC().Add(-48*time.Hour), time.Hour)
	if err := a.activateCertificate(expired); err == nil {
		t.Fatal("expired certificate was accepted")
	}
}

func TestStoredCertificateDefersToNewEnrollmentWhenAuthorityReportsRevoked(t *testing.T) {
	credential := certificateCredentialForTest(t, "cluster-revoked", time.Now().UTC().Add(-time.Minute), 24*time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/v1/clusters/cluster-revoked/certificates/current" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	a := &agent{cfg: config{Hub: server.URL, Enrollment: "new-enrollment-token"}, hub: server.Client()}
	accepted, err := a.acceptStoredCertificate(context.Background(), credential)
	if err != nil {
		t.Fatal(err)
	}
	if accepted {
		t.Fatal("revoked certificate suppressed explicit re-enrollment")
	}
	if a.clusterID != "" {
		t.Fatalf("clusterID=%q", a.clusterID)
	}
	transport := a.hub.Transport.(*http.Transport)
	if transport.TLSClientConfig != nil && len(transport.TLSClientConfig.Certificates) != 0 {
		t.Fatal("revoked client certificate remained installed during re-enrollment")
	}
}

func TestRuntimeCertificationAgentFreshInstallResumeAndFoundationVerify(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	component := components["secure-namespace-foundation"]
	rendered, err := catalog.RenderComponent(component, "4so-cert-agent", "catrel_agent")
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string]map[string]any{}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		switch request.Method {
		case http.MethodPost:
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			meta, _ := object["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			meta["uid"] = "uid-" + strings.ReplaceAll(name, "/", "-")
			meta["resourceVersion"] = "1"
			var objectPath string
			if path == "/api/v1/namespaces" {
				objectPath = path + "/" + name
			} else {
				objectPath = path + "/" + name
			}
			if _, exists := objects[objectPath]; exists {
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			objects[objectPath] = object
			return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodPatch:
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			meta, _ := object["metadata"].(map[string]any)
			current, exists := objects[path]
			if !exists {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			currentMeta, _ := current["metadata"].(map[string]any)
			if meta["resourceVersion"] != currentMeta["resourceVersion"] {
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			meta["uid"] = currentMeta["uid"]
			meta["resourceVersion"] = "2"
			objects[path] = object
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodGet:
			if path == "/api/v1/nodes" {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"items":[{"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`)), Header: make(http.Header)}, nil
			}
			if path == "/api/v1/namespaces/kube-system/services/kube-dns" {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"metadata":{"name":"kube-dns"}}`)), Header: make(http.Header)}, nil
			}
			object, ok := objects[path]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			raw, _ := json.Marshal(object)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected certification kube request %s %s", request.Method, path)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	task := controlplane.RuntimeCertificationTask{RunID: "rtc_agent", RunRevision: 2, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), Profile: controlplane.RuntimeCertificationFoundationV1, Phase: controlplane.RuntimeCertificationPhaseInstall, Namespace: "4so-cert-agent", InventoryDigest: digest("1"), EnvironmentFingerprint: digest("2"), CatalogReleaseID: "catrel_agent", ManifestDigest: digest("3"), SourceLockDigest: digest("4"), RenderedDigest: digest("5"), TaskAttempt: 1, CleanupToken: "cleanup-test", Resources: rendered.Resources}
	install := a.runRuntimeCertification(context.Background(), task)
	if !install.Success || install.Blocked {
		t.Fatalf("install=%+v", install)
	}
	runContract := controlplane.RuntimeCertificationRun{ResourceCount: len(rendered.Resources), Profile: task.Profile, Phase: controlplane.RuntimeCertificationPhaseInstall}
	if err := controlplane.ValidateRuntimeCertificationResultShape(runContract, install); err != nil {
		t.Fatalf("real agent INSTALL result rejected by control-plane contract: %v checks=%+v", err, install.Checks)
	}
	if len(objects) != 6 {
		t.Fatalf("expected six applied objects, got %d", len(objects))
	}
	task.Phase = controlplane.RuntimeCertificationPhaseVerify
	task.RunRevision = 3
	task.TaskAttempt = 2
	task.InstallCheckpointDigest = digest("6")
	verify := a.runRuntimeCertification(context.Background(), task)
	if !verify.Success || verify.Blocked {
		t.Fatalf("verify=%+v", verify)
	}
	for _, c := range verify.Checks {
		if c.Status != "PASS" {
			t.Fatalf("foundation emitted non-pass check: %+v", c)
		}
	}
	// Keep identity metadata intact but drift one rendered managed field. VERIFY must
	// not certify mere existence/name when desired state no longer matches.
	for path, object := range objects {
		if strings.Contains(path, "/configmaps/") {
			data, _ := object["data"].(map[string]any)
			for key := range data {
				data[key] = "drifted"
				break
			}
			break
		}
	}
	driftVerify := a.runRuntimeCertification(context.Background(), task)
	if driftVerify.Success {
		t.Fatalf("foundation VERIFY certified drifted managed fields: %+v", driftVerify)
	}
	driftCaught := false
	for _, c := range driftVerify.Checks {
		if strings.HasPrefix(c.Key, "verify/ConfigMap/") && c.Status == "FAIL" {
			driftCaught = true
		}
	}
	if !driftCaught {
		t.Fatalf("foundation VERIFY did not expose drifted ConfigMap evidence: %+v", driftVerify.Checks)
	}
	// Restore rendered state before exercising the broader TARGET profile path.
	for _, resource := range rendered.Resources {
		if fmt.Sprint(resource["kind"]) == "ConfigMap" {
			path, _, _ := certificationResourcePath(task, resource)
			currentMeta, _ := objects[path]["metadata"].(map[string]any)
			restored := map[string]any{}
			raw, _ := json.Marshal(resource)
			_ = json.Unmarshal(raw, &restored)
			restoredMeta, _ := restored["metadata"].(map[string]any)
			restoredMeta["uid"] = currentMeta["uid"]
			restoredMeta["resourceVersion"] = currentMeta["resourceVersion"]
			objects[path] = restored
		}
	}

	task.Profile = controlplane.RuntimeCertificationTargetV1
	target := a.runRuntimeCertification(context.Background(), task)
	if target.Success || !target.Blocked {
		t.Fatalf("target must block without executable adapters: %+v", target)
	}
	blocked := map[string]bool{}
	for _, c := range target.Checks {
		if c.Status == "BLOCKED" {
			blocked[c.Key] = true
		}
	}
	for _, key := range []string{"target-runtime/pvc-bind", "target-runtime/pvc-io", "target-runtime/snapshot-create", "target-runtime/snapshot-restore-pvc", "target-runtime/snapshot-restore-io", "target-runtime/backup-create", "target-runtime/restore-validate"} {
		if !blocked[key] {
			t.Fatalf("target must expose blocked storage evidence %s: %+v", key, target)
		}
	}
}

func TestRuntimeCertificationAgentRejectsExistingUnownedNamespace(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := catalog.RenderComponent(components["secure-namespace-foundation"], "4so-cert-owned", "catrel_expected")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.Path == "/api/v1/namespaces/4so-cert-owned" {
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"metadata":{"name":"4so-cert-owned","labels":{"platform.4so.io/catalog-release-id":"catrel_other"}}}`)), Header: make(http.Header)}, nil
		}
		t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		return nil, nil
	})}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	task := controlplane.RuntimeCertificationTask{RunID: "rtc_owned", RunRevision: 2, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), Profile: controlplane.RuntimeCertificationFoundationV1, Phase: controlplane.RuntimeCertificationPhaseInstall, Namespace: "4so-cert-owned", InventoryDigest: digest("a"), EnvironmentFingerprint: digest("b"), CatalogReleaseID: "catrel_expected", ManifestDigest: digest("c"), SourceLockDigest: digest("d"), RenderedDigest: digest("e"), TaskAttempt: 1, CleanupToken: "cleanup-test", Resources: rendered.Resources}
	result := (&agent{kube: client}).runRuntimeCertification(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "already exists") {
		t.Fatalf("unowned namespace accepted: %+v", result)
	}
}

func TestDiscoverAPISurfaceAndPlanImpactFromLiveInventory(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		body := "{}"
		code := http.StatusOK
		switch {
		case request.Method == http.MethodGet && path == "/api/v1":
			body = `{"groupVersion":"v1","resources":[{"name":"resourcequotas","namespaced":true,"kind":"ResourceQuota","verbs":["get","list","patch","delete"]},{"name":"limitranges","namespaced":true,"kind":"LimitRange","verbs":["get","patch","delete"]},{"name":"serviceaccounts","namespaced":true,"kind":"ServiceAccount","verbs":["get","patch","delete"]},{"name":"configmaps","namespaced":true,"kind":"ConfigMap","verbs":["get","patch","delete"]}]}`
		case request.Method == http.MethodGet && path == "/apis":
			body = `{"groups":[{"name":"networking.k8s.io","versions":[{"groupVersion":"networking.k8s.io/v1","version":"v1"}]},{"name":"apiextensions.k8s.io","versions":[{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}]}]}`
		case request.Method == http.MethodGet && path == "/apis/networking.k8s.io/v1":
			body = `{"groupVersion":"networking.k8s.io/v1","resources":[{"name":"networkpolicies","namespaced":true,"kind":"NetworkPolicy","verbs":["get","list","patch","delete"]}]}`
		case request.Method == http.MethodGet && path == "/apis/apiextensions.k8s.io/v1":
			body = `{"groupVersion":"apiextensions.k8s.io/v1","resources":[{"name":"customresourcedefinitions","namespaced":false,"kind":"CustomResourceDefinition","verbs":["get","list"]}]}`
		case request.Method == http.MethodGet && path == "/apis/apiextensions.k8s.io/v1/customresourcedefinitions":
			body = `{"items":[{"metadata":{"name":"widgets.widgets.example.io"},"spec":{"group":"widgets.example.io","scope":"Namespaced","names":{"kind":"Widget","plural":"widgets"},"versions":[{"name":"v1","served":true,"storage":true}]}}]}`
		case request.Method == http.MethodPost && path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			body = `{"status":{"allowed":true}}`
		case request.Method == http.MethodPatch && strings.Contains(request.URL.RawQuery, "dryRun=All"):
			if request.URL.Query().Get("fieldValidation") != "Strict" || request.Header.Get("Content-Type") != "application/apply-patch+yaml" {
				t.Fatalf("dry-run contract query=%s content-type=%s", request.URL.RawQuery, request.Header.Get("Content-Type"))
			}
			body = `{"metadata":{"name":"dry-run"}}`
		case request.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/namespaces/4so-platform-baseline/"):
			code = http.StatusNotFound
		case request.Method == http.MethodGet && path == "/apis/networking.k8s.io/v1/namespaces/4so-platform-baseline/networkpolicies/4so-default-deny-ingress":
			code = http.StatusNotFound
		default:
			code = http.StatusNotFound
		}
		return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	apiResources, crds, apiComplete, crdComplete := a.discoverAPISurface(context.Background())
	if !apiComplete || !crdComplete || len(apiResources) < 6 || len(crds) != 1 {
		t.Fatalf("discovery api=%d crd=%d complete=%v/%v", len(apiResources), len(crds), apiComplete, crdComplete)
	}
	inv := controlplane.ClusterInventory{Distribution: "rke2", KubernetesVersion: "v1.34.1", Nodes: []controlplane.ClusterNode{{Name: "node-a", Architecture: "amd64", Ready: true}}, APIResources: apiResources, CRDs: crds, APIDiscoveryComplete: apiComplete, CRDDiscoveryComplete: crdComplete, SchemaDiscoveryVersion: "OPENAPI_V3", SchemaDiscoveryDigest: "sha256:" + strings.Repeat("7", 64), SchemaDiscoveryComplete: true, Capacity: controlplane.ClusterCapacity{CPUAllocatableMilli: 4000, MemoryAllocatableBytes: 8 << 30, PodsAllocatable: 110}, Networking: controlplane.ClusterNetworking{CNI: "cilium"}, Capabilities: []string{"read-only-inventory", "controlled-baseline-deployment", "cni-inventory", "runtime-probe-image-digest-pinned"}}
	inv.Digest = controlplane.ClusterInventoryDigest(inv)
	digest := "sha256:" + strings.Repeat("a", 64)
	task := controlplane.BaselineTask{DeploymentID: "bld-impact", Action: "PLAN", BaselineID: baseline.SecureNamespaceID, BaselineVersion: baseline.SecureNamespaceVersion, TargetNamespace: baseline.ManagedNamespace, DesiredDigest: digest, Inventory: inv, Resources: baseline.Resources("bld-impact", digest)}
	result := a.planBaseline(context.Background(), task)
	if !result.Success || !result.Impact.ApprovalReady || result.Impact.Digest == "" || result.Impact.InventoryDigest != inv.Digest {
		t.Fatalf("result=%+v", result)
	}
	if result.Impact.Disruption.Level != "MEDIUM" || result.Impact.Disruption.MaintenanceRecommendation != "RECOMMENDED" {
		t.Fatalf("disruption=%+v", result.Impact.Disruption)
	}
	if result.Impact.Evidence.Status != "PASS" || result.Impact.Evidence.Method != controlplane.PlanEvidenceCollectionMethod || result.Impact.Evidence.RequiredCount != 6 || len(result.Impact.Evidence.Artifacts) != 6 {
		t.Fatalf("evidence plan=%+v", result.Impact.Evidence)
	}
	for _, item := range result.Impact.Evidence.Artifacts {
		if !item.Required || item.RetentionDays != controlplane.PlanEvidenceRetentionDays || !strings.HasPrefix(item.OutputLocation, "/api/v1/baseline-deployments/bld-impact/evidence/") {
			t.Fatalf("invalid planned evidence=%+v", item)
		}
	}
}

func TestSchemaAuthorityDiscoveryPrefersV3AndFallsBackV2(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	v3Body := `{"paths":{"api/v1":{"serverRelativeURL":"/openapi/v3/api/v1?hash=abc"}}}`
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/openapi/v3" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected schema request %s %s accept=%s", request.Method, request.URL.Path, request.Header.Get("Accept"))
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(v3Body)), Header: make(http.Header)}, nil
	})}
	version, digest, complete := (&agent{kube: client}).discoverSchemaAuthority(context.Background())
	expected := sha256.Sum256([]byte(v3Body))
	if !complete || version != "OPENAPI_V3" || digest != "sha256:"+hex.EncodeToString(expected[:]) {
		t.Fatalf("schema authority=%s %s complete=%v", version, digest, complete)
	}

	v2Body := `{"swagger":"2.0","definitions":{}}`
	client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/openapi/v3":
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader("not found")), Header: make(http.Header)}, nil
		case "/openapi/v2":
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(v2Body)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected fallback path %s", request.URL.Path)
			return nil, nil
		}
	})}
	version, digest, complete = (&agent{kube: client}).discoverSchemaAuthority(context.Background())
	expected = sha256.Sum256([]byte(v2Body))
	if !complete || version != "OPENAPI_V2" || digest != "sha256:"+hex.EncodeToString(expected[:]) {
		t.Fatalf("fallback schema authority=%s %s complete=%v", version, digest, complete)
	}
}

func TestStrictSchemaDryRunCapturesWarningsAndFailureWithoutMutation(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	digest := "sha256:" + strings.Repeat("6", 64)
	task := controlplane.BaselineTask{Inventory: controlplane.ClusterInventory{SchemaDiscoveryVersion: "OPENAPI_V3", SchemaDiscoveryDigest: digest, SchemaDiscoveryComplete: true, APIResources: []controlplane.ClusterAPIResourceObservation{{APIVersion: "v1", Version: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespaced: true, Verbs: []string{"get", "patch"}}}}}
	resource := controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "ConfigMap", Namespace: baseline.ManagedNamespace, Name: "4so-baseline-revision", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "4so-baseline-revision", "namespace": baseline.ManagedNamespace}}}
	mutations := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPatch || request.URL.Query().Get("dryRun") != "All" || request.URL.Query().Get("fieldValidation") != "Strict" || request.URL.Query().Get("fieldManager") != "4so-platform-agent-plan" {
			t.Fatalf("not a strict dry-run request: %s %s", request.Method, request.URL.String())
		}
		if request.URL.Query().Get("dryRun") != "All" {
			mutations++
		}
		header := make(http.Header)
		header.Add("Warning", `299 kube-apiserver "example deprecation warning"`)
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"kind":"ConfigMap"}`)), Header: header}, nil
	})}
	evidence := (&agent{kube: client}).schemaDryRunCompatibility(context.Background(), task, resource)
	if evidence.Status != "PASS" || evidence.Method != controlplane.PlanSchemaValidationMethod || evidence.HTTPStatus != 200 || evidence.SchemaIndexDigest != digest || len(evidence.Warnings) != 1 || mutations != 0 {
		t.Fatalf("dry-run evidence=%+v mutations=%d", evidence, mutations)
	}

	client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnprocessableEntity, Status: "422 Unprocessable Entity", Body: io.NopCloser(strings.NewReader(`{"message":"unknown field spec.invalid"}`)), Header: make(http.Header)}, nil
	})}
	evidence = (&agent{kube: client}).schemaDryRunCompatibility(context.Background(), task, resource)
	if evidence.Status != "FAIL" || evidence.HTTPStatus != 422 || !strings.HasPrefix(evidence.FailureDigest, "sha256:") {
		t.Fatalf("failed dry-run evidence=%+v", evidence)
	}
}

func TestRollbackFeasibilityProvesDeleteAndRestorePreimage(t *testing.T) {
	useRollbackTestToken(t)
	digest := "sha256:" + strings.Repeat("d", 64)
	inv := controlplane.ClusterInventory{SchemaDiscoveryVersion: "OPENAPI_V3", SchemaDiscoveryDigest: digest, SchemaDiscoveryComplete: true, APIResources: []controlplane.ClusterAPIResourceObservation{
		{APIVersion: "v1", Version: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespaced: true, Verbs: []string{"get", "patch", "delete"}},
	}}
	task := controlplane.BaselineTask{Inventory: inv}
	resource := controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "ConfigMap", Namespace: baseline.ManagedNamespace, Name: "4so-baseline-revision"}
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"status":{"allowed":true}}`)), Header: make(http.Header)}, nil
		}
		if r.Method == http.MethodPut && r.URL.Query().Get("dryRun") == "All" && r.URL.Query().Get("fieldValidation") == "Strict" {
			raw, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(raw), `"resourceVersion":"99"`) || !strings.Contains(string(raw), `"uid":"x"`) || strings.Contains(string(raw), `"status"`) {
				t.Fatalf("restore dry-run was not UID/resourceVersion fenced: %s", raw)
			}
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"kind":"ConfigMap"}`)), Header: make(http.Header)}, nil
		}
		t.Fatalf("unexpected rollback feasibility request %s %s", r.Method, r.URL.String())
		return nil, nil
	})}
	a := &agent{kube: client}
	add := a.rollbackFeasibility(context.Background(), task, resource, controlplane.BaselinePlanChange{Resource: "ConfigMap/4so-baseline-revision", Action: "ADD"}, nil)
	if add.Status != "PASS" || add.Strategy != "DELETE_CREATED_RESOURCE" || add.AuthorizationStatus != "PASS" {
		t.Fatalf("add rollback=%+v", add)
	}
	current := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": resource.Name, "namespace": resource.Namespace, "resourceVersion": "99", "uid": "x"}, "data": map[string]any{"before": "true"}, "status": map[string]any{"ignored": true}}
	update := a.rollbackFeasibility(context.Background(), task, resource, controlplane.BaselinePlanChange{Resource: "ConfigMap/4so-baseline-revision", Action: "UPDATE"}, current)
	if update.Status != "PASS" || update.Strategy != "RESTORE_PREIMAGE" || update.DryRunStatus != "PASS" || update.RestoreObjectDigest == "" || update.ObservedUID != "x" || update.ObservedObjectDigest != update.RestoreObjectDigest {
		t.Fatalf("update rollback=%+v", update)
	}
	if requests != 2 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestRollbackFeasibilityBlocksDeniedDeleteAndSecretPreimage(t *testing.T) {
	useRollbackTestToken(t)
	digest := "sha256:" + strings.Repeat("e", 64)
	inv := controlplane.ClusterInventory{SchemaDiscoveryVersion: "OPENAPI_V3", SchemaDiscoveryDigest: digest, SchemaDiscoveryComplete: true, APIResources: []controlplane.ClusterAPIResourceObservation{{APIVersion: "v1", Version: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespaced: true, Verbs: []string{"patch", "delete"}}}}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"status":{"allowed":false,"reason":"policy denied"}}`)), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	task := controlplane.BaselineTask{Inventory: inv}
	cm := controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "x"}
	denied := a.rollbackFeasibility(context.Background(), task, cm, controlplane.BaselinePlanChange{Resource: "ConfigMap/x", Action: "ADD"}, nil)
	if denied.Status != "FAIL" || denied.FailureDigest == "" {
		t.Fatalf("denied=%+v", denied)
	}
	secret := controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "Secret", Namespace: "ns", Name: "s"}
	sensitive := a.rollbackFeasibility(context.Background(), task, secret, controlplane.BaselinePlanChange{Resource: "Secret/s", Action: "UPDATE"}, map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "s", "namespace": "ns"}, "data": map[string]any{"token": "abc"}})
	if sensitive.Status != "FAIL" || sensitive.RestoreObject != nil || sensitive.FailureDigest == "" {
		t.Fatalf("sensitive=%+v", sensitive)
	}
}

func TestRollbackBaselineExecutesBoundStrategiesAndRejectsTamper(t *testing.T) {
	useRollbackTestToken(t)
	restore := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "4so-baseline-revision", "namespace": baseline.ManagedNamespace}, "data": map[string]any{"before": "true"}}
	calls := []string{}
	deleteObservations := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		status := http.StatusOK
		body := `{}`
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/serviceaccounts/4so-baseline-observer"):
			deleteObservations++
			if deleteObservations >= 2 {
				status = http.StatusNotFound
			} else {
				body = `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"4so-baseline-observer","namespace":"4so-platform-baseline","uid":"uid-baseline-observer","resourceVersion":"101","annotations":{"platform.4so.io/managed":"true","platform.4so.io/deployment-id":"bdep-1","platform.4so.io/desired-digest":"sha256:` + strings.Repeat("d", 64) + `"},"labels":{"app.kubernetes.io/managed-by":"4so-platform-factory"}}}`
			}
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configmaps/4so-baseline-revision"):
			body = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"4so-baseline-revision","namespace":"` + baseline.ManagedNamespace + `","uid":"uid-config","resourceVersion":"200","annotations":{"platform.4so.io/managed":"true","platform.4so.io/deployment-id":"bdep-1","platform.4so.io/desired-digest":"sha256:` + strings.Repeat("d", 64) + `"},"labels":{"app.kubernetes.io/managed-by":"4so-platform-factory"}},"data":{"after":"true"}}`
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/configmaps/4so-baseline-revision"):
			raw, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(raw), `"uid":"uid-config"`) || !strings.Contains(string(raw), `"resourceVersion":"200"`) || !strings.Contains(string(raw), `"before":"true"`) {
				t.Fatalf("restore update was not fenced or did not carry preimage: %s", raw)
			}
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	desiredDigest := "sha256:" + strings.Repeat("d", 64)
	desiredMeta := func(name string) map[string]any {
		return map[string]any{"name": name, "namespace": baseline.ManagedNamespace, "annotations": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/deployment-id": "bdep-1", "platform.4so.io/desired-digest": desiredDigest}, "labels": map[string]any{"app.kubernetes.io/managed-by": "4so-platform-factory"}}
	}
	task := controlplane.BaselineTask{DeploymentID: "bdep-1", DesiredDigest: desiredDigest, Resources: []controlplane.BaselineTaskResource{
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: baseline.ManagedNamespace, Name: "4so-baseline-revision", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": desiredMeta("4so-baseline-revision"), "data": map[string]any{"after": "true"}}},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: baseline.ManagedNamespace, Name: "4so-baseline-observer", Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": desiredMeta("4so-baseline-observer")}},
	}, Rollback: []controlplane.PlanRollbackResource{
		{Resource: "ConfigMap/4so-baseline-revision", Strategy: "RESTORE_PREIMAGE", Status: "PASS", ObservedUID: "uid-config", ObservedObjectDigest: rollbackObjectDigest(restore), RestoreObject: restore, RestoreObjectDigest: rollbackObjectDigest(restore)},
		{Resource: "ServiceAccount/4so-baseline-observer", Strategy: "DELETE_CREATED_RESOURCE", Status: "PASS"},
	}}
	result := a.rollbackBaseline(context.Background(), task)
	if !result.Success || deleteObservations < 2 || len(calls) != 5 {
		t.Fatalf("result=%+v deleteObservations=%d calls=%v", result, deleteObservations, calls)
	}
	if !strings.HasPrefix(calls[len(calls)-1], http.MethodPut+" ") {
		t.Fatalf("rollback restored preimage before delete completion was observed: calls=%v", calls)
	}
	task.Rollback[0].RestoreObjectDigest = "sha256:" + strings.Repeat("0", 64)
	result = a.rollbackBaseline(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "integrity") {
		t.Fatalf("tampered rollback accepted: %+v", result)
	}
}

func TestRollbackBaselineRestoreRejectsUIDReplacementAndResourceVersionRace(t *testing.T) {
	useRollbackTestToken(t)
	path := baselineResourcePaths["ConfigMap/4so-baseline-revision"]
	restore := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "4so-baseline-revision", "namespace": baseline.ManagedNamespace}, "data": map[string]any{"before": "true"}}
	owned := func(uid, rv string) string {
		return `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"4so-baseline-revision","namespace":"` + baseline.ManagedNamespace + `","uid":"` + uid + `","resourceVersion":"` + rv + `","annotations":{"platform.4so.io/managed":"true","platform.4so.io/deployment-id":"bdep-restore","platform.4so.io/desired-digest":"sha256:` + strings.Repeat("c", 64) + `"},"labels":{"app.kubernetes.io/managed-by":"4so-platform-factory"}},"data":{"after":"true"}}`
	}
	t.Run("uid replacement", func(t *testing.T) {
		puts := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPut {
				puts++
			}
			if r.Method != http.MethodGet || r.URL.Path != path {
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(owned("uid-replacement", "9"))), Header: make(http.Header)}, nil
		})}
		task := controlplane.BaselineTask{DeploymentID: "bdep-restore", DesiredDigest: "sha256:" + strings.Repeat("c", 64), Resources: []controlplane.BaselineTaskResource{{APIVersion: "v1", Kind: "ConfigMap", Namespace: baseline.ManagedNamespace, Name: "4so-baseline-revision", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "4so-baseline-revision", "namespace": baseline.ManagedNamespace, "annotations": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/deployment-id": "bdep-restore", "platform.4so.io/desired-digest": "sha256:" + strings.Repeat("c", 64)}, "labels": map[string]any{"app.kubernetes.io/managed-by": "4so-platform-factory"}}, "data": map[string]any{"after": "true"}}}}, Rollback: []controlplane.PlanRollbackResource{{Resource: "ConfigMap/4so-baseline-revision", Strategy: "RESTORE_PREIMAGE", Status: "PASS", ObservedUID: "uid-original", ObservedObjectDigest: rollbackObjectDigest(restore), RestoreObject: restore, RestoreObjectDigest: rollbackObjectDigest(restore)}}}
		result := (&agent{kube: client}).rollbackBaseline(context.Background(), task)
		if result.Success || puts != 0 || !strings.Contains(result.Error, "identity changed") {
			t.Fatalf("result=%+v puts=%d", result, puts)
		}
	})
	t.Run("owned state drift before rollback", func(t *testing.T) {
		puts := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPut {
				puts++
			}
			if r.Method != http.MethodGet || r.URL.Path != path {
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			body := strings.Replace(owned("uid-original", "10"), `"data":{"after":"true"}`, `"data":{"external":"drift"}`, 1)
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		task := controlplane.BaselineTask{DeploymentID: "bdep-restore", DesiredDigest: "sha256:" + strings.Repeat("c", 64), Resources: []controlplane.BaselineTaskResource{{APIVersion: "v1", Kind: "ConfigMap", Namespace: baseline.ManagedNamespace, Name: "4so-baseline-revision", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "4so-baseline-revision", "namespace": baseline.ManagedNamespace, "annotations": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/deployment-id": "bdep-restore", "platform.4so.io/desired-digest": "sha256:" + strings.Repeat("c", 64)}, "labels": map[string]any{"app.kubernetes.io/managed-by": "4so-platform-factory"}}, "data": map[string]any{"after": "true"}}}}, Rollback: []controlplane.PlanRollbackResource{{Resource: "ConfigMap/4so-baseline-revision", Strategy: "RESTORE_PREIMAGE", Status: "PASS", ObservedUID: "uid-original", ObservedObjectDigest: rollbackObjectDigest(restore), RestoreObject: restore, RestoreObjectDigest: rollbackObjectDigest(restore)}}}
		result := (&agent{kube: client}).rollbackBaseline(context.Background(), task)
		if result.Success || puts != 0 || !strings.Contains(result.Error, "approved applied state changed") {
			t.Fatalf("result=%+v puts=%d", result, puts)
		}
	})

	t.Run("resource version race", func(t *testing.T) {
		puts := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case http.MethodGet:
				return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(owned("uid-original", "10"))), Header: make(http.Header)}, nil
			case http.MethodPut:
				puts++
				var object map[string]any
				if err := json.NewDecoder(r.Body).Decode(&object); err != nil {
					t.Fatal(err)
				}
				meta, _ := object["metadata"].(map[string]any)
				if meta["uid"] != "uid-original" || meta["resourceVersion"] != "10" {
					t.Fatalf("restore fence=%v", meta)
				}
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"Conflict"}`)), Header: make(http.Header)}, nil
			default:
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				return nil, nil
			}
		})}
		task := controlplane.BaselineTask{DeploymentID: "bdep-restore", DesiredDigest: "sha256:" + strings.Repeat("c", 64), Resources: []controlplane.BaselineTaskResource{{APIVersion: "v1", Kind: "ConfigMap", Namespace: baseline.ManagedNamespace, Name: "4so-baseline-revision", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "4so-baseline-revision", "namespace": baseline.ManagedNamespace, "annotations": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/deployment-id": "bdep-restore", "platform.4so.io/desired-digest": "sha256:" + strings.Repeat("c", 64)}, "labels": map[string]any{"app.kubernetes.io/managed-by": "4so-platform-factory"}}, "data": map[string]any{"after": "true"}}}}, Rollback: []controlplane.PlanRollbackResource{{Resource: "ConfigMap/4so-baseline-revision", Strategy: "RESTORE_PREIMAGE", Status: "PASS", ObservedUID: "uid-original", ObservedObjectDigest: rollbackObjectDigest(restore), RestoreObject: restore, RestoreObjectDigest: rollbackObjectDigest(restore)}}}
		result := (&agent{kube: client}).rollbackBaseline(context.Background(), task)
		if result.Success || puts != 1 || !strings.Contains(result.Error, "UID/resourceVersion conflict") {
			t.Fatalf("result=%+v puts=%d", result, puts)
		}
	})
}

func useRollbackTestToken(t *testing.T) {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	t.Cleanup(func() { serviceAccountTokenPath = previous })
}

func TestClusterMaintenancePDBAwareDrainAndUncordon(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousToken := serviceAccountTokenPath
	previousPoll := maintenancePollInterval
	serviceAccountTokenPath = tokenFile
	maintenancePollInterval = 2 * time.Millisecond
	defer func() { serviceAccountTokenPath = previousToken; maintenancePollInterval = previousPoll }()

	unschedulable := false
	appPresent := true
	evictionAttempts := 0
	patches := []bool{}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		status := http.StatusOK
		body := `{}`
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/nodes/worker-1":
			body = fmt.Sprintf(`{"metadata":{"name":"worker-1","uid":"node-uid-1"},"spec":{"unschedulable":%t}}`, unschedulable)
		case request.Method == http.MethodPatch && request.URL.Path == "/api/v1/nodes/worker-1":
			if request.Header.Get("Content-Type") != "application/json-patch+json" {
				t.Fatalf("content-type=%q", request.Header.Get("Content-Type"))
			}
			var payload []map[string]any
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if len(payload) != 2 || payload[0]["op"] != "test" || payload[0]["value"] != "node-uid-1" {
				t.Fatalf("fence patch=%v", payload)
			}
			unschedulable, _ = payload[1]["value"].(bool)
			patches = append(patches, unschedulable)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/pods":
			if request.URL.Query().Get("fieldSelector") != "spec.nodeName=worker-1" {
				t.Fatalf("field selector=%q", request.URL.Query().Get("fieldSelector"))
			}
			items := []string{`{"metadata":{"name":"daemon","namespace":"kube-system","uid":"uid-daemon","resourceVersion":"7","annotations":{},"ownerReferences":[{"kind":"DaemonSet","controller":true}]}}`}
			if appPresent {
				items = append(items, `{"metadata":{"name":"web-1","namespace":"app","uid":"uid-web-1","resourceVersion":"11","annotations":{},"ownerReferences":[{"kind":"ReplicaSet","controller":true}]},"spec":{"volumes":[]}}`)
			}
			body = `{"items":[` + strings.Join(items, ",") + `]}`
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/namespaces/app/pods/web-1/eviction":
			var eviction map[string]any
			if err := json.NewDecoder(request.Body).Decode(&eviction); err != nil {
				t.Fatal(err)
			}
			deleteOptions, _ := eviction["deleteOptions"].(map[string]any)
			preconditions, _ := deleteOptions["preconditions"].(map[string]any)
			if preconditions["uid"] != "uid-web-1" || preconditions["resourceVersion"] != "11" {
				t.Fatalf("eviction preconditions=%v", preconditions)
			}
			evictionAttempts++
			if evictionAttempts == 1 {
				status = http.StatusTooManyRequests
				body = `{"message":"cannot evict pod as it would violate the pod's disruption budget"}`
			} else {
				status = http.StatusCreated
				appPresent = false
			}
		default:
			t.Fatalf("unexpected kube request %s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d", status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}

	a := &agent{kube: client}
	result := a.executeClusterMaintenanceTask(context.Background(), controlplane.ClusterMaintenanceTask{RunID: "cmr-1", RunRevision: 2, OperationID: "op-1", OperationRevision: 4, OperationFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), ClusterID: "cluster-1", NodeNames: []string{"worker-1"}, NodeUIDs: map[string]string{"worker-1": "node-uid-1"}, InventoryDigest: "sha256:" + strings.Repeat("a", 64), DrainTimeoutSeconds: 30, Method: controlplane.ClusterMaintenanceAuthorityMethod})
	if result.OperationFenceToken != 1 {
		t.Fatalf("maintenance result fence=%d", result.OperationFenceToken)
	}
	if !result.Success || result.Error != "" || len(result.Results) != 1 {
		t.Fatalf("result=%+v", result)
	}
	node := result.Results[0]
	if !node.Cordoned || !node.DrainAttempted || !node.Drained || !node.Uncordoned {
		t.Fatalf("node result=%+v", node)
	}
	if evictionAttempts != 2 || len(patches) != 2 || !patches[0] || patches[1] || unschedulable {
		t.Fatalf("evictions=%d patches=%v finalUnschedulable=%v", evictionAttempts, patches, unschedulable)
	}
	if len(node.EvictedPods) != 1 || node.EvictedPods[0] != "app/web-1" || len(node.PDBBlockedPods) != 1 || node.PDBBlockedPods[0] != "app/web-1" || len(node.SkippedPods) != 1 || node.SkippedPods[0] != "kube-system/daemon" {
		t.Fatalf("pod evidence=%+v", node)
	}
}

func TestClusterMaintenanceRejectsUnmanagedAndEmptyDirPodsBeforeEviction(t *testing.T) {
	tests := []struct {
		name string
		pod  string
		want string
	}{
		{name: "unmanaged", pod: `{"metadata":{"name":"standalone","namespace":"app","uid":"uid-standalone","resourceVersion":"4","annotations":{},"ownerReferences":[]},"spec":{"volumes":[]}}`, want: "no controller owner"},
		{name: "emptydir", pod: `{"metadata":{"name":"cache","namespace":"app","uid":"uid-cache","resourceVersion":"5","annotations":{},"ownerReferences":[{"kind":"ReplicaSet","controller":true}]},"spec":{"volumes":[{"name":"scratch","emptyDir":{}}]}}`, want: "emptyDir"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenFile := filepath.Join(t.TempDir(), "service-account-token")
			if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
				t.Fatal(err)
			}
			previousToken := serviceAccountTokenPath
			serviceAccountTokenPath = tokenFile
			defer func() { serviceAccountTokenPath = previousToken }()
			unschedulable := false
			evictions := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				status := http.StatusOK
				body := `{}`
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/api/v1/nodes/worker-1":
					body = fmt.Sprintf(`{"metadata":{"name":"worker-1","uid":"node-uid-1"},"spec":{"unschedulable":%t}}`, unschedulable)
				case request.Method == http.MethodPatch && request.URL.Path == "/api/v1/nodes/worker-1":
					var payload []map[string]any
					if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					unschedulable, _ = payload[1]["value"].(bool)
				case request.Method == http.MethodGet && request.URL.Path == "/api/v1/pods":
					body = `{"items":[` + tc.pod + `]}`
				case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/eviction"):
					evictions++
				default:
					t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
				}
				return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d", status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			result := (&agent{kube: client}).executeClusterMaintenanceTask(context.Background(), controlplane.ClusterMaintenanceTask{RunID: "cmr-safe", RunRevision: 1, OperationID: "op-safe", OperationRevision: 1, OperationFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), ClusterID: "cluster-1", NodeNames: []string{"worker-1"}, NodeUIDs: map[string]string{"worker-1": "node-uid-1"}, InventoryDigest: "sha256:" + strings.Repeat("a", 64), DrainTimeoutSeconds: 30, Method: controlplane.ClusterMaintenanceAuthorityMethod})
			if result.Success || !strings.Contains(result.Error, tc.want) || evictions != 0 || unschedulable {
				t.Fatalf("result=%+v evictions=%d unschedulable=%v", result, evictions, unschedulable)
			}
		})
	}
}

func TestClusterMaintenancePreflightsAllPodsBeforeFirstEviction(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousToken := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousToken }()
	unschedulable := false
	evictions := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{}`
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/nodes/worker-1":
			body = fmt.Sprintf(`{"metadata":{"name":"worker-1","uid":"node-uid-1"},"spec":{"unschedulable":%t}}`, unschedulable)
		case request.Method == http.MethodPatch && request.URL.Path == "/api/v1/nodes/worker-1":
			var payload []map[string]any
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			unschedulable, _ = payload[1]["value"].(bool)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/pods":
			body = `{"items":[` +
				`{"metadata":{"name":"safe","namespace":"app","uid":"uid-safe","resourceVersion":"1","annotations":{},"ownerReferences":[{"kind":"ReplicaSet","controller":true}]},"spec":{"volumes":[]}},` +
				`{"metadata":{"name":"standalone","namespace":"app","uid":"uid-standalone","resourceVersion":"2","annotations":{},"ownerReferences":[]},"spec":{"volumes":[]}}]}`
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/eviction"):
			evictions++
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	result := (&agent{kube: client}).executeClusterMaintenanceTask(context.Background(), controlplane.ClusterMaintenanceTask{RunID: "cmr-preflight", RunRevision: 1, OperationID: "op-preflight", OperationRevision: 1, OperationFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), ClusterID: "cluster-1", NodeNames: []string{"worker-1"}, NodeUIDs: map[string]string{"worker-1": "node-uid-1"}, InventoryDigest: "sha256:" + strings.Repeat("a", 64), DrainTimeoutSeconds: 30, Method: controlplane.ClusterMaintenanceAuthorityMethod})
	if result.Success || !strings.Contains(result.Error, "no controller owner") || evictions != 0 || unschedulable {
		t.Fatalf("result=%+v evictions=%d unschedulable=%v", result, evictions, unschedulable)
	}
}

func TestMaintenanceEvictionRejectsReplacementConflict(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousToken := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousToken }()
	p := maintenancePod{}
	p.Metadata.Name = "web-1"
	p.Metadata.Namespace = "app"
	p.Metadata.UID = "uid-old"
	p.Metadata.ResourceVersion = "10"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var eviction map[string]any
		if err := json.NewDecoder(request.Body).Decode(&eviction); err != nil {
			t.Fatal(err)
		}
		pre := eviction["deleteOptions"].(map[string]any)["preconditions"].(map[string]any)
		if pre["uid"] != "uid-old" || pre["resourceVersion"] != "10" {
			t.Fatalf("preconditions=%v", pre)
		}
		return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"Conflict"}`)), Header: make(http.Header)}, nil
	})}
	ok, blocked, err := (&agent{kube: client}).evictMaintenancePod(context.Background(), p)
	if ok || blocked || err == nil || !strings.Contains(err.Error(), "identity/resourceVersion conflict") {
		t.Fatalf("ok=%v blocked=%v err=%v", ok, blocked, err)
	}
}

func TestClusterMaintenanceRejectsPreCordonedNode(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousToken := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousToken }()
	patches := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPatch {
			patches++
		}
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/nodes/worker-1" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"metadata":{"name":"worker-1","uid":"node-uid-1"},"spec":{"unschedulable":true}}`)), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	result := a.executeClusterMaintenanceTask(context.Background(), controlplane.ClusterMaintenanceTask{RunID: "cmr-2", RunRevision: 1, OperationID: "op-2", OperationRevision: 2, OperationFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), ClusterID: "cluster-1", NodeNames: []string{"worker-1"}, NodeUIDs: map[string]string{"worker-1": "node-uid-1"}, InventoryDigest: "sha256:" + strings.Repeat("b", 64), DrainTimeoutSeconds: 30, Method: controlplane.ClusterMaintenanceAuthorityMethod})
	if result.Success || !strings.Contains(result.Error, "already unschedulable") || patches != 0 {
		t.Fatalf("result=%+v patches=%d", result, patches)
	}
}

func TestClusterMaintenanceRejectsExpiredLeaseBeforeKubernetesMutation(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unexpected Kubernetes mutation after expired maintenance lease")
	})}
	task := controlplane.ClusterMaintenanceTask{RunID: "cmr-expired", RunRevision: 1, OperationID: "op-expired", OperationRevision: 1, OperationFenceToken: 1, LeaseExpiresAt: time.Now().Add(-time.Second), ClusterID: "cluster-1", NodeNames: []string{"worker-1"}, NodeUIDs: map[string]string{"worker-1": "node-uid-1"}, InventoryDigest: "sha256:" + strings.Repeat("a", 64), DrainTimeoutSeconds: 30, Method: controlplane.ClusterMaintenanceAuthorityMethod}
	result := (&agent{kube: client}).executeClusterMaintenanceTask(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "invalid cluster maintenance task contract") || calls != 0 {
		t.Fatalf("result=%+v calls=%d", result, calls)
	}
}

func TestLoadOrClaimPrefersAuthoritativeCertificateSecretOverStaleLocalCache(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	oldCredential := certificateCredentialForTest(t, "cluster-old", time.Now().UTC().Add(-time.Minute), 24*time.Hour)
	currentCredential := certificateCredentialForTest(t, "cluster-current", time.Now().UTC().Add(-time.Minute), 24*time.Hour)
	cachePath := filepath.Join(t.TempDir(), "agent-credential.json")
	oldRaw, _ := json.Marshal(oldCredential)
	if err := os.WriteFile(cachePath, oldRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	data := map[string]string{
		"clusterId": base64.StdEncoding.EncodeToString([]byte(currentCredential.ClusterID)),
		"tls.crt":   base64.StdEncoding.EncodeToString([]byte(currentCredential.CertificatePEM)),
		"tls.key":   base64.StdEncoding.EncodeToString([]byte(currentCredential.PrivateKeyPEM)),
		"notAfter":  base64.StdEncoding.EncodeToString([]byte(currentCredential.NotAfter.UTC().Format(time.RFC3339))),
	}
	secretRaw, _ := json.Marshal(map[string]any{"data": data})
	kube := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/namespaces/4so-platform-agent/secrets/agent-cert" {
			t.Fatalf("unexpected Kubernetes request %s %s", request.Method, request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(secretRaw))), Header: make(http.Header)}, nil
	})}
	hub := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	a := &agent{cfg: config{Namespace: "4so-platform-agent", CertificateSecret: "agent-cert", TokenFile: cachePath}, kube: kube, hub: hub}
	if err := a.loadOrClaim(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.clusterID != currentCredential.ClusterID {
		t.Fatalf("stale local cache won over authoritative Secret: clusterID=%q", a.clusterID)
	}
	cached, ok := a.readFileCredential()
	if !ok || cached.ClusterID != currentCredential.ClusterID {
		t.Fatalf("local cache was not refreshed from authority: %+v ok=%v", cached, ok)
	}
}

func TestTaskExecutionContextIsBoundToActiveLease(t *testing.T) {
	parent := context.Background()
	if _, _, err := taskExecutionContext(parent, time.Now().Add(-time.Second)); err == nil {
		t.Fatal("expected expired lease to reject execution")
	}
	lease := time.Now().Add(2 * time.Minute)
	ctx, cancel, err := taskExecutionContext(parent, lease)
	if err != nil {
		t.Fatalf("active lease rejected: %v", err)
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("execution context missing lease deadline")
	}
	if delta := deadline.Sub(lease); delta < -time.Millisecond || delta > time.Millisecond {
		t.Fatalf("execution deadline=%s lease=%s", deadline, lease)
	}
}

func TestTenantProtectedCreateRejectsConcurrentForeignOwner(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	tenantID := "ten_race"
	task := controlplane.TenantTask{TenantID: tenantID, Namespace: "tenant-race"}
	tests := []struct {
		name       string
		resource   controlplane.BaselineTaskResource
		objectPath string
	}{
		{
			name: "namespace",
			resource: controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "Namespace", Name: "tenant-race", Object: map[string]any{
				"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "tenant-race", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}},
			}},
			objectPath: "/api/v1/namespaces/tenant-race",
		},
		{
			name: "resourcequota",
			resource: controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "ResourceQuota", Namespace: "tenant-race", Name: "tenant-quota", Object: map[string]any{
				"apiVersion": "v1", "kind": "ResourceQuota", "metadata": map[string]any{"name": "tenant-quota", "namespace": "tenant-race", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}},
			}},
			objectPath: "/api/v1/namespaces/tenant-race/resourcequotas/tenant-quota",
		},
		{
			name: "limitrange",
			resource: controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "LimitRange", Namespace: "tenant-race", Name: "tenant-limits", Object: map[string]any{
				"apiVersion": "v1", "kind": "LimitRange", "metadata": map[string]any{"name": "tenant-limits", "namespace": "tenant-race", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}},
			}},
			objectPath: "/api/v1/namespaces/tenant-race/limitranges/tenant-limits",
		},
		{
			name: "networkpolicy",
			resource: controlplane.BaselineTaskResource{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: "tenant-race", Name: "tenant-network", Object: map[string]any{
				"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "tenant-network", "namespace": "tenant-race", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}},
			}},
			objectPath: "/apis/networking.k8s.io/v1/namespaces/tenant-race/networkpolicies/tenant-network",
		},
		{
			name: "configmap",
			resource: controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "ConfigMap", Namespace: "tenant-race", Name: "tenant-config", Object: map[string]any{
				"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "tenant-config", "namespace": "tenant-race", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}},
			}},
			objectPath: "/api/v1/namespaces/tenant-race/configmaps/tenant-config",
		},
		{
			name: "schedule",
			resource: controlplane.BaselineTaskResource{APIVersion: "velero.io/v1", Kind: "Schedule", Namespace: "velero", Name: controlplane.TenantBackupScheduleName(tenantID), Object: map[string]any{
				"apiVersion": "velero.io/v1", "kind": "Schedule", "metadata": map[string]any{"name": controlplane.TenantBackupScheduleName(tenantID), "namespace": "velero", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}},
			}},
			objectPath: "/apis/velero.io/v1/namespaces/velero/schedules/" + controlplane.TenantBackupScheduleName(tenantID),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getCount := 0
			patchCount := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.Method {
				case http.MethodGet:
					getCount++
					if getCount == 1 {
						return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
					}
					foreign := map[string]any{"metadata": map[string]any{"labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": "ten_foreign"}}}
					raw, _ := json.Marshal(foreign)
					return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
				case http.MethodPost:
					return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
				case http.MethodPatch:
					patchCount++
					return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
				default:
					t.Fatalf("unexpected %s %s", request.Method, request.URL.Path)
					return nil, nil
				}
			})}
			a := &agent{kube: client}
			err := a.applyTenantResource(context.Background(), task, tc.resource)
			if err == nil || !strings.Contains(err.Error(), "refusing to adopt concurrently created") {
				t.Fatalf("concurrent foreign owner accepted: err=%v", err)
			}
			if patchCount != 0 {
				t.Fatalf("foreign %s was mutated after conflict: patches=%d", tc.name, patchCount)
			}
		})
	}
}

func TestTenantResourceRejectsExistingForeignOwnerBeforeMutation(t *testing.T) {
	useRollbackTestToken(t)
	tenantID := "ten_existing"
	task := controlplane.TenantTask{TenantID: tenantID, Namespace: "tenant-existing"}
	resources := []controlplane.BaselineTaskResource{
		{APIVersion: "v1", Kind: "Namespace", Name: "tenant-existing", Object: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "tenant-existing", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}},
		{APIVersion: "v1", Kind: "ResourceQuota", Namespace: "tenant-existing", Name: "tenant-quota", Object: map[string]any{"apiVersion": "v1", "kind": "ResourceQuota", "metadata": map[string]any{"name": "tenant-quota", "namespace": "tenant-existing", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}},
		{APIVersion: "v1", Kind: "LimitRange", Namespace: "tenant-existing", Name: "tenant-limits", Object: map[string]any{"apiVersion": "v1", "kind": "LimitRange", "metadata": map[string]any{"name": "tenant-limits", "namespace": "tenant-existing", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}},
		{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Namespace: "tenant-existing", Name: "tenant-network", Object: map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": "tenant-network", "namespace": "tenant-existing", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}},
		{APIVersion: "v1", Kind: "ConfigMap", Namespace: "tenant-existing", Name: "tenant-config", Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "tenant-config", "namespace": "tenant-existing", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}},
		{APIVersion: "velero.io/v1", Kind: "Schedule", Namespace: "velero", Name: controlplane.TenantBackupScheduleName(tenantID), Object: map[string]any{"apiVersion": "velero.io/v1", "kind": "Schedule", "metadata": map[string]any{"name": controlplane.TenantBackupScheduleName(tenantID), "namespace": "velero", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}},
	}
	for _, resource := range resources {
		t.Run(resource.Kind, func(t *testing.T) {
			patches, posts := 0, 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.Method {
				case http.MethodGet:
					foreign := map[string]any{"metadata": map[string]any{"uid": "uid-foreign", "resourceVersion": "9", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": "ten_foreign"}}}
					raw, _ := json.Marshal(foreign)
					return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
				case http.MethodPatch:
					patches++
				case http.MethodPost:
					posts++
				}
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			})}
			err := (&agent{kube: client}).applyTenantResource(context.Background(), task, resource)
			if err == nil || !strings.Contains(err.Error(), "not owned by this tenant") || patches != 0 || posts != 0 {
				t.Fatalf("foreign %s accepted: err=%v patches=%d posts=%d", resource.Kind, err, patches, posts)
			}
		})
	}
}

func TestTenantDeleteCleansOwnedLegacyScheduleAndRejectsAmbiguousLegacyOwnership(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	tenantID := "ten_legacy"
	namespace := "tenant-legacy"
	legacyPath := "/apis/velero.io/v1/namespaces/velero/schedules/tenant-platform-backup"
	nsPath := "/api/v1/namespaces/" + namespace
	ownedLabels := map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}
	makeLegacy := func(included string) map[string]any {
		return map[string]any{"metadata": map[string]any{"uid": "uid-legacy-" + included, "resourceVersion": "20", "labels": ownedLabels}, "spec": map[string]any{"template": map[string]any{"includedNamespaces": []any{included}}}}
	}
	objects := map[string]map[string]any{
		nsPath:     {"metadata": map[string]any{"uid": "uid-namespace-legacy", "resourceVersion": "21", "labels": ownedLabels}},
		legacyPath: makeLegacy(namespace),
	}
	deleteCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodGet:
			object, ok := objects[request.URL.Path]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			raw, _ := json.Marshal(object)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
		case http.MethodDelete:
			deleteCalls++
			var options map[string]any
			if err := json.NewDecoder(request.Body).Decode(&options); err != nil {
				t.Fatal(err)
			}
			preconditions, _ := options["preconditions"].(map[string]any)
			current, ok := objects[request.URL.Path]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			metadata, _ := current["metadata"].(map[string]any)
			if preconditions["uid"] != metadata["uid"] || preconditions["resourceVersion"] != metadata["resourceVersion"] {
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"message":"identity precondition failed"}`)), Header: make(http.Header)}, nil
			}
			delete(objects, request.URL.Path)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	task := controlplane.TenantTask{TenantID: tenantID, TenantRevision: 1, Action: "DELETE", Namespace: namespace, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour)}
	result := a.executeTenantTask(context.Background(), task)
	if !result.Success || !result.Deleted || deleteCalls != 2 {
		t.Fatalf("legacy delete did not clean schedule+namespace: result=%+v deletes=%d", result, deleteCalls)
	}

	objects[nsPath] = map[string]any{"metadata": map[string]any{"uid": "uid-namespace-legacy-2", "resourceVersion": "22", "labels": ownedLabels}}
	objects[legacyPath] = makeLegacy("tenant-other")
	deleteCalls = 0
	result = a.executeTenantTask(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "ownership is ambiguous") || deleteCalls != 0 {
		t.Fatalf("ambiguous legacy ownership must fail closed: result=%+v deletes=%d", result, deleteCalls)
	}
}

func TestRuntimeCertificationRejectsConcurrentForeignNamespace(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := catalog.RenderComponent(components["secure-namespace-foundation"], "4so-cert-race", "catrel_race")
	if err != nil {
		t.Fatal(err)
	}
	gets := 0
	patches := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		switch {
		case request.Method == http.MethodGet && path == "/api/v1/namespaces/4so-cert-race":
			gets++
			if gets == 1 {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			foreign := `{"metadata":{"name":"4so-cert-race","uid":"foreign-uid","labels":{"app.kubernetes.io/managed-by":"other-controller"}}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(foreign)), Header: make(http.Header)}, nil
		case request.Method == http.MethodPost && path == "/api/v1/namespaces":
			return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"AlreadyExists"}`)), Header: make(http.Header)}, nil
		case request.Method == http.MethodPatch:
			patches++
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, path)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	task := controlplane.RuntimeCertificationTask{RunID: "rtc_race", RunRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), Profile: controlplane.RuntimeCertificationFoundationV1, Phase: controlplane.RuntimeCertificationPhaseInstall, Namespace: "4so-cert-race", InventoryDigest: digest("1"), EnvironmentFingerprint: digest("2"), CatalogReleaseID: "catrel_race", ManifestDigest: digest("3"), SourceLockDigest: digest("4"), RenderedDigest: digest("5"), TaskAttempt: 1, CleanupToken: "cleanup-test", Resources: rendered.Resources}
	result := a.runRuntimeCertification(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "refusing to adopt concurrently created runtime certification namespace") || patches != 0 {
		t.Fatalf("result=%+v patches=%d", result, patches)
	}
}

func TestRollbackBaselineDeleteRejectsForeignReplacementAndUsesUIDPrecondition(t *testing.T) {
	useRollbackTestToken(t)
	path := baselineResourcePaths["ServiceAccount/4so-baseline-observer"]
	deleteCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == path:
			body := `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"4so-baseline-observer","namespace":"4so-platform-baseline","uid":"uid-owned","resourceVersion":"55","annotations":{"platform.4so.io/managed":"true","platform.4so.io/deployment-id":"bdep-owned","platform.4so.io/desired-digest":"sha256:` + strings.Repeat("a", 64) + `"},"labels":{"app.kubernetes.io/managed-by":"4so-platform-factory"}}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		case r.Method == http.MethodDelete && r.URL.Path == path:
			deleteCalls++
			var opts map[string]any
			if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
				t.Fatal(err)
			}
			pre, _ := opts["preconditions"].(map[string]any)
			if pre["uid"] != "uid-owned" || pre["resourceVersion"] != "55" {
				t.Fatalf("delete preconditions=%v", opts)
			}
			return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"Conflict"}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	task := controlplane.BaselineTask{DeploymentID: "bdep-owned", DesiredDigest: "sha256:" + strings.Repeat("a", 64), Resources: []controlplane.BaselineTaskResource{{APIVersion: "v1", Kind: "ServiceAccount", Namespace: baseline.ManagedNamespace, Name: "4so-baseline-observer", Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "4so-baseline-observer", "namespace": baseline.ManagedNamespace, "annotations": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/deployment-id": "bdep-owned", "platform.4so.io/desired-digest": "sha256:" + strings.Repeat("a", 64)}, "labels": map[string]any{"app.kubernetes.io/managed-by": "4so-platform-factory"}}}}}, Rollback: []controlplane.PlanRollbackResource{{Resource: "ServiceAccount/4so-baseline-observer", Strategy: "DELETE_CREATED_RESOURCE", Status: "PASS"}}}
	result := a.rollbackBaseline(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "identity precondition conflict") || deleteCalls != 1 {
		t.Fatalf("result=%+v deleteCalls=%d", result, deleteCalls)
	}
}

func TestClusterMaintenanceRejectsNodeUIDReplacementBeforeCordon(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousToken := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousToken }()
	patches := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPatch {
			patches++
		}
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/nodes/worker-1" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"metadata":{"name":"worker-1","uid":"replacement-uid"},"spec":{"unschedulable":false}}`)), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	task := controlplane.ClusterMaintenanceTask{RunID: "cmr-uid", RunRevision: 1, OperationID: "op-uid", OperationRevision: 1, OperationFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), ClusterID: "cluster-1", NodeNames: []string{"worker-1"}, NodeUIDs: map[string]string{"worker-1": "approved-uid"}, InventoryDigest: "sha256:" + strings.Repeat("c", 64), DrainTimeoutSeconds: 30, Method: controlplane.ClusterMaintenanceAuthorityMethod}
	result := a.executeClusterMaintenanceTask(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "UID no longer matches") || patches != 0 {
		t.Fatalf("result=%+v patches=%d", result, patches)
	}
}

func TestBaselineApplyRejectsPostPlanDriftAndResourceVersionRace(t *testing.T) {
	useRollbackTestToken(t)
	desiredDigest := "sha256:" + strings.Repeat("9", 64)
	resource := baseline.Resources("bdep-plan-fence", desiredDigest)[4]
	path := baselineResourcePaths[resource.Kind+"/"+resource.Name]
	preimage := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": resource.Name, "namespace": resource.Namespace, "uid": "uid-plan", "resourceVersion": "10"}, "data": map[string]any{"before": "true"}}
	observed, err := sanitizeRollbackObject(resource, preimage)
	if err != nil {
		t.Fatal(err)
	}
	rollback := controlplane.PlanRollbackResource{Resource: resource.Kind + "/" + resource.Name, ChangeAction: "UPDATE", Strategy: "RESTORE_PREIMAGE", Status: "PASS", AuthorizationStatus: "PASS", DryRunStatus: "PASS", HTTPStatus: 200, ObservedUID: "uid-plan", ObservedObjectDigest: rollbackObjectDigest(observed), RestoreObject: observed, RestoreObjectDigest: rollbackObjectDigest(observed)}
	task := controlplane.BaselineTask{DeploymentID: "bdep-plan-fence", DesiredDigest: desiredDigest}

	t.Run("drift after plan", func(t *testing.T) {
		patches := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPatch {
				patches++
			}
			if r.Method != http.MethodGet || r.URL.Path != path {
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			body := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"` + resource.Name + `","namespace":"` + resource.Namespace + `","uid":"uid-plan","resourceVersion":"11"},"data":{"external":"change"}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		err := (&agent{kube: client}).applyBaselineResource(context.Background(), task, resource, rollback)
		if err == nil || patches != 0 || !strings.Contains(err.Error(), "changed after planning") {
			t.Fatalf("err=%v patches=%d", err, patches)
		}
	})

	t.Run("managed-label-preserving drift after plan", func(t *testing.T) {
		patches := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPatch {
				patches++
			}
			if r.Method != http.MethodGet || r.URL.Path != path {
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			body := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"` + resource.Name + `","namespace":"` + resource.Namespace + `","uid":"uid-plan","resourceVersion":"11","annotations":{"platform.4so.io/managed":"true","platform.4so.io/deployment-id":"bdep-plan-fence","platform.4so.io/desired-digest":"` + desiredDigest + `"},"labels":{"app.kubernetes.io/managed-by":"4so-platform-factory"}},"data":{"external":"change"}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		err := (&agent{kube: client}).applyBaselineResource(context.Background(), task, resource, rollback)
		if err == nil || patches != 0 || !strings.Contains(err.Error(), "changed after planning") {
			t.Fatalf("err=%v patches=%d", err, patches)
		}
	})

	t.Run("resource version race", func(t *testing.T) {
		patches := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case http.MethodGet:
				raw, _ := json.Marshal(preimage)
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
			case http.MethodPatch:
				patches++
				var object map[string]any
				if err := json.NewDecoder(r.Body).Decode(&object); err != nil {
					t.Fatal(err)
				}
				metadata, _ := object["metadata"].(map[string]any)
				if metadata["resourceVersion"] != "10" {
					t.Fatalf("conditional apply resourceVersion=%v", metadata["resourceVersion"])
				}
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"Conflict"}`)), Header: make(http.Header)}, nil
			default:
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				return nil, nil
			}
		})}
		err := (&agent{kube: client}).applyBaselineResource(context.Background(), task, resource, rollback)
		if err == nil || patches != 1 || !strings.Contains(err.Error(), "resourceVersion conflict") {
			t.Fatalf("err=%v patches=%d", err, patches)
		}
	})
}

func TestOwnedExistingMutationPathsUseConditionalResourceVersion(t *testing.T) {
	useRollbackTestToken(t)
	t.Run("tenant namespace", func(t *testing.T) {
		tenantID := "ten-rv"
		namespace := "tenant-rv"
		current := `{"metadata":{"name":"tenant-rv","uid":"uid-tenant-rv","resourceVersion":"21","labels":{"platform.4so.io/managed":"true","platform.4so.io/tenant-id":"ten-rv"}}}`
		patches := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case http.MethodGet:
				return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(current)), Header: make(http.Header)}, nil
			case http.MethodPatch:
				patches++
				var object map[string]any
				if err := json.NewDecoder(r.Body).Decode(&object); err != nil {
					t.Fatal(err)
				}
				meta, _ := object["metadata"].(map[string]any)
				if meta["resourceVersion"] != "21" {
					t.Fatalf("resourceVersion=%v", meta["resourceVersion"])
				}
				return &http.Response{StatusCode: 409, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"Conflict"}`)), Header: make(http.Header)}, nil
			default:
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				return nil, nil
			}
		})}
		resource := controlplane.BaselineTaskResource{APIVersion: "v1", Kind: "Namespace", Name: namespace, Object: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": namespace, "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/tenant-id": tenantID}}}}
		err := (&agent{kube: client}).applyTenantResource(context.Background(), controlplane.TenantTask{TenantID: tenantID, Namespace: namespace}, resource)
		if err == nil || patches != 1 || !strings.Contains(err.Error(), "resourceVersion conflict") {
			t.Fatalf("err=%v patches=%d", err, patches)
		}
	})

	t.Run("provider cluster", func(t *testing.T) {
		digest := "sha256:" + strings.Repeat("8", 64)
		task := controlplane.ProviderClusterTask{ProviderClusterID: "pcl-rv", Namespace: "4so-provider-system", ResourceName: "pf-rv", DesiredDigest: digest, Resource: map[string]any{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "metadata": map[string]any{"name": "pf-rv", "namespace": "4so-provider-system", "labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/provider-cluster-id": "pcl-rv"}, "annotations": map[string]any{"platform.4so.io/desired-digest": digest}}}}
		current := `{"metadata":{"name":"pf-rv","namespace":"4so-provider-system","uid":"uid-provider-rv","resourceVersion":"31","labels":{"platform.4so.io/managed":"true","platform.4so.io/provider-cluster-id":"pcl-rv"},"annotations":{"platform.4so.io/desired-digest":"` + digest + `"}}}`
		patches := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case http.MethodGet:
				return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(current)), Header: make(http.Header)}, nil
			case http.MethodPatch:
				patches++
				var object map[string]any
				if err := json.NewDecoder(r.Body).Decode(&object); err != nil {
					t.Fatal(err)
				}
				meta, _ := object["metadata"].(map[string]any)
				if meta["resourceVersion"] != "31" {
					t.Fatalf("resourceVersion=%v", meta["resourceVersion"])
				}
				return &http.Response{StatusCode: 409, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"Conflict"}`)), Header: make(http.Header)}, nil
			default:
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				return nil, nil
			}
		})}
		err := (&agent{kube: client}).applyProviderClusterResource(context.Background(), task)
		if err == nil || patches != 1 || !strings.Contains(err.Error(), "resourceVersion conflict") {
			t.Fatalf("err=%v patches=%d", err, patches)
		}
	})

	t.Run("runtime certification namespace retry", func(t *testing.T) {
		task := controlplane.RuntimeCertificationTask{TaskAttempt: 2, Namespace: "4so-cert-rv", CatalogReleaseID: "catrel-rv", Resources: []map[string]any{{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "4so-cert-rv", "labels": map[string]any{"app.kubernetes.io/managed-by": "4so-platform-factory", "platform.4so.io/catalog-release-id": "catrel-rv", "platform.4so.io/component": "secure-namespace-foundation"}}}}}
		current := `{"metadata":{"name":"4so-cert-rv","uid":"uid-cert-rv","resourceVersion":"41","labels":{"app.kubernetes.io/managed-by":"4so-platform-factory","platform.4so.io/catalog-release-id":"catrel-rv","platform.4so.io/component":"secure-namespace-foundation"}}}`
		patches := 0
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.Method {
			case http.MethodGet:
				return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(current)), Header: make(http.Header)}, nil
			case http.MethodPatch:
				patches++
				var object map[string]any
				if err := json.NewDecoder(r.Body).Decode(&object); err != nil {
					t.Fatal(err)
				}
				meta, _ := object["metadata"].(map[string]any)
				if meta["resourceVersion"] != "41" {
					t.Fatalf("resourceVersion=%v", meta["resourceVersion"])
				}
				return &http.Response{StatusCode: 409, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"Conflict"}`)), Header: make(http.Header)}, nil
			default:
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				return nil, nil
			}
		})}
		_, err := (&agent{kube: client}).ensureRuntimeCertificationNamespace(context.Background(), task)
		if err == nil || patches != 1 || !strings.Contains(err.Error(), "resourceVersion conflict") {
			t.Fatalf("err=%v patches=%d", err, patches)
		}
	})
}

func TestBaselineDesiredFieldComparisonDetectsStaleDigestDrift(t *testing.T) {
	desired := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name": "example",
			"annotations": map[string]any{
				"platform.4so.io/desired-digest": "sha256:" + strings.Repeat("a", 64),
			},
		},
		"data": map[string]any{"mode": "expected"},
	}
	current := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":            "example",
			"resourceVersion": "22",
			"annotations": map[string]any{
				"platform.4so.io/desired-digest": "sha256:" + strings.Repeat("a", 64),
				"server.example/extra":           "allowed",
			},
		},
		"data": map[string]any{"mode": "drifted"},
	}
	if kubeObjectContainsDesiredFields(current, desired) {
		t.Fatal("stale desired-digest annotation must not hide managed-field drift")
	}
	current["data"] = map[string]any{"mode": "expected"}
	if !kubeObjectContainsDesiredFields(current, desired) {
		t.Fatal("extra server-managed fields must not make an otherwise matching desired object drift")
	}
}

func TestBaselineAddConflictNeverAdoptsForeignConcurrentResource(t *testing.T) {
	useRollbackTestToken(t)
	digest := "sha256:" + strings.Repeat("7", 64)
	resource := baseline.Resources("bdep-add-race", digest)[4]
	path := baselineResourcePaths[resource.Kind+"/"+resource.Name]
	gets, posts, patches := 0, 0, 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == path:
			gets++
			if gets == 1 {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			foreign := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"` + resource.Name + `","namespace":"` + resource.Namespace + `","uid":"foreign-uid","resourceVersion":"2","annotations":{"platform.4so.io/managed":"true","platform.4so.io/deployment-id":"different-deployment","platform.4so.io/desired-digest":"` + digest + `"},"labels":{"app.kubernetes.io/managed-by":"4so-platform-factory"}}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(foreign)), Header: make(http.Header)}, nil
		case r.Method == http.MethodPost:
			posts++
			return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{"reason":"AlreadyExists"}`)), Header: make(http.Header)}, nil
		case r.Method == http.MethodPatch:
			patches++
			t.Fatalf("foreign concurrent baseline object must never be patched")
			return nil, nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}
	rollback := controlplane.PlanRollbackResource{Resource: resource.Kind + "/" + resource.Name, ChangeAction: "ADD", Strategy: "DELETE_CREATED_RESOURCE", Status: "PASS", AuthorizationStatus: "PASS", DryRunStatus: "NOT_APPLICABLE"}
	err := (&agent{kube: client}).applyBaselineResource(context.Background(), controlplane.BaselineTask{DeploymentID: "bdep-add-race", DesiredDigest: digest}, resource, rollback)
	if err == nil || !strings.Contains(err.Error(), "refusing to adopt concurrently created or drifted baseline resource") || gets != 2 || posts != 1 || patches != 0 {
		t.Fatalf("err=%v gets=%d posts=%d patches=%d", err, gets, posts, patches)
	}
}

func TestRuntimeProbeCleanupFailureFailsVerification(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	verificationID := "rtv_cleanup_failure"
	jobName := "4so-runtime-probe-" + strings.TrimPrefix(verificationID, "rtv_")
	jobPath := "/apis/batch/v1/namespaces/4so-platform-baseline/jobs/" + jobName
	created := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := func(code int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == jobPath && !created:
			return response(http.StatusNotFound, `{}`)
		case request.Method == http.MethodPost && request.URL.Path == "/apis/batch/v1/namespaces/4so-platform-baseline/jobs":
			created = true
			return response(http.StatusCreated, `{"metadata":{"uid":"job-cleanup-uid","resourceVersion":"1"}}`)
		case request.Method == http.MethodGet && request.URL.Path == jobPath && created:
			return response(http.StatusOK, `{"metadata":{"uid":"job-cleanup-uid","resourceVersion":"2","labels":{"platform.4so.io/runtime-verification":"`+verificationID+`"}},"status":{"succeeded":1}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/namespaces/4so-platform-baseline/pods":
			return response(http.StatusOK, `{"items":[{"metadata":{"name":"probe-pod","ownerReferences":[{"uid":"job-cleanup-uid"}]},"status":{"containerStatuses":[{"name":"probe","state":{"terminated":{"message":"{\"dnsResolved\":true,\"addresses\":[\"10.43.0.1\"],\"tcpConnected\":true,\"durationMillis\":2}"}}}]}}]}`)
		case request.Method == http.MethodDelete && request.URL.Path == jobPath:
			return response(http.StatusConflict, `{"message":"resourceVersion conflict"}`)
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return response(http.StatusInternalServerError, `{}`)
		}
	})}

	a := &agent{kube: client}
	checks, err := a.runProbeJob(context.Background(), controlplane.RuntimeVerificationTask{VerificationID: verificationID, ProbeImage: "registry.local/probe@sha256:" + strings.Repeat("a", 64)})
	if err == nil || !strings.Contains(err.Error(), "probe cleanup failed") {
		t.Fatalf("cleanup failure was not surfaced: err=%v checks=%+v", err, checks)
	}
	foundFailure := false
	for _, item := range checks {
		if item.Key == "probe-job-cleanup" && item.Status == "FAIL" {
			foundFailure = true
		}
	}
	if !foundFailure {
		t.Fatalf("cleanup failure evidence missing: %+v", checks)
	}
}

func TestAgentPollDelaySpreadsStartupAndRecurringCycles(t *testing.T) {
	interval := 60 * time.Second
	startupA := agentPollDelay("cluster-a", interval, 0)
	startupB := agentPollDelay("cluster-b", interval, 0)
	if startupA < 0 || startupA > interval/5 || startupB < 0 || startupB > interval/5 {
		t.Fatalf("startup jitter outside [0,12s]: a=%s b=%s", startupA, startupB)
	}
	if startupA == startupB {
		t.Fatalf("different clusters unexpectedly share identical startup jitter: %s", startupA)
	}
	for cycle := uint64(1); cycle <= 20; cycle++ {
		delay := agentPollDelay("cluster-a", interval, cycle)
		if delay < 54*time.Second || delay > 66*time.Second {
			t.Fatalf("cycle %d delay=%s outside +/-10%% window", cycle, delay)
		}
	}
	if got, want := agentPollDelay("cluster-a", interval, 7), agentPollDelay("cluster-a", interval, 7); got != want {
		t.Fatalf("jitter must be deterministic: got=%s want=%s", got, want)
	}
}

func TestDetectDistributionAuthorityRequiresRealClusterVersionSingleton(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/apis/config.openshift.io/v1/clusterversions/version" {
			t.Fatalf("unexpected Kubernetes request: %s", request.URL.Path)
		}
		body := `{"metadata":{"name":"version","uid":"cv-uid-1"},"status":{"desired":{"version":"4.19.0-okd-scos.0"}}}`
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	distribution, method, uid, version, err := (&agent{kube: client}).detectDistributionAuthority(context.Background(), "kubernetes", "v1.32.0", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if distribution != "okd" || method != controlplane.DistributionEvidenceOKDClusterV1 || uid != "cv-uid-1" || version != "4.19.0-okd-scos.0" {
		t.Fatalf("unexpected OKD authority result: distribution=%q method=%q uid=%q version=%q", distribution, method, uid, version)
	}
}

func TestDetectDistributionAuthorityDistinguishesRedHatOpenShiftFromOKD(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/apis/config.openshift.io/v1/clusterversions/version" {
			t.Fatalf("unexpected Kubernetes request: %s", request.URL.Path)
		}
		body := `{"metadata":{"name":"version","uid":"ocp-cv-uid-1"},"status":{"desired":{"version":"4.19.7"}}}`
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	distribution, method, uid, releaseVersion, err := (&agent{kube: client}).detectDistributionAuthority(context.Background(), "kubernetes", "v1.32.0", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if distribution != targetmodel.DistributionOpenShift || method != controlplane.DistributionEvidenceOpenShiftClusterV1 || uid != "ocp-cv-uid-1" || releaseVersion != "4.19.7" {
		t.Fatalf("OpenShift was collapsed into OKD authority: distribution=%q method=%q uid=%q version=%q", distribution, method, uid, releaseVersion)
	}
}

func TestDetectDistributionAuthorityRejectsClusterVersionCRDSpoof(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"metadata":{"name":"version","uid":"cv-uid-1"},"status":{"desired":{"version":"4.19.0-okd-scos.0"}}}`
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	crds := []controlplane.ClusterCRDObservation{{Name: "clusterversions.config.openshift.io"}}
	if _, _, _, _, err := (&agent{kube: client}).detectDistributionAuthority(context.Background(), "kubernetes", "v1.32.0", crds, true); err == nil {
		t.Fatal("same-name CRD spoof was accepted as OKD authority")
	}
}

func TestMutationRBACActiveRequiresIdentityBindingAndEveryRepresentativePermission(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	ssarCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/api/v1/namespaces/4so-platform-agent/configmaps/4so-platform-mutation-activation":
			body := `{"data":{"clusterId":"cluster-a","externalUid":"uid-a","issuedFromInventoryDigest":"sha256:` + strings.Repeat("a", 64) + `"}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		case "/api/v1/namespaces/kube-system":
			body := `{"metadata":{"uid":"uid-a"}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			ssarCalls++
			allowed := ssarCalls != 4
			body := fmt.Sprintf(`{"status":{"allowed":%t,"denied":%t}}`, allowed, !allowed)
			return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected Kubernetes request: %s", request.URL.Path)
			return nil, nil
		}
	})}
	if (&agent{kube: client, cfg: config{Namespace: "4so-platform-agent"}, clusterID: "cluster-a"}).mutationRBACActive(context.Background(), "sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("partial mutation RBAC was reported active")
	}
	if ssarCalls != 4 {
		t.Fatalf("RBAC proof did not fail closed at denied permission: calls=%d", ssarCalls)
	}
}

func TestMutationRBACActiveRejectsActivationManifestFromAnotherCluster(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	ssarCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/api/v1/namespaces/4so-platform-agent/configmaps/4so-platform-mutation-activation":
			body := `{"data":{"clusterId":"cluster-a","externalUid":"uid-a","issuedFromInventoryDigest":"sha256:` + strings.Repeat("b", 64) + `"}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		default:
			ssarCalls++
			body := `{"status":{"allowed":true,"denied":false}}`
			return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
	})}
	if (&agent{kube: client, cfg: config{Namespace: "4so-platform-agent"}, clusterID: "cluster-b"}).mutationRBACActive(context.Background(), "sha256:"+strings.Repeat("b", 64)) {
		t.Fatal("activation manifest bound to another cluster was accepted")
	}
	if ssarCalls != 0 {
		t.Fatalf("identity mismatch should fail before any mutation permission proof: calls=%d", ssarCalls)
	}
}

func TestMutationRBACActiveRejectsActivationIssuedForStaleInventoryBasis(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	nonActivationCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/v1/namespaces/4so-platform-agent/configmaps/4so-platform-mutation-activation" {
			body := `{"data":{"clusterId":"cluster-a","externalUid":"uid-a","issuedFromInventoryDigest":"sha256:` + strings.Repeat("a", 64) + `"}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		nonActivationCalls++
		return &http.Response{StatusCode: http.StatusInternalServerError, Status: "500 unexpected", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	if (&agent{kube: client, cfg: config{Namespace: "4so-platform-agent"}, clusterID: "cluster-a"}).mutationRBACActive(context.Background(), "sha256:"+strings.Repeat("b", 64)) {
		t.Fatal("activation issued for a stale inventory basis was accepted")
	}
	if nonActivationCalls != 0 {
		t.Fatalf("stale activation digest must fail before UID/SSAR proof, calls=%d", nonActivationCalls)
	}
}

func TestMutationRBACActiveRejectsRevokedActivationBeforePermissionProof(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	nonActivationCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/v1/namespaces/4so-platform-agent/configmaps/4so-platform-mutation-activation" {
			body := `{"data":{"clusterId":"cluster-a","externalUid":"uid-a","issuedFromInventoryDigest":"sha256:revoked","revoked":"true"}}`
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		nonActivationCalls++
		return &http.Response{StatusCode: http.StatusInternalServerError, Status: "500 unexpected", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	if (&agent{kube: client, cfg: config{Namespace: "4so-platform-agent"}, clusterID: "cluster-a"}).mutationRBACActive(context.Background(), "sha256:"+strings.Repeat("c", 64)) {
		t.Fatal("revoked mutation activation was accepted")
	}
	if nonActivationCalls != 0 {
		t.Fatalf("revoked activation must fail before UID/SSAR proof, calls=%d", nonActivationCalls)
	}
}

func TestEnrollmentPrincipalIsolationAttestationRequiresExpectedImportScopedServiceAccount(t *testing.T) {
	importID := "imp_generation_1"
	expected := controlplane.FleetAgentServiceAccountName(importID)
	a := &agent{cfg: config{ImportID: importID, ServiceAccount: expected}}
	if !a.enrollmentPrincipalIsolated() {
		t.Fatal("expected import-scoped service account was not attested")
	}
	a.cfg.ServiceAccount = "4so-platform-agent"
	if a.enrollmentPrincipalIsolated() {
		t.Fatal("legacy fixed service account was incorrectly attested as isolated")
	}
	a.cfg.ServiceAccount = controlplane.FleetAgentServiceAccountName("imp_other")
	if a.enrollmentPrincipalIsolated() {
		t.Fatal("service account from a different enrollment generation was accepted")
	}
}

func TestDiscoverOKDDistributionComponentsCapturesClusterVersionAndOperatorConditions(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.URL.Path {
		case "/apis/config.openshift.io/v1/clusteroperators":
			body = `{"items":[{"metadata":{"name":"network"},"status":{"version":"4.19.0","conditions":[{"type":"Available","status":"True"},{"type":"Progressing","status":"False"},{"type":"Degraded","status":"False"},{"type":"Upgradeable","status":"True"}]}},{"metadata":{"name":"monitoring"},"status":{"version":"4.19.0","conditions":[{"type":"Available","status":"False","reason":"RolloutPending","message":"monitoring rollout pending"},{"type":"Progressing","status":"True"},{"type":"Degraded","status":"False"}]}}]}`
		case "/apis/config.openshift.io/v1/clusterversions/version":
			body = `{"metadata":{"name":"version"},"spec":{"channel":"stable-4"},"status":{"desired":{"version":"4.19.0-okd-scos.0","image":"registry.example/release@sha256:` + strings.Repeat("a", 64) + `"},"conditions":[{"type":"Available","status":"True"},{"type":"Progressing","status":"False"},{"type":"Failing","status":"False"}]}}`
		default:
			t.Fatalf("unexpected Kubernetes request: %s", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	components, err := (&agent{kube: client}).discoverOpenShiftDistributionComponents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 3 {
		t.Fatalf("components=%+v", components)
	}
	byName := map[string]controlplane.ClusterAddOn{}
	for _, component := range components {
		byName[component.Name] = component
	}
	if byName["version"].Kind != "cluster-version" || byName["version"].Version != "4.19.0-okd-scos.0" || !byName["version"].Healthy || byName["version"].Degraded != "False" {
		t.Fatalf("cluster version=%+v", byName["version"])
	}
	if byName["network"].Kind != "cluster-operator" || !byName["network"].Healthy {
		t.Fatalf("network=%+v", byName["network"])
	}
	if byName["monitoring"].Healthy || byName["monitoring"].Progressing != "True" || byName["monitoring"].Reason != "RolloutPending" {
		t.Fatalf("monitoring=%+v", byName["monitoring"])
	}
}
func TestClusterVersionFailingConditionMapsToProductDegradedHealth(t *testing.T) {
	conditions := []struct {
		Type    string `json:"type"`
		Status  string `json:"status"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}{
		{Type: "Available", Status: "True"},
		{Type: "Progressing", Status: "False"},
		{Type: "Failing", Status: "True", Reason: "PayloadFailed", Message: "release payload reconciliation failed"},
		{Type: "Upgradeable", Status: "False", Reason: "AdminAckRequired"},
	}
	available, progressing, degraded, upgradeable, reason, message := clusterVersionConditionSummary(conditions)
	if available != "True" || progressing != "False" || degraded != "True" || upgradeable != "False" {
		t.Fatalf("unexpected condition projection available=%q progressing=%q degraded=%q upgradeable=%q", available, progressing, degraded, upgradeable)
	}
	if reason != "PayloadFailed" || message != "release payload reconciliation failed" {
		t.Fatalf("unexpected failure evidence reason=%q message=%q", reason, message)
	}
}

func TestDiscoverWorkloadExplorerReadsBoundedOperationalInventory(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	now := time.Now().UTC().Truncate(time.Second)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.URL.Path {
		case "/apis/apps/v1/deployments":
			body = `{"items":[{"metadata":{"namespace":"app","name":"web"},"spec":{"replicas":3,"template":{"spec":{"containers":[{"image":"registry.example/web@sha256:` + strings.Repeat("a", 64) + `"}]}}},"status":{"replicas":3,"readyReplicas":2}}]}`
		case "/apis/apps/v1/statefulsets", "/apis/apps/v1/daemonsets", "/apis/batch/v1/jobs":
			body = `{"items":[]}`
		case "/api/v1/services":
			body = `{"items":[{"metadata":{"namespace":"app","name":"web"},"spec":{"type":"ClusterIP","clusterIP":"10.43.1.20","ports":[{"name":"http","port":8080,"protocol":"TCP"}]}}]}`
		case "/apis/networking.k8s.io/v1/ingresses":
			body = `{"items":[{"metadata":{"namespace":"app","name":"web"},"spec":{"ingressClassName":"nginx","rules":[{"host":"web.example.test"}],"tls":[{"hosts":["web.example.test"]}]}}]}`
		case "/api/v1/persistentvolumeclaims":
			body = `{"items":[{"metadata":{"namespace":"app","name":"data"},"spec":{"storageClassName":"longhorn","resources":{"requests":{"storage":"10Gi"}}},"status":{"phase":"Bound"}}]}`
		case "/api/v1/events":
			body = fmt.Sprintf(`{"items":[{"metadata":{"namespace":"app"},"type":"Warning","reason":"Unhealthy","message":"readiness probe failed","count":2,"regarding":{"kind":"Deployment","name":"web"},"eventTime":%q}]}`, now.Format(time.RFC3339))
		default:
			t.Fatalf("unexpected Kubernetes request: %s", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}

	explorer, err := (&agent{kube: client}).discoverWorkloadExplorer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if explorer.Authority != controlplane.WorkloadExplorerAuthorityMethod || !explorer.Complete || explorer.Truncated {
		t.Fatalf("unexpected explorer authority/state: %+v", explorer)
	}
	if len(explorer.Workloads) != 1 || explorer.Workloads[0].Kind != "Deployment" || explorer.Workloads[0].ReadyReplicas != 2 || len(explorer.Workloads[0].Images) != 1 {
		t.Fatalf("workloads=%+v", explorer.Workloads)
	}
	if len(explorer.Services) != 1 || explorer.Services[0].Type != "ClusterIP" || explorer.Services[0].ClusterIP != "10.43.1.20" || explorer.Services[0].Ports[0].Port != 8080 || len(explorer.Ingresses) != 1 || explorer.Ingresses[0].Hosts[0] != "web.example.test" {
		t.Fatalf("service/ingress mismatch services=%+v ingresses=%+v", explorer.Services, explorer.Ingresses)
	}
	if len(explorer.PVCs) != 1 || explorer.PVCs[0].Requested != "10Gi" || explorer.PVCs[0].Phase != "Bound" {
		t.Fatalf("pvcs=%+v", explorer.PVCs)
	}
	if len(explorer.Events) != 1 || explorer.Events[0].Reason != "Unhealthy" || explorer.Events[0].RegardingName != "web" || explorer.Events[0].LastObservedAt.IsZero() {
		t.Fatalf("events=%+v", explorer.Events)
	}
}

func TestDiscoverWorkloadExplorerUsesKubernetesPaginationAndStopsAtBound(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	serviceCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/api/v1/services" {
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"items":[]}`)), Header: make(http.Header)}, nil
		}
		serviceCalls++
		wantLimit := 100
		continueValue := request.URL.Query().Get("continue")
		start := 0
		next := ""
		switch serviceCalls {
		case 1:
			if continueValue != "" {
				t.Fatalf("first service page unexpectedly had continue=%q", continueValue)
			}
			next = "page-2"
		case 2:
			if continueValue != "page-2" {
				t.Fatalf("second service page continue=%q", continueValue)
			}
			start = 100
			next = "page-3"
		case 3:
			wantLimit = 50
			if continueValue != "page-3" {
				t.Fatalf("third service page continue=%q", continueValue)
			}
			start = 200
			next = "page-4"
		default:
			t.Fatalf("service list fetched past bounded inventory: call=%d", serviceCalls)
		}
		if request.URL.Query().Get("limit") != strconv.Itoa(wantLimit) {
			t.Fatalf("service page %d limit=%q want=%d", serviceCalls, request.URL.Query().Get("limit"), wantLimit)
		}
		items := make([]map[string]any, wantLimit)
		for i := range items {
			items[i] = map[string]any{"metadata": map[string]any{"namespace": "app", "name": fmt.Sprintf("svc-%03d", start+i)}, "spec": map[string]any{"type": "ClusterIP", "clusterIP": fmt.Sprintf("10.43.%d.%d", (start+i)/250, (start+i)%250+1)}}
		}
		raw, err := json.Marshal(map[string]any{"metadata": map[string]any{"continue": next}, "items": items})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
	})}

	explorer, err := (&agent{kube: client}).discoverWorkloadExplorer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if serviceCalls != 3 || len(explorer.Services) != workloadExplorerItemLimit || !explorer.Truncated {
		t.Fatalf("pagination not bounded calls=%d services=%d truncated=%v", serviceCalls, len(explorer.Services), explorer.Truncated)
	}
}

func TestAgentSchedulerV2TaskKickIsBounded(t *testing.T) {
	kick := make(chan struct{}, 1)
	if !enqueueAgentTaskCycle(kick) {
		t.Fatal("first task cycle must be queued")
	}
	if enqueueAgentTaskCycle(kick) {
		t.Fatal("task queue must retain at most one pending cycle while the single writer is busy")
	}
	<-kick
	if !enqueueAgentTaskCycle(kick) {
		t.Fatal("task cycle must be queueable again after the pending epoch is consumed")
	}
}

func TestAgentSchedulerV2TaskLaneIsSingleWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kick := make(chan struct{}, 1)
	started := make(chan int, 2)
	release := make(chan struct{}, 2)
	var active atomic.Int32
	var maxActive atomic.Int32
	var cycles atomic.Int32

	done := make(chan struct{})
	go func() {
		defer close(done)
		runSingleWriterTaskLane(ctx, kick, func(context.Context) {
			current := active.Add(1)
			for {
				max := maxActive.Load()
				if current <= max || maxActive.CompareAndSwap(max, current) {
					break
				}
			}
			cycle := int(cycles.Add(1))
			started <- cycle
			<-release
			active.Add(-1)
		})
	}()

	if !enqueueAgentTaskCycle(kick) {
		t.Fatal("queue first cycle")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first cycle did not start")
	}
	// While cycle 1 is executing, exactly one newer inventory epoch may wait.
	if !enqueueAgentTaskCycle(kick) {
		t.Fatal("one pending task cycle must be accepted while writer is active")
	}
	if enqueueAgentTaskCycle(kick) {
		t.Fatal("a second pending task cycle must be coalesced")
	}
	release <- struct{}{}
	select {
	case cycle := <-started:
		if cycle != 2 {
			t.Fatalf("second cycle=%d", cycle)
		}
	case <-time.After(time.Second):
		t.Fatal("pending cycle did not run")
	}
	release <- struct{}{}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("task lane did not stop after context cancellation")
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("task lane allowed concurrent writers: max active=%d", got)
	}
}

func TestAgentSchedulerV2IncludesWorkloadLogProcessor(t *testing.T) {
	a := &agent{}
	processors := a.taskProcessors()
	seen := map[string]int{}
	for i, processor := range processors {
		seen[processor.name] = i
	}
	idx, ok := seen["workload logs"]
	if !ok {
		t.Fatal("workload log processor is missing from the single-writer task lane")
	}
	if _, ok := seen["cluster maintenance"]; !ok {
		t.Fatal("cluster maintenance processor missing")
	}
	if _, ok := seen["runtime certification"]; !ok {
		t.Fatal("runtime certification processor missing")
	}
	if idx <= seen["cluster maintenance"] || idx >= seen["runtime certification"] {
		t.Fatalf("workload log processor order=%d maintenance=%d certification=%d", idx, seen["cluster maintenance"], seen["runtime certification"])
	}
}

func TestComponentRuntimeCertificationGatewayInstallReadinessPartial(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	component := components["gateway-api"]
	rendered, err := catalog.RenderComponent(component, "4so-component-cert", "catrel_component")
	if err != nil {
		t.Fatal(err)
	}
	resources := make([]map[string]any, 0, len(rendered.Resources))
	for _, resource := range rendered.Resources {
		raw, _ := json.Marshal(resource)
		var cloned map[string]any
		_ = json.Unmarshal(raw, &cloned)
		delete(cloned, "status")
		meta, _ := cloned["metadata"].(map[string]any)
		labels, _ := meta["labels"].(map[string]any)
		if labels == nil {
			labels = map[string]any{}
			meta["labels"] = labels
		}
		labels["app.kubernetes.io/managed-by"] = "4so-platform-factory"
		labels["platform.4so.io/component"] = "gateway-api"
		labels["platform.4so.io/catalog-release-id"] = "catrel_component"
		labels["platform.4so.io/runtime-certification-profile"] = "COMPONENT_RUNTIME_V1"
		resources = append(resources, cloned)
	}
	objects := map[string]map[string]any{}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		switch request.Method {
		case http.MethodGet:
			if path == "/api/v1/nodes" {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"items":[{"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`)), Header: make(http.Header)}, nil
			}
			if path == "/api/v1/namespaces/kube-system/services/kube-dns" {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"metadata":{"name":"kube-dns"}}`)), Header: make(http.Header)}, nil
			}
			if strings.HasPrefix(path, "/apis/gateway.networking.k8s.io/") {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"items":[]}`)), Header: make(http.Header)}, nil
			}
			object, ok := objects[path]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			raw, _ := json.Marshal(object)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
		case http.MethodPost:
			var object map[string]any
			if err := json.NewDecoder(request.Body).Decode(&object); err != nil {
				t.Fatal(err)
			}
			meta, _ := object["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			objectPath := strings.TrimRight(path, "/") + "/" + url.PathEscape(name)
			if _, exists := objects[objectPath]; exists {
				return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			meta["uid"] = "uid-" + name
			meta["resourceVersion"] = "1"
			if object["kind"] == "CustomResourceDefinition" {
				object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Established", "status": "True"}}}
			}
			objects[objectPath] = object
			return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodPatch:
			current, ok := objects[path]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			var patch map[string]any
			if err := json.NewDecoder(request.Body).Decode(&patch); err != nil {
				t.Fatal(err)
			}
			currentMeta, _ := current["metadata"].(map[string]any)
			uid, _ := currentMeta["uid"].(string)
			if strings.Contains(request.Header.Get("Content-Type"), "apply-patch") {
				patchMeta, _ := patch["metadata"].(map[string]any)
				patchMeta["uid"] = uid
				patchMeta["resourceVersion"] = "3"
				if patch["kind"] == "CustomResourceDefinition" {
					patch["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Established", "status": "True"}}}
				}
				objects[path] = patch
			} else {
				patchMeta, _ := patch["metadata"].(map[string]any)
				patchLabels, _ := patchMeta["labels"].(map[string]any)
				labels, _ := currentMeta["labels"].(map[string]any)
				for k, v := range patchLabels {
					if v == nil {
						delete(labels, k)
					} else {
						labels[k] = v
					}
				}
				patchAnnotations, _ := patchMeta["annotations"].(map[string]any)
				annotations, _ := currentMeta["annotations"].(map[string]any)
				if annotations == nil {
					annotations = map[string]any{}
					currentMeta["annotations"] = annotations
				}
				for k, v := range patchAnnotations {
					if v == nil {
						delete(annotations, k)
					} else {
						annotations[k] = v
					}
				}
				currentMeta["resourceVersion"] = "2"
			}
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case http.MethodDelete:
			if _, ok := objects[path]; !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			delete(objects, path)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected component certification kube request %s %s", request.Method, path)
			return nil, nil
		}
	})}
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	task := controlplane.RuntimeCertificationTask{
		RunID: "rtc_component", RunRevision: 2, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour),
		Profile: controlplane.RuntimeCertificationComponentV1, Phase: controlplane.RuntimeCertificationPhaseInstall,
		Namespace: "4so-component-cert", InventoryDigest: digest("1"), EnvironmentFingerprint: digest("2"),
		CatalogReleaseID: "catrel_component", ComponentName: "gateway-api", ComponentRelease: component.Spec.Release,
		ManifestDigest: digest("3"), SourceLockDigest: component.Spec.Source.SourceLockDigest, RenderedDigest: digest("4"),
		TaskAttempt: 1, CleanupToken: "cleanup-component", Resources: resources,
	}
	a := &agent{kube: client}
	install := a.runRuntimeCertification(context.Background(), task)
	if !install.Success || install.Blocked {
		t.Fatalf("component install=%+v", install)
	}
	runContract := controlplane.RuntimeCertificationRun{ResourceCount: len(resources), Profile: task.Profile, Phase: controlplane.RuntimeCertificationPhaseInstall, ComponentName: task.ComponentName, ComponentRelease: task.ComponentRelease}
	if err := controlplane.ValidateRuntimeCertificationResultShape(runContract, install); err != nil {
		t.Fatalf("component install result rejected: %v checks=%+v", err, install.Checks)
	}
	task.Phase = controlplane.RuntimeCertificationPhaseVerify
	task.RunRevision = 3
	task.TaskAttempt = 2
	task.InstallCheckpointDigest = digest("5")
	verify := a.runRuntimeCertification(context.Background(), task)
	if !verify.Success || verify.Blocked {
		t.Fatalf("component verify=%+v", verify)
	}
	runContract.Phase = controlplane.RuntimeCertificationPhaseVerify
	if err := controlplane.ValidateRuntimeCertificationResultShape(runContract, verify); err != nil {
		t.Fatalf("component verify result rejected: %v checks=%+v", err, verify.Checks)
	}
	task.Phase = controlplane.RuntimeCertificationPhaseFailure
	task.RunRevision = 4
	task.TaskAttempt = 3
	failure := a.runRuntimeCertification(context.Background(), task)
	if !failure.Success || failure.Blocked {
		t.Fatalf("component failure/recovery=%+v", failure)
	}
	runContract.Phase = controlplane.RuntimeCertificationPhaseFailure
	if err := controlplane.ValidateRuntimeCertificationResultShape(runContract, failure); err != nil {
		t.Fatalf("component failure/recovery result rejected: %v checks=%+v", err, failure.Checks)
	}
	task.Phase = controlplane.RuntimeCertificationPhaseRemove
	task.RunRevision = 5
	task.TaskAttempt = 4
	remove := a.runRuntimeCertification(context.Background(), task)
	if !remove.Success || remove.Blocked {
		t.Fatalf("component remove=%+v", remove)
	}
	runContract.Phase = controlplane.RuntimeCertificationPhaseRemove
	if err := controlplane.ValidateRuntimeCertificationResultShape(runContract, remove); err != nil {
		t.Fatalf("component remove result rejected: %v checks=%+v", err, remove.Checks)
	}
	if len(objects) != 0 {
		t.Fatalf("component remove left orphaned resources: %d", len(objects))
	}
}

func TestComponentRuntimeRemoveRefusesCRDWithLiveInstances(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previousTokenPath }()
	components, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	component := components["gateway-api"]
	rendered, err := catalog.RenderComponent(component, "4so-component-cert", "catrel_component")
	if err != nil {
		t.Fatal(err)
	}
	var resource map[string]any
	for _, candidate := range rendered.Resources {
		if candidate["kind"] == "CustomResourceDefinition" {
			raw, _ := json.Marshal(candidate)
			_ = json.Unmarshal(raw, &resource)
			break
		}
	}
	if resource == nil {
		t.Fatal("gateway-api fixture has no CRD")
	}
	delete(resource, "status")
	meta, _ := resource["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
		meta["labels"] = labels
	}
	labels["app.kubernetes.io/managed-by"] = "4so-platform-factory"
	labels["platform.4so.io/component"] = "gateway-api"
	labels["platform.4so.io/catalog-release-id"] = "catrel_component"
	labels["platform.4so.io/runtime-certification-profile"] = "COMPONENT_RUNTIME_V1"
	meta["uid"] = "uid-live-crd"
	meta["resourceVersion"] = "7"
	resource["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Established", "status": "True"}}}
	task := controlplane.RuntimeCertificationTask{Profile: controlplane.RuntimeCertificationComponentV1, Phase: controlplane.RuntimeCertificationPhaseRemove, Namespace: "4so-component-cert", CatalogReleaseID: "catrel_component", ComponentName: "gateway-api", ComponentRelease: component.Spec.Release, Resources: []map[string]any{resource}}
	path, _, err := certificationResourcePath(task, resource)
	if err != nil {
		t.Fatal(err)
	}
	listPath, ok := componentRuntimeCRDInstanceListPath(resource)
	if !ok {
		t.Fatal("CRD instance list path not derived")
	}
	deleted := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == path:
			raw, _ := json.Marshal(resource)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
		case request.Method == http.MethodGet && request.URL.Path == listPath:
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"items":[{"metadata":{"name":"live-user-resource"}}]}`)), Header: make(http.Header)}, nil
		case request.Method == http.MethodDelete:
			deleted = true
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		default:
			t.Fatalf("unexpected kube request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	a := &agent{kube: client}
	result := a.removeComponentRuntimeCertification(context.Background(), task)
	if result.Success || result.Error == "" || deleted {
		t.Fatalf("unsafe CRD removal was not rejected: result=%+v deleted=%t", result, deleted)
	}
	if len(result.Checks) != 1 || result.Checks[0].Status == "PASS" || !strings.Contains(result.Checks[0].Detail, "live custom resources") {
		t.Fatalf("unexpected remove safety evidence: %+v", result.Checks)
	}
}

func TestRuntimeCertificationExtendedPhasesAreComponentOnly(t *testing.T) {
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	task := controlplane.RuntimeCertificationTask{
		RunID: "rtc_noncomponent", RunRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour),
		Profile: controlplane.RuntimeCertificationTargetV1, Phase: controlplane.RuntimeCertificationPhaseRemove,
		Namespace: "4so-cert", InventoryDigest: digest("1"), EnvironmentFingerprint: digest("2"), CatalogReleaseID: "catrel", ManifestDigest: digest("3"), SourceLockDigest: digest("4"), RenderedDigest: digest("5"), TaskAttempt: 1, CleanupToken: "cleanup", Resources: []map[string]any{{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "4so-cert", "labels": map[string]any{"app.kubernetes.io/managed-by": "4so-platform-factory"}}}},
	}
	if err := validateRuntimeCertificationTask(task); err == nil || !strings.Contains(err.Error(), "component-only") {
		t.Fatalf("non-component extended phase was accepted: %v", err)
	}
}

func TestVMwareProviderProfileRequiresCAPVClusterAndMachineTemplates(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()
	task := controlplane.ProviderProfileTask{ProfileID: "prv_vmware", ProfileRevision: 1, TaskFenceToken: 1, LeaseExpiresAt: time.Now().Add(time.Hour), Namespace: "4so-provider-system", ClusterClassName: "vmware-prod", WorkerClassName: "workers", InfrastructureProvider: "vmware"}
	class := map[string]any{
		"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "ClusterClass",
		"metadata": map[string]any{"name": "vmware-prod", "namespace": "4so-provider-system"},
		"spec": map[string]any{
			"infrastructure": map[string]any{"templateRef": map[string]any{"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1", "kind": "VSphereClusterTemplate", "name": "vmware-cluster"}},
			"controlPlane": map[string]any{"machineInfrastructure": map[string]any{"templateRef": map[string]any{"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1", "kind": "VSphereMachineTemplate", "name": "vmware-control-plane"}}},
			"workers": map[string]any{"machineDeployments": []any{map[string]any{"class": "workers", "infrastructure": map[string]any{"templateRef": map[string]any{"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1", "kind": "VSphereMachineTemplate", "name": "vmware-worker"}}}}},
		},
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		raw, _ := json.Marshal(class)
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
	})}
	a := &agent{kube: client}
	result := a.executeProviderProfileTask(context.Background(), task)
	if !result.Success {
		t.Fatalf("CAPV profile should verify: %+v", result)
	}
	class["spec"].(map[string]any)["infrastructure"] = map[string]any{"ref": map[string]any{"apiGroup": "infrastructure.cluster.x-k8s.io", "kind": "VSphereClusterTemplate", "name": "legacy"}}
	result = a.executeProviderProfileTask(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "v1beta2 infrastructure.templateRef") {
		t.Fatalf("legacy v1beta1 ClusterClass reference shape was accepted: %+v", result)
	}
	class["spec"].(map[string]any)["infrastructure"] = map[string]any{"templateRef": map[string]any{"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1", "kind": "OtherClusterTemplate", "name": "bad"}}
	result = a.executeProviderProfileTask(context.Background(), task)
	if result.Success || !strings.Contains(result.Error, "VSphereClusterTemplate") {
		t.Fatalf("unsafe CAPV profile result=%+v", result)
	}
}


func TestProviderProfileTaskInfrastructureProviderAllowlist(t *testing.T) {
	base := controlplane.ProviderProfileTask{
		ProfileID: "prv_test", ProfileRevision: 1, TaskFenceToken: 1,
		LeaseExpiresAt: time.Now().Add(time.Hour), Namespace: "4so-provider-system",
		ClusterClassName: "cloud-prod", WorkerClassName: "workers",
	}
	for _, provider := range []string{"", "unspecified", "vmware", "aws", "azure", "gcp"} {
		task := base
		task.InfrastructureProvider = provider
		if err := validateProviderProfileTask(task); err != nil {
			t.Fatalf("admitted provider %q rejected: %v", provider, err)
		}
	}
	task := base
	task.InfrastructureProvider = "unknown-cloud"
	if err := validateProviderProfileTask(task); err == nil {
		t.Fatal("unknown infrastructure provider was admitted")
	}
}

func TestPublicCloudProviderProfilesRequireProviderSpecificClusterClassTemplates(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	cases := []struct {
		provider    string
		clusterKind string
		machineKind string
	}{
		{provider: "aws", clusterKind: "AWSClusterTemplate", machineKind: "AWSMachineTemplate"},
		{provider: "azure", clusterKind: "AzureClusterTemplate", machineKind: "AzureMachineTemplate"},
		{provider: "gcp", clusterKind: "GCPClusterTemplate", machineKind: "GCPMachineTemplate"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			task := controlplane.ProviderProfileTask{
				ProfileID: "prv_" + tc.provider, ProfileRevision: 1, TaskFenceToken: 1,
				LeaseExpiresAt: time.Now().Add(time.Hour), Namespace: "4so-provider-system",
				ClusterClassName: tc.provider + "-prod", WorkerClassName: "workers",
				InfrastructureProvider: tc.provider,
			}
			class := map[string]any{
				"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "ClusterClass",
				"metadata": map[string]any{"name": tc.provider + "-prod", "namespace": "4so-provider-system"},
				"spec": map[string]any{
					"infrastructure": map[string]any{"templateRef": map[string]any{"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1", "kind": tc.clusterKind, "name": tc.provider + "-cluster"}},
					"controlPlane": map[string]any{"machineInfrastructure": map[string]any{"templateRef": map[string]any{"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1", "kind": tc.machineKind, "name": tc.provider + "-control-plane"}}},
					"workers": map[string]any{"machineDeployments": []any{map[string]any{"class": "workers", "infrastructure": map[string]any{"templateRef": map[string]any{"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1", "kind": tc.machineKind, "name": tc.provider + "-worker"}}}}},
				},
			}
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				raw, _ := json.Marshal(class)
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
			})}
			a := &agent{kube: client}
			result := a.executeProviderProfileTask(context.Background(), task)
			if !result.Success {
				t.Fatalf("%s profile should verify: %+v", tc.provider, result)
			}

			class["spec"].(map[string]any)["infrastructure"] = map[string]any{"templateRef": map[string]any{"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1", "kind": "VSphereClusterTemplate", "name": "cross-provider"}}
			result = a.executeProviderProfileTask(context.Background(), task)
			if result.Success || !strings.Contains(result.Error, tc.clusterKind) {
				t.Fatalf("%s cross-provider ClusterClass was accepted: %+v", tc.provider, result)
			}
		})
	}
}


func publicCloudProviderTaskForTest(provider, action, pending string) controlplane.ProviderClusterTask {
	id := "pcl_" + provider
	name := "pf-" + provider + "-123456"
	digest := "sha256:" + strings.Repeat("d", 64)
	resource := map[string]any(nil)
	if action == "APPLY" {
		resource = map[string]any{
			"apiVersion": "cluster.x-k8s.io/v1beta2",
			"kind": "Cluster",
			"metadata": map[string]any{
				"name": name, "namespace": "4so-provider-system",
				"labels": map[string]any{"platform.4so.io/managed": "true", "platform.4so.io/provider-cluster-id": id},
				"annotations": map[string]any{"platform.4so.io/desired-digest": digest},
			},
			"spec": map[string]any{"topology": map[string]any{"classRef": map[string]any{"name": provider + "-prod", "namespace": "4so-provider-system"}, "version": "v1.33.2"}},
		}
	}
	return controlplane.ProviderClusterTask{
		ProviderClusterID: id, ClusterRevision: 2, TaskFenceToken: 7,
		LeaseExpiresAt: time.Now().Add(time.Hour), Action: action, PendingAction: pending,
		Namespace: "4so-provider-system", ResourceName: name, DesiredDigest: digest,
		InfrastructureProvider: provider,
		CredentialRef: "external-secret://4so-provider-system/" + provider + "-prod",
		Resource: resource,
	}
}

func ownedPublicCloudClusterForTest(task controlplane.ProviderClusterTask) map[string]any {
	object := map[string]any{}
	raw, _ := json.Marshal(task.Resource)
	_ = json.Unmarshal(raw, &object)
	metadata, _ := object["metadata"].(map[string]any)
	metadata["uid"] = "uid-" + task.ProviderClusterID
	metadata["resourceVersion"] = "17"
	object["status"] = map[string]any{"phase": "Provisioned", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}
	return object
}

func TestPublicCloudProviderAmbiguousApplyRequiresReadbackAndNeverReplays(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil { t.Fatal(err) }
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	for _, provider := range []string{"aws", "azure", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			task := publicCloudProviderTaskForTest(provider, "APPLY", "PROVISION")
			mutations := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.Method {
				case http.MethodGet:
					return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
				case http.MethodPost:
					mutations++
					return nil, fmt.Errorf("connection reset after request submission")
				default:
					t.Fatalf("unexpected %s %s", request.Method, request.URL.Path)
					return nil, nil
				}
			})}
			result := (&agent{kube: client}).executeProviderClusterTask(context.Background(), task)
			if result.Success || !result.RecoveryRequired || mutations != 1 || !strings.Contains(result.Error, "readback") {
				t.Fatalf("%s ambiguous result=%+v mutations=%d", provider, result, mutations)
			}
		})
	}
}

func TestPublicCloudProviderAmbiguousApplyMayCloseOnlyFromAuthoritativeReadback(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil { t.Fatal(err) }
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	task := publicCloudProviderTaskForTest("aws", "APPLY", "PROVISION")
	gets, mutations := 0, 0
	owned := ownedPublicCloudClusterForTest(task)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodGet:
			gets++
			if gets < 3 {
				return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
			raw, _ := json.Marshal(owned)
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
		case http.MethodPost:
			mutations++
			return nil, fmt.Errorf("transport timeout after request submission")
		default:
			t.Fatalf("unexpected %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	result := (&agent{kube: client}).executeProviderClusterTask(context.Background(), task)
	if !result.Success || result.RecoveryRequired || result.ObservedDigest != task.DesiredDigest || mutations != 1 || gets != 3 {
		t.Fatalf("readback resolution result=%+v gets=%d mutations=%d", result, gets, mutations)
	}
}

func TestPublicCloudProviderRejectsUnsafeCredentialBeforeMutation(t *testing.T) {
	task := publicCloudProviderTaskForTest("azure", "APPLY", "PROVISION")
	task.CredentialRef = "inline-client-secret"
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unexpected request")
	})}
	result := (&agent{kube: client}).executeProviderClusterTask(context.Background(), task)
	if result.Success || result.RecoveryRequired || calls != 0 || !strings.Contains(result.Error, "credential reference") {
		t.Fatalf("unsafe credential result=%+v calls=%d", result, calls)
	}
}

func TestProviderInspectDeleteIsReadOnly(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "service-account-token")
	if err := os.WriteFile(tokenFile, []byte("service-account"), 0o600); err != nil { t.Fatal(err) }
	previous := serviceAccountTokenPath
	serviceAccountTokenPath = tokenFile
	defer func() { serviceAccountTokenPath = previous }()

	task := publicCloudProviderTaskForTest("gcp", "INSPECT_DELETE", "DELETE")
	task.Resource = nil
	mutations := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			mutations++
			return nil, fmt.Errorf("unexpected mutation %s", request.Method)
		}
		return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	result := (&agent{kube: client}).executeProviderClusterTask(context.Background(), task)
	if !result.Success || !result.Deleted || result.RecoveryRequired || mutations != 0 {
		t.Fatalf("inspect-delete result=%+v mutations=%d", result, mutations)
	}
}
