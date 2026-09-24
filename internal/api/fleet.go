package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/targetmodel"
	"sort"
	"strings"
	"time"
)

type createClusterImportInput struct {
	ProjectID        string `json:"projectId"`
	Name             string `json:"name"`
	DisplayName      string `json:"displayName"`
	ExpiresInMinutes int    `json:"expiresInMinutes,omitempty"`
}
type claimClusterInput struct {
	Token        string `json:"token"`
	ExternalUID  string `json:"externalUid"`
	AgentVersion string `json:"agentVersion"`
}
type inventoryInput struct {
	ObservedAt                  time.Time                                    `json:"observedAt"`
	ExternalUID                 string                                       `json:"externalUid"`
	Distribution                string                                       `json:"distribution"`
	DistributionEvidenceMethod  string                                       `json:"distributionEvidenceMethod"`
	DistributionEvidenceUID     string                                       `json:"distributionEvidenceUid"`
	DistributionEvidenceVersion string                                       `json:"distributionEvidenceVersion"`
	KubernetesVersion           string                                       `json:"kubernetesVersion"`
	Nodes                       []controlplane.ClusterNode                   `json:"nodes"`
	AddOns                      []controlplane.ClusterAddOn                  `json:"addOns"`
	StorageClasses              []controlplane.ClusterStorageClass           `json:"storageClasses"`
	Capacity                    controlplane.ClusterCapacity                 `json:"capacity"`
	Certificates                []controlplane.ClusterCertificateObservation `json:"certificates"`
	Networking                  controlplane.ClusterNetworking               `json:"networking"`
	WorkloadExplorer            controlplane.ClusterWorkloadExplorer         `json:"workloadExplorer"`
	APIResources                []controlplane.ClusterAPIResourceObservation `json:"apiResources"`
	CRDs                        []controlplane.ClusterCRDObservation         `json:"crds"`
	APIDiscoveryComplete        bool                                         `json:"apiDiscoveryComplete"`
	CRDDiscoveryComplete        bool                                         `json:"crdDiscoveryComplete"`
	SchemaDiscoveryVersion      string                                       `json:"schemaDiscoveryVersion"`
	SchemaDiscoveryDigest       string                                       `json:"schemaDiscoveryDigest"`
	SchemaDiscoveryComplete     bool                                         `json:"schemaDiscoveryComplete"`
	Capabilities                []string                                     `json:"capabilities"`
}
type heartbeatInput struct {
	AgentVersion string `json:"agentVersion"`
	ExternalUID  string `json:"externalUid"`
}

type targetRBACRevocationAcknowledgementInput struct {
	FenceDigest string `json:"fenceDigest"`
}

func randomCredential(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func agentCredential(enrollment, importID string) string {
	mac := hmac.New(sha256.New, []byte(enrollment))
	_, _ = mac.Write([]byte("4so-fleet-agent:" + importID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func credentialDigest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func agentBearer(r *http.Request) (string, error) {
	v := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(v, "Bearer ") {
		return "", fmt.Errorf("agent bearer token is required")
	}
	v = strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
	if len(v) < 32 {
		return "", fmt.Errorf("agent bearer token is invalid")
	}
	return v, nil
}
func (s *Server) createClusterImport(w http.ResponseWriter, r *http.Request) {
	actor, e := actorID(r)
	if e != nil {
		writeError(w, 401, "ACTOR_REQUIRED", e.Error())
		return
	}
	var in createClusterImportInput
	if e = decodeJSON(w, r, &in); e != nil {
		writeError(w, 400, "INVALID_REQUEST", e.Error())
		return
	}
	if _, e = s.requireProjectAccess(r, in.ProjectID, organizationWrite); e != nil {
		writeScopeError(w, e)
		return
	}
	ttl := in.ExpiresInMinutes
	if ttl == 0 {
		ttl = 30
	}
	if ttl < 5 || ttl > 1440 {
		writeError(w, 422, "VALIDATION_FAILED", "expiresInMinutes must be between 5 and 1440")
		return
	}
	if s.fleetAgentImage == "" || !strings.Contains(s.fleetAgentImage, "@sha256:") {
		writeError(w, http.StatusServiceUnavailable, "FLEET_AGENT_UNAVAILABLE", "digest-pinned fleet agent image is not configured")
		return
	}
	if s.runtimeProbeImage == "" || !strings.Contains(s.runtimeProbeImage, "@sha256:") {
		writeError(w, http.StatusServiceUnavailable, "RUNTIME_PROBE_UNAVAILABLE", "digest-pinned runtime probe image is not configured")
		return
	}
	base := strings.TrimRight(s.fleetPublicURL, "/")
	if !validFleetPublicURL(base) {
		writeError(w, http.StatusServiceUnavailable, "FLEET_PUBLIC_URL_UNAVAILABLE", "a valid configured HTTPS public URL is required for cluster import")
		return
	}
	token, e := randomCredential(32)
	if e != nil {
		writeError(w, 500, "TOKEN_GENERATION_FAILED", "could not generate enrollment token")
		return
	}
	v, e := s.store.CreateClusterImport(r.Context(), controlplane.ClusterImport{ProjectID: in.ProjectID, Name: in.Name, DisplayName: in.DisplayName, TokenDigest: credentialDigest(token), ExpiresAt: time.Now().UTC().Add(time.Duration(ttl) * time.Minute)}, actor)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	manifest := renderClusterImportManifest(base, v.ID, v.AgentServiceAccount, token, s.fleetAgentImage, s.runtimeProbeImage, s.publicCAPEM)
	writeJSON(w, 201, map[string]any{"import": v, "enrollmentToken": token, "manifest": manifest, "warning": "The enrollment token is shown once. Approve the import before applying the manifest to the target cluster."})
}
func validFleetPublicURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
}

func renderClusterImportManifest(base, id, serviceAccountName, token, image, probeImage, caPEM string) string {
	if strings.TrimSpace(serviceAccountName) == "" {
		serviceAccountName = "4so-platform-agent"
	}
	caBlock, caEnv, caVolumeMount, caVolume := "", "", "", ""
	if strings.TrimSpace(caPEM) != "" {
		indented := strings.ReplaceAll(strings.TrimSpace(caPEM), "\n", "\n    ")
		caBlock = fmt.Sprintf(`---
apiVersion: v1
kind: ConfigMap
metadata:
  name: 4so-platform-hub-ca
  namespace: 4so-platform-agent
data:
  ca.crt: |
    %s
`, indented)
		caEnv = `
        - name: PLATFORM_HUB_CA_FILE
          value: /etc/4so-platform/ca.crt`
		caVolumeMount = `
        - name: hub-ca
          mountPath: /etc/4so-platform
          readOnly: true`
		caVolume = `
      - name: hub-ca
        configMap:
          name: 4so-platform-hub-ca`
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: 4so-platform-agent
%s---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: 4so-platform-agent
  labels:
    platform.4so.io/managed: "true"
    platform.4so.io/enrollment-principal: "true"
---
apiVersion: v1
kind: Secret
metadata:
  name: 4so-platform-agent-bootstrap
  namespace: 4so-platform-agent
type: Opaque
stringData:
  hubURL: %q
  importID: %q
  enrollmentToken: %q
---
apiVersion: v1
kind: Secret
metadata:
  name: 4so-platform-agent-credential
  namespace: 4so-platform-agent
type: Opaque
stringData:
  token: ""
  clusterId: ""
---
apiVersion: v1
kind: Secret
metadata:
  name: 4so-platform-agent-certificate
  namespace: 4so-platform-agent
type: Opaque
stringData:
  tls.crt: ""
  tls.key: ""
  clusterId: ""
  notAfter: ""
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: 4so-platform-agent-credential
  namespace: 4so-platform-agent
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["4so-platform-agent-credential", "4so-platform-agent-certificate", "4so-platform-agent-bootstrap"]
  verbs: ["get", "patch", "update"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["4so-platform-mutation-activation"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-agent-credential
  namespace: 4so-platform-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-agent-credential
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: 4so-platform-agent-readonly
rules:
- apiGroups: [""]
  resources: ["nodes", "services"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["persistentvolumeclaims", "events"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["namespaces"]
  resourceNames: ["kube-system"]
  verbs: ["get"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
  verbs: ["get", "list"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list"]
- apiGroups: ["storage.k8s.io"]
  resources: ["storageclasses"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["rolebindings", "clusterrolebindings"]
  verbs: ["get", "list"]
- apiGroups: ["config.openshift.io"]
  resources: ["clusterversions"]
  resourceNames: ["version"]
  verbs: ["get"]
- apiGroups: ["snapshot.storage.k8s.io"]
  resources: ["volumesnapshotclasses"]
  verbs: ["get", "list"]
- apiGroups: ["velero.io"]
  resources: ["backupstoragelocations"]
  verbs: ["get", "list"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["get", "list"]
- apiGroups: ["authorization.k8s.io"]
  resources: ["selfsubjectaccessreviews"]
  verbs: ["create"]
- nonResourceURLs: ["/api", "/api/*", "/apis", "/apis/*", "/openapi", "/openapi/*"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-platform-agent-readonly
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-platform-agent-readonly
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: 4so-platform-agent
  namespace: 4so-platform-agent
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: {app: 4so-platform-agent}
  template:
    metadata:
      labels: {app: 4so-platform-agent}
    spec:
      serviceAccountName: %s
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: agent
        image: %s
        imagePullPolicy: IfNotPresent
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        env:
        - name: PLATFORM_HUB_URL
          valueFrom: {secretKeyRef: {name: 4so-platform-agent-bootstrap, key: hubURL}}
        - name: PLATFORM_IMPORT_ID
          valueFrom: {secretKeyRef: {name: 4so-platform-agent-bootstrap, key: importID}}
        - name: PLATFORM_ENROLLMENT_TOKEN
          valueFrom: {secretKeyRef: {name: 4so-platform-agent-bootstrap, key: enrollmentToken}}
        - name: PLATFORM_AGENT_TOKEN_FILE
          value: /var/lib/4so-platform-agent/credential.json
        - name: PLATFORM_AGENT_NAMESPACE
          valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
        - name: PLATFORM_AGENT_SERVICE_ACCOUNT
          value: %s
        - name: PLATFORM_AGENT_CREDENTIAL_SECRET
          value: 4so-platform-agent-credential
        - name: PLATFORM_AGENT_CERTIFICATE_SECRET
          value: 4so-platform-agent-certificate
        - name: PLATFORM_AGENT_BOOTSTRAP_SECRET
          value: 4so-platform-agent-bootstrap
        - name: PLATFORM_RUNTIME_PROBE_IMAGE
          value: %s
        - name: PLATFORM_AGENT_IMAGE
          value: %s%s
        volumeMounts:
        - name: state
          mountPath: /var/lib/4so-platform-agent%s
      volumes:
      - name: state
        emptyDir: {}%s
`, caBlock, serviceAccountName, base, id, token, serviceAccountName, serviceAccountName, serviceAccountName, image, serviceAccountName, probeImage, image, caEnv, caVolumeMount, caVolume)
}

func renderClusterMutationActivationManifest(clusterID, serviceAccountName, externalUID, inventoryDigest string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: 4so-platform-baseline
  labels:
    platform.4so.io/managed: "true"
    platform.4so.io/cluster-id: %q
---
apiVersion: v1
kind: Namespace
metadata:
  name: 4so-provider-system
  labels:
    platform.4so.io/managed: "true"
    platform.4so.io/cluster-id: %q
---
apiVersion: v1
kind: Namespace
metadata:
  name: 4so-platform-node-maintenance
  labels:
    platform.4so.io/managed: "true"
    platform.4so.io/cluster-id: %q
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: 4so-platform-mutation-activation
  namespace: 4so-platform-agent
  labels:
    platform.4so.io/managed: "true"
    platform.4so.io/cluster-id: %q
data:
  clusterId: %q
  externalUid: %q
  issuedFromInventoryDigest: %q
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: 4so-platform-provider-manager
  namespace: 4so-provider-system
  annotations:
    platform.4so.io/inventory-digest: %q
rules:
- apiGroups: ["cluster.x-k8s.io"]
  resources: ["clusterclasses"]
  verbs: ["get"]
- apiGroups: ["cluster.x-k8s.io"]
  resources: ["clusters"]
  verbs: ["get", "create", "update", "patch", "delete"]
- apiGroups: ["cluster.x-k8s.io"]
  resources: ["machines", "machinesets", "machinedeployments"]
  verbs: ["get", "list", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-provider-manager
  namespace: 4so-provider-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-provider-manager
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: 4so-platform-baseline-manager
  namespace: 4so-platform-baseline
  annotations:
    platform.4so.io/inventory-digest: %q
rules:
- apiGroups: [""]
  resources: ["resourcequotas", "limitranges", "serviceaccounts", "configmaps"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["batch"]
  resources: ["jobs"]
  verbs: ["get", "list", "create", "delete"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-baseline-manager
  namespace: 4so-platform-baseline
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-baseline-manager
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: 4so-platform-node-maintenance-job-manager
  namespace: 4so-platform-node-maintenance
  annotations:
    platform.4so.io/inventory-digest: %q
rules:
- apiGroups: ["batch"]
  resources: ["jobs"]
  verbs: ["get", "list", "create", "delete"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-node-maintenance-job-manager
  namespace: 4so-platform-node-maintenance
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-node-maintenance-job-manager
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: 4so-platform-agent-maintenance-manager
  annotations:
    platform.4so.io/inventory-digest: %q
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "patch", "update"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-platform-agent-maintenance-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-platform-agent-maintenance-manager
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: 4so-platform-agent-tenant-manager
  annotations:
    platform.4so.io/inventory-digest: %q
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "create", "patch", "delete"]
- apiGroups: [""]
  resources: ["resourcequotas", "limitranges", "serviceaccounts", "configmaps", "persistentvolumeclaims"]
  verbs: ["get", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "create", "update", "patch", "delete"]
- apiGroups: ["snapshot.storage.k8s.io"]
  resources: ["volumesnapshots"]
  verbs: ["get", "create", "update", "patch", "delete"]
- apiGroups: ["velero.io"]
  resources: ["schedules", "backups", "restores"]
  verbs: ["get", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-platform-agent-tenant-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-platform-agent-tenant-manager
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: 4so-openchoreo-executor
  namespace: 4so-platform-agent
  labels:
    platform.4so.io/managed: "true"
    platform.4so.io/runtime-role: openchoreo-executor
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: 4so-platform-runtime-job-launcher
  namespace: 4so-platform-agent
rules:
- apiGroups: ["batch"]
  resources: ["jobs"]
  verbs: ["get", "list", "create", "delete"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["4so-openchoreo-runtime", "4so-openchoreo-runtime-ownership"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["serviceaccounts"]
  resourceNames: ["4so-openchoreo-executor"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-runtime-job-launcher
  namespace: 4so-platform-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-runtime-job-launcher
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: 4so-platform-runtime-rbac-observer
rules:
- apiGroups: ["authorization.k8s.io"]
  resources: ["subjectaccessreviews"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-platform-runtime-rbac-observer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-platform-runtime-rbac-observer
subjects:
- kind: ServiceAccount
  name: %s
  namespace: 4so-platform-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: 4so-openchoreo-runtime-manager
rules:
- apiGroups: [""]
  resources: ["namespaces", "configmaps", "secrets", "serviceaccounts", "services"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["cert-manager.io"]
  resources: ["issuers", "certificates"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-openchoreo-runtime-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-openchoreo-runtime-manager
subjects:
- kind: ServiceAccount
  name: 4so-openchoreo-executor
  namespace: 4so-platform-agent
`, clusterID, clusterID, clusterID, clusterID, clusterID, externalUID, inventoryDigest, inventoryDigest, serviceAccountName, inventoryDigest, serviceAccountName, inventoryDigest, serviceAccountName, inventoryDigest, serviceAccountName, inventoryDigest, serviceAccountName, serviceAccountName, serviceAccountName)
}

// renderClusterRevocationRBACManifest is an idempotent target-side authorization
// fence. Hub credential revocation is authoritative immediately, but Kubernetes
// RBAC is local to the imported target. Applying this manifest removes every
// subject from the bindings installed by enrollment/mutation activation and
// marks the activation proof revoked without deleting historical Roles.
// A later explicit re-enrollment can safely re-bind read-only access to its new
// import-scoped principal before a new mutation activation is admitted.
func clusterMutationRevocationDigest(c controlplane.ManagedCluster) string {
	if strings.HasPrefix(strings.TrimSpace(c.MutationRBACIssuedForDigest), "sha256:") {
		return strings.TrimSpace(c.MutationRBACIssuedForDigest)
	}
	return strings.TrimSpace(c.InventoryDigest)
}

func renderClusterRevocationRBACManifest(clusterID, externalUID, inventoryDigest string, mutationActive bool) string {
	inventoryDigest = strings.TrimSpace(inventoryDigest)
	if !strings.HasPrefix(inventoryDigest, "sha256:") || len(inventoryDigest) != 71 {
		inventoryDigest = "sha256:" + strings.Repeat("0", 64)
	}
	base := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: 4so-platform-mutation-activation
  namespace: 4so-platform-agent
  labels:
    platform.4so.io/managed: "true"
    platform.4so.io/cluster-id: %q
data:
  clusterId: %q
  externalUid: %q
  issuedFromInventoryDigest: %q
  revoked: "true"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-agent-credential
  namespace: 4so-platform-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-agent-credential
subjects: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-platform-agent-readonly
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-platform-agent-readonly
subjects: []
`, clusterID, clusterID, externalUID, inventoryDigest)
	if !mutationActive {
		return base
	}
	return base + `---
apiVersion: v1
kind: Namespace
metadata:
  name: 4so-provider-system
  labels:
    platform.4so.io/managed: "true"
---
apiVersion: v1
kind: Namespace
metadata:
  name: 4so-platform-baseline
  labels:
    platform.4so.io/managed: "true"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-provider-manager
  namespace: 4so-provider-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-provider-manager
subjects: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-baseline-manager
  namespace: 4so-platform-baseline
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-baseline-manager
subjects: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-node-maintenance-job-manager
  namespace: 4so-platform-node-maintenance
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-node-maintenance-job-manager
subjects: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-platform-agent-maintenance-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-platform-agent-maintenance-manager
subjects: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-platform-agent-tenant-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-platform-agent-tenant-manager
subjects: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: 4so-platform-runtime-job-launcher
  namespace: 4so-platform-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: 4so-platform-runtime-job-launcher
subjects: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-platform-runtime-rbac-observer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-platform-runtime-rbac-observer
subjects: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: 4so-openchoreo-runtime-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: 4so-openchoreo-runtime-manager
subjects: []
`
}

func (s *Server) approveClusterImport(w http.ResponseWriter, r *http.Request) {
	current, e := s.store.GetClusterImport(r.Context(), r.PathValue("id"))
	if e != nil {
		writeStoreError(w, e)
		return
	}
	if _, e = s.requireProjectAccess(r, current.ProjectID, organizationWrite); e != nil {
		writeScopeError(w, e)
		return
	}
	actor, e := approvalActor(r, current.RequestedBy)
	if e != nil {
		writeApprovalError(w, e)
		return
	}
	rev, e := parseExpectedRevision(r)
	if e != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", e.Error())
		return
	}
	v, e := s.store.ApproveClusterImport(r.Context(), r.PathValue("id"), rev, actor)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) revokeClusterImport(w http.ResponseWriter, r *http.Request) {
	current, e := s.store.GetClusterImport(r.Context(), r.PathValue("id"))
	if e != nil {
		writeStoreError(w, e)
		return
	}
	if _, e = s.requireProjectAccess(r, current.ProjectID, organizationWrite); e != nil {
		writeScopeError(w, e)
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Confirm-Revoke")) != "revoke-cluster-import" {
		writeError(w, http.StatusPreconditionRequired, "REVOCATION_CONFIRMATION_REQUIRED", "X-Confirm-Revoke: revoke-cluster-import is required")
		return
	}
	actor, e := actorID(r)
	if e != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", e.Error())
		return
	}
	rev, e := parseExpectedRevision(r)
	if e != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", e.Error())
		return
	}
	v, e := s.store.RevokeClusterImport(r.Context(), current.ID, rev, actor)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) listClusterImports(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.ClusterImport, error)
	if pager, ok := s.store.(clusterImportPageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ClusterImport, error) {
			return pager.ListClusterImportsPage(r.Context(), ids, all, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.ClusterImport, error) {
		return s.store.ListClusterImports(r.Context(), projectID)
	}, page, func(item controlplane.ClusterImport) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeOperatorCollectionJSON(w, r, 200, v)
}
func (s *Server) getClusterImport(w http.ResponseWriter, r *http.Request) {
	v, e := s.store.GetClusterImport(r.Context(), r.PathValue("id"))
	if e != nil {
		writeStoreError(w, e)
		return
	}
	if _, e = s.requireProjectAccess(r, v.ProjectID, organizationRead); e != nil {
		writeScopeError(w, e)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) claimClusterImport(w http.ResponseWriter, r *http.Request) {
	var in claimClusterInput
	if e := decodeJSON(w, r, &in); e != nil {
		writeError(w, 400, "INVALID_REQUEST", e.Error())
		return
	}
	agent := agentCredential(in.Token, r.PathValue("id"))
	imp, c, e := s.store.ClaimClusterImport(r.Context(), r.PathValue("id"), credentialDigest(in.Token), credentialDigest(agent), in.ExternalUID, in.AgentVersion)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"import": imp, "cluster": c, "agentToken": agent})
}
func (s *Server) revokeManagedCluster(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	if err = requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "cluster credential revocation requires platform-admin")
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Confirm-Revoke")) != "revoke-cluster-agent" {
		writeError(w, http.StatusPreconditionRequired, "REVOKE_CONFIRMATION_REQUIRED", "X-Confirm-Revoke: revoke-cluster-agent is required")
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	cluster, imp, err := s.store.RevokeManagedCluster(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, cluster.Revision)
	serviceAccountName := strings.TrimSpace(imp.AgentServiceAccount)
	if serviceAccountName == "" {
		serviceAccountName = "4so-platform-agent"
	}
	fenceDigest := controlplane.ClusterTargetRBACRevocationFenceDigest(cluster)
	acknowledged := controlplane.ClusterTargetRBACRevocationAcknowledged(cluster)
	status := "APPLY_REQUIRED"
	next := "apply-target-rbac-revocation-fence-then-post-digest-bound-acknowledgement-before-reenrollment"
	if acknowledged {
		status = "ACKNOWLEDGED"
		next = "target-rbac-revocation-fence-acknowledged"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster":                         cluster,
		"clusterImport":                   imp,
		"agentCredentialRevoked":          true, // compatibility alias: Hub credential authority only
		"hubAgentCredentialRevoked":       true,
		"targetRBACRevocationStatus":      status,
		"targetRBACRevocationRequired":    !acknowledged,
		"targetRBACRevocationFenceDigest": fenceDigest,
		"revokedAgentServiceAccount":      serviceAccountName,
		"targetRBACRevocationManifest":    renderClusterRevocationRBACManifest(cluster.ID, cluster.ExternalUID, clusterMutationRevocationDigest(cluster), controlplane.ClusterMayHaveTargetMutationRBAC(cluster)),
		"next":                            next,
	})
}

func (s *Server) getClusterRevocationRBACManifest(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "cluster target RBAC revocation manifest requires platform-admin")
		return
	}
	c, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if c.ConnectionState != "REVOKED" {
		writeError(w, http.StatusConflict, "CLUSTER_NOT_REVOKED", "target RBAC revocation manifest is available only after Hub cluster credential revocation")
		return
	}
	imp, err := s.store.GetClusterImport(r.Context(), c.ImportID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	serviceAccountName := strings.TrimSpace(imp.AgentServiceAccount)
	if serviceAccountName == "" {
		serviceAccountName = "4so-platform-agent"
	}
	fenceDigest := controlplane.ClusterTargetRBACRevocationFenceDigest(c)
	acknowledged := controlplane.ClusterTargetRBACRevocationAcknowledged(c)
	status := "APPLY_REQUIRED"
	next := "apply this manifest to the revoked target, then POST the exact fence digest acknowledgement before re-enrollment"
	if acknowledged {
		status = "ACKNOWLEDGED"
		next = "target RBAC revocation fence acknowledgement recorded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"clusterId":                          c.ID,
		"externalUid":                        c.ExternalUID,
		"revokedAgentServiceAccount":         serviceAccountName,
		"targetRBACRevocationStatus":         status,
		"targetRBACRevocationRequired":       !acknowledged,
		"targetRBACRevocationFenceDigest":    fenceDigest,
		"targetRBACRevocationAcknowledgedAt": c.TargetRBACRevocationAcknowledgedAt,
		"targetRBACRevocationManifest":       renderClusterRevocationRBACManifest(c.ID, c.ExternalUID, clusterMutationRevocationDigest(c), controlplane.ClusterMayHaveTargetMutationRBAC(c)),
		"next":                               next,
	})
}

func (s *Server) acknowledgeClusterTargetRBACRevocation(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "target RBAC revocation acknowledgement requires platform-admin")
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in targetRBACRevocationAcknowledgementInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(in.FenceDigest), "sha256:") {
		writeError(w, http.StatusPreconditionRequired, "TARGET_RBAC_REVOCATION_FENCE_DIGEST_REQUIRED", "the exact targetRBACRevocationFenceDigest returned by the revocation manifest endpoint is required")
		return
	}
	c, err := s.store.AcknowledgeManagedClusterTargetRBACRevocation(r.Context(), r.PathValue("id"), rev, strings.TrimSpace(in.FenceDigest), actor)
	if err != nil {
		if errors.Is(err, controlplane.ErrValidation) {
			writeError(w, http.StatusPreconditionFailed, "TARGET_RBAC_REVOCATION_FENCE_DIGEST_MISMATCH", "fence digest does not match the current revoked cluster authority")
			return
		}
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, c.Revision)
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster":                         c,
		"targetRBACRevocationStatus":      "ACKNOWLEDGED",
		"targetRBACRevocationRequired":    false,
		"targetRBACRevocationFenceDigest": controlplane.ClusterTargetRBACRevocationFenceDigest(c),
		"acknowledgementIsPhysicalProof":  false,
		"next":                            "same-UID re-enrollment may now proceed; Physical Runtime certification remains independent",
	})
}

func (s *Server) listManagedClusters(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	var page func([]string, bool, *controlplane.CollectionCursor, int) ([]controlplane.ManagedCluster, error)
	if pager, ok := s.store.(managedClusterPageStore); ok {
		page = func(ids []string, all bool, cursor *controlplane.CollectionCursor, limit int) ([]controlplane.ManagedCluster, error) {
			return pager.ListManagedClustersPage(r.Context(), ids, all, cursor, limit)
		}
	}
	v, err := boundedProjectCollection(s, w, r, projectID, func() ([]controlplane.ManagedCluster, error) {
		return s.store.ListManagedClusters(r.Context(), projectID)
	}, page, func(item controlplane.ManagedCluster) string { return item.ProjectID })
	if err != nil {
		writeStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	rows := make([]map[string]any, 0, len(v))
	for _, c := range v {
		online := c.ConnectionState != "REVOKED" && c.LastSeenAt != nil && now.Sub(*c.LastSeenAt) <= 3*time.Minute
		rows = append(rows, map[string]any{"cluster": c, "target": targetmodel.ImportedTarget(c.Distribution), "online": online, "inventoryReadOnly": true, "controlledMutationEnabled": controlplane.ClusterTaskClaimAdmittedAt(c, time.Now().UTC()), "okdImportAdmitted": controlplane.ClusterHasCapability(c, controlplane.OKDImportAdmissionCapability), "reconnect": controlplane.ClusterReconnectAuthority(c, now), "mutationScope": "secure-namespace-foundation"})
	}
	writeOperatorCollectionJSON(w, r, 200, rows)
}
func (s *Server) getManagedCluster(w http.ResponseWriter, r *http.Request) {
	c, e := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if e != nil {
		writeStoreError(w, e)
		return
	}
	if _, e = s.requireProjectAccess(r, c.ProjectID, organizationRead); e != nil {
		writeScopeError(w, e)
		return
	}
	inv, err := optionalClusterInventory(s.store, r.Context(), c.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	certificates, err := s.store.ListAgentCertificates(r.Context(), c.ID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	activeCertificates := 0
	for _, certificate := range certificates {
		if certificate.State == controlplane.AgentCertificateActive {
			activeCertificates++
		}
	}
	agentAuthentication := "bootstrap-bearer"
	if activeCertificates > 0 {
		agentAuthentication = "mTLS"
	}
	online := c.ConnectionState != "REVOKED" && c.LastSeenAt != nil && time.Since(*c.LastSeenAt) <= 3*time.Minute
	mutationAdmitted := controlplane.ClusterTaskClaimAdmittedAt(c, time.Now().UTC())
	identityVerified := clusterHasCapabilityAPI(c.Capabilities, controlplane.TargetIdentityContinuityCapability)
	activationCurrent := controlplane.ClusterMutationRBACActivationCurrent(c)
	activeProof := clusterHasCapabilityAPI(c.Capabilities, controlplane.TargetMutationRBACActiveCapability)
	mutationCandidate := controlplane.ClusterMutationAdmissionEligible(c)
	okdHealth := controlplane.TranslateOKDHealth(inv)
	targetProfile := controlplane.CompileTargetProfile(inv, nil)
	reconnect := controlplane.ClusterReconnectAuthority(c, time.Now().UTC())
	writeJSON(w, 200, map[string]any{"cluster": c, "target": targetmodel.ImportedTarget(c.Distribution), "inventory": inv, "agentCertificates": certificates, "activeAgentCertificates": activeCertificates, "agentAuthentication": agentAuthentication, "online": online, "inventoryReadOnly": true, "identityContinuityVerified": identityVerified, "mutationEnabled": mutationAdmitted, "mutationAdmitted": mutationAdmitted, "mutationRBACActivationIssued": activationCurrent, "mutationRBACActivationRequired": mutationCandidate && identityVerified && !activationCurrent, "mutationRBACProofPending": mutationCandidate && identityVerified && activationCurrent && !activeProof, "okdImportAdmitted": controlplane.ClusterHasCapability(c, controlplane.OKDImportAdmissionCapability), "okdHealth": okdHealth, "targetProfile": targetProfile, "reconnect": reconnect, "mutationScope": "4so-platform-baseline", "genericMutationEnabled": false})
}

func (s *Server) writeClusterMutationRBACManifest(w http.ResponseWriter, c controlplane.ManagedCluster, imp controlplane.ClusterImport) {
	serviceAccountName := strings.TrimSpace(imp.AgentServiceAccount)
	if serviceAccountName == "" {
		serviceAccountName = "4so-platform-agent"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"clusterId":                 c.ID,
		"distribution":              c.Distribution,
		"inventoryDigest":           c.InventoryDigest,
		"mutationRBACBasisDigest":   c.MutationRBACBasisDigest,
		"activationIssuedForDigest": c.MutationRBACIssuedForDigest,
		"agentServiceAccount":       serviceAccountName,
		"activationIssued":          true,
		"manifest":                  renderClusterMutationActivationManifest(c.ID, serviceAccountName, c.ExternalUID, c.MutationRBACIssuedForDigest),
		"next":                      "apply this manifest to the target, then wait for the next inventory report to prove target-mutation-rbac-active",
	})
}

func (s *Server) getClusterMutationRBACManifest(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, c.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	if c.ConnectionState == "REVOKED" {
		writeError(w, http.StatusConflict, "CLUSTER_REVOKED", "mutation RBAC activation is unavailable for a revoked cluster")
		return
	}
	if !controlplane.ClusterMutationRBACActivationCurrent(c) {
		writeError(w, http.StatusConflict, "TARGET_MUTATION_ACTIVATION_NOT_ISSUED", "no current digest-bound mutation RBAC activation has been issued; POST this endpoint to issue one")
		return
	}
	imp, err := s.store.GetClusterImport(r.Context(), c.ImportID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.writeClusterMutationRBACManifest(w, c, imp)
}

func (s *Server) issueClusterMutationRBACManifest(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, c.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", err.Error())
		return
	}
	c, imp, err := s.store.AuthorizeClusterMutationRBACActivation(r.Context(), c.ID, actor)
	if err != nil {
		if errors.Is(err, controlplane.ErrPrerequisite) {
			writeError(w, http.StatusConflict, "TARGET_MUTATION_NOT_ADMITTED", "fresh identity- and principal-attested inventory for an admitted target distribution is required before mutation RBAC can be activated")
			return
		}
		writeStoreError(w, err)
		return
	}
	s.writeClusterMutationRBACManifest(w, c, imp)
}

func clusterHasCapabilityAPI(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func (s *Server) reportClusterInventory(w http.ResponseWriter, r *http.Request) {
	agentDigest, e := s.agentCredentialDigest(r, r.PathValue("id"))
	if e != nil {
		writeError(w, 401, "AGENT_AUTH_REQUIRED", e.Error())
		return
	}
	var in inventoryInput
	if e = decodeJSON(w, r, &in); e != nil {
		writeError(w, 400, "INVALID_REQUEST", e.Error())
		return
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = time.Now().UTC()
	}
	sort.Strings(in.Capabilities)
	for i := range in.APIResources {
		sort.Strings(in.APIResources[i].Verbs)
	}
	sort.Slice(in.APIResources, func(i, j int) bool {
		if in.APIResources[i].APIVersion == in.APIResources[j].APIVersion {
			if in.APIResources[i].Kind == in.APIResources[j].Kind {
				return in.APIResources[i].Resource < in.APIResources[j].Resource
			}
			return in.APIResources[i].Kind < in.APIResources[j].Kind
		}
		return in.APIResources[i].APIVersion < in.APIResources[j].APIVersion
	})
	for i := range in.CRDs {
		sort.Slice(in.CRDs[i].Versions, func(a, b int) bool { return in.CRDs[i].Versions[a].Name < in.CRDs[i].Versions[b].Name })
	}
	sort.Slice(in.CRDs, func(i, j int) bool { return in.CRDs[i].Name < in.CRDs[j].Name })
	workloadExplorer, normalizeErr := controlplane.NormalizeClusterWorkloadExplorer(in.WorkloadExplorer)
	if normalizeErr != nil {
		writeError(w, http.StatusUnprocessableEntity, "WORKLOAD_EXPLORER_INVALID", normalizeErr.Error())
		return
	}
	in.WorkloadExplorer = workloadExplorer
	cluster, e := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if e != nil {
		writeStoreError(w, e)
		return
	}
	observedExternalUID := strings.TrimSpace(in.ExternalUID)
	identityContinuityVerified := observedExternalUID != "" && observedExternalUID == strings.TrimSpace(cluster.ExternalUID)
	if observedExternalUID != "" && !identityContinuityVerified {
		writeError(w, http.StatusConflict, "CLUSTER_IDENTITY_MISMATCH", "observed kube-system UID does not match the cluster identity bound at import claim")
		return
	}
	inv := controlplane.ClusterInventory{ObservedAt: in.ObservedAt, Distribution: in.Distribution, DistributionEvidenceMethod: in.DistributionEvidenceMethod, DistributionEvidenceUID: in.DistributionEvidenceUID, DistributionEvidenceVersion: in.DistributionEvidenceVersion, KubernetesVersion: in.KubernetesVersion, Nodes: in.Nodes, AddOns: in.AddOns, StorageClasses: in.StorageClasses, Capacity: in.Capacity, Certificates: in.Certificates, Networking: in.Networking, WorkloadExplorer: in.WorkloadExplorer, APIResources: in.APIResources, CRDs: in.CRDs, APIDiscoveryComplete: in.APIDiscoveryComplete, CRDDiscoveryComplete: in.CRDDiscoveryComplete, SchemaDiscoveryVersion: in.SchemaDiscoveryVersion, SchemaDiscoveryDigest: in.SchemaDiscoveryDigest, SchemaDiscoveryComplete: in.SchemaDiscoveryComplete, Capabilities: in.Capabilities}
	// Identity continuity is a server-owned authority marker. Never trust the
	// capability if an agent submits it itself. Mixed-version agents without
	// externalUid remain observable but are normalized to read-only.
	inv = controlplane.NormalizeClusterInventoryIdentityAuthority(inv, identityContinuityVerified)
	c, stored, e := s.store.UpsertClusterInventory(r.Context(), r.PathValue("id"), agentDigest, observedExternalUID, inv)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"cluster": c, "target": targetmodel.ImportedTarget(c.Distribution), "inventory": stored, "identityContinuityVerified": identityContinuityVerified})
}
func (s *Server) heartbeatCluster(w http.ResponseWriter, r *http.Request) {
	agentDigest, e := s.agentCredentialDigest(r, r.PathValue("id"))
	if e != nil {
		writeError(w, 401, "AGENT_AUTH_REQUIRED", e.Error())
		return
	}
	var in heartbeatInput
	if e = decodeJSON(w, r, &in); e != nil {
		writeError(w, 400, "INVALID_REQUEST", e.Error())
		return
	}
	cluster, e := s.store.GetManagedCluster(r.Context(), r.PathValue("id"))
	if e != nil {
		writeStoreError(w, e)
		return
	}
	observedExternalUID := strings.TrimSpace(in.ExternalUID)
	if observedExternalUID != "" && observedExternalUID != strings.TrimSpace(cluster.ExternalUID) {
		writeError(w, http.StatusConflict, "CLUSTER_IDENTITY_MISMATCH", "observed kube-system UID does not match the cluster identity bound at import claim")
		return
	}
	// Legacy agents may omit externalUid. Acknowledge their heartbeat for
	// rolling compatibility, but do not let an identity-unverified heartbeat
	// refresh server liveness or mutation authority. Their inventory reports
	// remain sufficient to keep read-only observability online.
	if observedExternalUID == "" {
		writeJSON(w, 200, cluster)
		return
	}
	c, e := s.store.HeartbeatCluster(r.Context(), r.PathValue("id"), agentDigest, observedExternalUID, in.AgentVersion)
	if e != nil {
		writeStoreError(w, e)
		return
	}
	writeJSON(w, 200, c)
}
