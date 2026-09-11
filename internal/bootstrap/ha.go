package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/installation"
)

func (r *Runner) sshTarget(run Run, host string) string {
	user := normalizeSSHUser(run.Request.Infrastructure.SSHUser)
	return user + "@" + host
}

func (r *Runner) sshArgs(run Run, host string, command string) []string {
	return []string{
		"-i", r.sshKeyPath(),
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + r.sshKnownHostsPath(),
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "LogLevel=ERROR",
		r.sshTarget(run, host), command,
	}
}

func haShellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func (r *Runner) remoteRun(ctx context.Context, run Run, host, command string) error {
	return r.system.Run(ctx, "ssh", r.sshArgs(run, host, command), nil)
}

func (r *Runner) remoteCopy(ctx context.Context, run Run, source, host, destination string, mode string) error {
	sourcePath := source
	if simulated, ok := r.system.(*SimulatedSystem); ok && filepath.IsAbs(source) {
		if !strings.HasPrefix(source, r.bundleDir+string(filepath.Separator)) && !strings.HasPrefix(source, r.stateDir+string(filepath.Separator)) {
			sourcePath = simulated.path(source)
		}
	}
	file, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer file.Close()
	dir := filepath.Dir(destination)
	temp := destination + ".4so-stage"
	command := "set -eu; umask 077; mkdir -p " + haShellQuote(dir) + "; rm -f " + haShellQuote(temp) + "; cat > " + haShellQuote(temp) + "; chmod " + mode + " " + haShellQuote(temp) + "; mv -f " + haShellQuote(temp) + " " + haShellQuote(destination)
	return r.system.RunInput(ctx, "ssh", r.sshArgs(run, host, command), nil, file)
}

func (r *Runner) joinHAControllerNodes(ctx context.Context, run Run) error {
	if run.Request.ProfileID != "production-standard-ha" {
		return nil
	}
	for _, peer := range run.Request.Infrastructure.NodeAddresses[1:] {
		if err := validateSSHHost(peer); err != nil {
			return err
		}
		if err := r.remoteRun(ctx, run, peer, "mkdir -p /etc/rancher/rke2 /var/lib/4so-platform-installer/bundle/rke2 /var/lib/rancher/rke2/agent/images"); err != nil {
			return fmt.Errorf("prepare HA node %s: %w", peer, err)
		}
		installer, _ := safeBundlePath(r.bundleDir, "artifacts/"+filepath.Base("install.sh"))
		// Use the already staged installer because source names may differ.
		installer = "/var/lib/4so-platform-installer/bundle/rke2/install.sh"
		if err := r.remoteCopy(ctx, run, installer, peer, "/var/lib/4so-platform-installer/bundle/rke2/install.sh", "0700"); err != nil {
			return err
		}
		bundle, _, loadErr := LoadBundle(r.bundleDir)
		if loadErr != nil {
			return loadErr
		}
		for _, artifact := range bundle.Spec.RKE2.InstallArtifacts {
			source, _ := safeBundlePath(r.bundleDir, artifact.Path)
			if err := r.remoteCopy(ctx, run, source, peer, "/var/lib/4so-platform-installer/bundle/rke2/"+filepath.Base(artifact.Path), "0600"); err != nil {
				return err
			}
		}
		for _, artifact := range append(append([]Artifact{}, bundle.Spec.RKE2.ImageArchives...), bundle.Spec.Workloads.ImageArchives...) {
			source, _ := safeBundlePath(r.bundleDir, artifact.Path)
			if err := r.remoteCopy(ctx, run, source, peer, "/var/lib/rancher/rke2/agent/images/"+filepath.Base(artifact.Path), "0600"); err != nil {
				return err
			}
		}
		configSource := filepath.Join(r.stateDir, "ha-nodes", peer, "config.yaml")
		if err := r.remoteCopy(ctx, run, configSource, peer, "/etc/rancher/rke2/config.yaml", "0600"); err != nil {
			return fmt.Errorf("stage HA node %s configuration: %w", peer, err)
		}
		command := "chmod 700 /var/lib/4so-platform-installer/bundle/rke2/install.sh && INSTALL_RKE2_ARTIFACT_PATH=/var/lib/4so-platform-installer/bundle/rke2 INSTALL_RKE2_SKIP_DOWNLOAD=true INSTALL_RKE2_TYPE=server /bin/sh /var/lib/4so-platform-installer/bundle/rke2/install.sh && systemctl enable --now rke2-server"
		if err := r.remoteRun(ctx, run, peer, command); err != nil {
			return fmt.Errorf("join HA node %s: %w", peer, err)
		}
	}
	return nil
}

func (r *Runner) verifyHAQuorum(ctx context.Context, run Run) error {
	if run.Request.ProfileID != "production-standard-ha" || r.simulation {
		return nil
	}
	return waitUntil(ctx, 5*time.Second, 10*time.Minute, func() error {
		raw, err := r.system.Output(ctx, "/var/lib/rancher/rke2/bin/kubectl", []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "get", "nodes", "-o", "json"}, nil)
		if err != nil {
			return err
		}
		var result struct {
			Items []struct {
				Status struct {
					Conditions []struct{ Type, Status string } `json:"conditions"`
				} `json:"status"`
			} `json:"items"`
		}
		if err = json.Unmarshal(raw, &result); err != nil {
			return err
		}
		if len(result.Items) != 3 {
			return fmt.Errorf("expected 3 management nodes, got %d", len(result.Items))
		}
		ready := 0
		for _, item := range result.Items {
			for _, condition := range item.Status.Conditions {
				if condition.Type == "Ready" && condition.Status == "True" {
					ready++
					break
				}
			}
		}
		if ready != 3 {
			return fmt.Errorf("expected 3 Ready management nodes, got %d", ready)
		}
		return nil
	})
}

func (r *Runner) deployReplicatedStorage(ctx context.Context, run Run, bundle BundleManifest) error {
	if run.Request.ProfileID != "production-standard-ha" {
		return nil
	}
	source, err := safeBundlePath(r.bundleDir, bundle.Spec.Workloads.StorageManifest.Path)
	if err != nil {
		return err
	}
	destination := "/var/lib/rancher/rke2/server/manifests/4so-platform-replicated-storage.yaml"
	if err = r.system.CopyFile(source, destination, 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kc := "/etc/rancher/rke2/rke2.yaml"
	storageClass := strings.TrimSpace(run.Request.Infrastructure.StorageClass)
	return waitUntil(ctx, 3*time.Second, 10*time.Minute, func() error {
		raw, err := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kc, "get", "storageclass", storageClass, "-o", `jsonpath={.metadata.annotations.platform\.4so\.io/replicated}`}, nil)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(raw)) != "true" {
			return fmt.Errorf("storageClass %s is not certified as replicated", storageClass)
		}
		return nil
	})
}

func (r *Runner) deployPostgreSQLOperator(ctx context.Context, run Run, bundle BundleManifest) error {
	if run.Request.ProfileID != "production-standard-ha" {
		return nil
	}
	source, err := safeBundlePath(r.bundleDir, bundle.Spec.Workloads.CloudNativePGManifest.Path)
	if err != nil {
		return err
	}
	destination := "/var/lib/rancher/rke2/server/manifests/4so-platform-cloudnative-pg.yaml"
	if err = r.system.CopyFile(source, destination, 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	return waitUntil(ctx, 3*time.Second, 10*time.Minute, func() error {
		for _, crd := range []string{"clusters.postgresql.cnpg.io", "databases.postgresql.cnpg.io"} {
			if err := r.system.Run(ctx, "/var/lib/rancher/rke2/bin/kubectl", []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "get", "crd", crd}, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

func foundationManifestHA(bundle BundleManifest, password, keycloakDBPassword, forgejoDBPassword, forgejoPassword, identityPassword, sessionSecret, bootstrapToken, catalogSigningKey string, caPEM, tlsCertPEM, tlsKeyPEM, agentCAPEM, agentCAKeyPEM []byte, request installation.InstallRequest) string {
	storageClass := request.Infrastructure.StorageClass
	dsn := fmt.Sprintf("postgresql://platform:%s@platform-postgresql-rw:5432/platform_factory?sslmode=require", strings.ReplaceAll(password, "@", "%40"))
	issuer := "https://auth." + request.Network.DNSZone + "/realms/platform"
	redirect := strings.TrimRight(request.Network.PublicEndpoint, "/") + "/auth/callback"
	agentPublicURL := "https://agent." + strings.TrimSpace(request.Network.DNSZone)
	enc := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata: {name: platform-system}
---
apiVersion: v1
kind: Secret
metadata: {name: platform-postgresql-app, namespace: platform-system}
type: kubernetes.io/basic-auth
data:
  username: %s
  password: %s
---
apiVersion: v1
kind: Secret
metadata: {name: platform-keycloak-db, namespace: platform-system, labels: {cnpg.io/reload: "true"}}
type: kubernetes.io/basic-auth
data:
  username: %s
  password: %s
---
apiVersion: v1
kind: Secret
metadata: {name: platform-forgejo-db, namespace: platform-system, labels: {cnpg.io/reload: "true"}}
type: kubernetes.io/basic-auth
data:
  username: %s
  password: %s
---
apiVersion: v1
kind: Secret
metadata: {name: platform-database, namespace: platform-system}
type: Opaque
data:
  password: %s
  dsn: %s
---
apiVersion: v1
kind: Secret
metadata: {name: platform-internal-services, namespace: platform-system, annotations: {platform.4so.io/bootstrap-owner: "4so-platform-installer"}}
type: Opaque
data:
  forgejo-admin-password: %s
  identity-admin-password: %s
  identity-admin-email: %s
  session-secret: %s
  bootstrap-token: %s
  catalog-signing-key: %s
---
apiVersion: v1
kind: Secret
metadata: {name: platform-agent-mtls, namespace: platform-system}
type: Opaque
data:
  client-ca.crt: %s
  client-ca.key: %s
  tls.crt: %s
  tls.key: %s
---
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata: {name: platform-postgresql, namespace: platform-system}
spec:
  instances: 3
  imageName: %s
  primaryUpdateStrategy: unsupervised
  managed:
    roles:
      - name: keycloak
        ensure: present
        login: true
        superuser: false
        createdb: false
        createrole: false
        passwordSecret: {name: platform-keycloak-db}
      - name: forgejo
        ensure: present
        login: true
        superuser: false
        createdb: false
        createrole: false
        passwordSecret: {name: platform-forgejo-db}
  bootstrap:
    initdb:
      database: platform_factory
      owner: platform
      secret: {name: platform-postgresql-app}
  storage:
    storageClass: %s
    size: 50Gi
  affinity:
    enablePodAntiAffinity: true
    topologyKey: kubernetes.io/hostname
---
apiVersion: postgresql.cnpg.io/v1
kind: Database
metadata: {name: platform-keycloak-database, namespace: platform-system}
spec:
  name: keycloak
  owner: keycloak
  cluster: {name: platform-postgresql}
---
apiVersion: postgresql.cnpg.io/v1
kind: Database
metadata: {name: platform-forgejo-database, namespace: platform-system}
spec:
  name: forgejo
  owner: forgejo
  cluster: {name: platform-postgresql}
---
apiVersion: v1
kind: Service
metadata: {name: platform-postgresql, namespace: platform-system}
spec:
  type: ExternalName
  externalName: platform-postgresql-rw.platform-system.svc.cluster.local
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: platform-api, namespace: platform-system}
spec:
  minAvailable: 2
  selector: {matchLabels: {app: platform-api}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: platform-api, namespace: platform-system, annotations: {platform.4so.io/bootstrap-owner: "4so-platform-installer"}}
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate: {maxUnavailable: 0, maxSurge: 1}
  minReadySeconds: 10
  progressDeadlineSeconds: 600
  selector: {matchLabels: {app: platform-api}}
  template:
    metadata: {labels: {app: platform-api}, annotations: {platform.4so.io/bootstrap-restart: "initial"}}
    spec:
      terminationGracePeriodSeconds: 75
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector: {matchLabels: {app: platform-api}}
              topologyKey: kubernetes.io/hostname
      containers:
        - name: api
          image: %s
          imagePullPolicy: IfNotPresent
          env:
            - {name: PLATFORM_FACTORY_LISTEN, value: "0.0.0.0:8080"}
            - {name: PLATFORM_FACTORY_SOURCE_RELEASE_DIGEST, value: %s}
            - name: PLATFORM_FACTORY_POSTGRES_DSN
              valueFrom: {secretKeyRef: {name: platform-database, key: dsn}}
            - {name: PLATFORM_FACTORY_POSTGRES_MAX_OPEN_CONNS, value: "20"}
            - {name: PLATFORM_FACTORY_POSTGRES_MIGRATION_MODE, value: "rolling"}
            - {name: PLATFORM_FACTORY_POSTGRES_MAX_IDLE_CONNS, value: "5"}
            - {name: PLATFORM_FACTORY_INTERNAL_GIT_URL, value: "http://platform-forgejo:3000"}
            - {name: PLATFORM_FACTORY_INTERNAL_GIT_USERNAME, value: platform-admin}
            - name: PLATFORM_FACTORY_INTERNAL_GIT_PASSWORD
              valueFrom: {secretKeyRef: {name: platform-internal-services, key: forgejo-admin-password}}
            - {name: PLATFORM_FACTORY_INTERNAL_GIT_BOOTSTRAP, value: "true"}
            - {name: PLATFORM_FACTORY_INTERNAL_REGISTRY_URL, value: "http://platform-zot:5000"}
            - {name: PLATFORM_FACTORY_INTERNAL_IDENTITY_URL, value: "http://platform-keycloak:8080"}
            - {name: PLATFORM_FACTORY_INTERNAL_GITOPS_URL, value: "http://argocd-server.platform-gitops.svc.cluster.local"}
            - {name: PLATFORM_FACTORY_OIDC_ENABLED, value: "true"}
            - {name: PLATFORM_FACTORY_OIDC_ISSUER, value: %s}
            - {name: PLATFORM_FACTORY_OIDC_INTERNAL_BASE, value: "http://platform-keycloak:8080"}
            - {name: PLATFORM_FACTORY_OIDC_CLIENT_ID, value: platform-console}
            - {name: PLATFORM_FACTORY_OIDC_REDIRECT_URL, value: %s}
            - name: PLATFORM_FACTORY_SESSION_SECRET
              valueFrom: {secretKeyRef: {name: platform-internal-services, key: session-secret}}
            - name: PLATFORM_FACTORY_BOOTSTRAP_TOKEN
              valueFrom: {secretKeyRef: {name: platform-internal-services, key: bootstrap-token}}
            - name: PLATFORM_FACTORY_CATALOG_SIGNING_PRIVATE_KEY_B64
              valueFrom: {secretKeyRef: {name: platform-internal-services, key: catalog-signing-key}}
            - {name: PLATFORM_FACTORY_FLEET_AGENT_IMAGE, value: %s}
            - {name: PLATFORM_FACTORY_RUNTIME_PROBE_IMAGE, value: %s}
            - {name: PLATFORM_FACTORY_PUBLIC_URL, value: %s}
            - {name: PLATFORM_FACTORY_AGENT_PUBLIC_URL, value: %s}
            - {name: PLATFORM_FACTORY_PUBLIC_CA_PEM_B64, value: %s}
            - {name: PLATFORM_FACTORY_AGENT_MTLS_REQUIRED, value: "true"}
            - {name: PLATFORM_FACTORY_AGENT_LISTEN, value: "0.0.0.0:8443"}
            - {name: PLATFORM_FACTORY_AGENT_CA_CERT_FILE, value: "/etc/4so-agent-mtls/client-ca.crt"}
            - {name: PLATFORM_FACTORY_AGENT_CA_KEY_FILE, value: "/etc/4so-agent-mtls/client-ca.key"}
            - {name: PLATFORM_FACTORY_AGENT_TLS_CERT_FILE, value: "/etc/4so-agent-mtls/tls.crt"}
            - {name: PLATFORM_FACTORY_AGENT_TLS_KEY_FILE, value: "/etc/4so-agent-mtls/tls.key"}
          ports:
            - {name: http, containerPort: 8080}
            - {name: agent-mtls, containerPort: 8443}
          resources:
            requests: {cpu: 500m, memory: 512Mi}
            limits: {cpu: "2", memory: 1Gi}
          volumeMounts:
            - {name: agent-mtls, mountPath: /etc/4so-agent-mtls, readOnly: true}
            - {name: identity-admin, mountPath: /run/secrets/platform, readOnly: true}
          readinessProbe: {httpGet: {path: /readyz, port: 8080}, initialDelaySeconds: 5, periodSeconds: 5}
          startupProbe: {httpGet: {path: /readyz, port: 8080}, periodSeconds: 5, failureThreshold: 24}
          livenessProbe: {httpGet: {path: /healthz, port: 8080}, periodSeconds: 15, timeoutSeconds: 3, failureThreshold: 4}
      volumes:
        - name: agent-mtls
          secret: {secretName: platform-agent-mtls, defaultMode: 0400}
        - name: identity-admin
          secret:
            secretName: platform-internal-services
            defaultMode: 0400
            items:
              - {key: identity-admin-password, path: identity-admin-password}
---
apiVersion: v1
kind: Service
metadata: {name: platform-api, namespace: platform-system}
spec:
  selector: {app: platform-api}
  ports:
    - {name: http, port: 8080, targetPort: 8080}
    - {name: agent-mtls, port: 8443, targetPort: 8443}
`, enc("platform"), enc(password), enc("keycloak"), enc(keycloakDBPassword), enc("forgejo"), enc(forgejoDBPassword), enc(password), enc(dsn), enc(forgejoPassword), enc(identityPassword), enc(request.Services.Identity.AdminEmail), enc(sessionSecret), enc(bootstrapToken), enc(catalogSigningKey), base64.StdEncoding.EncodeToString(agentCAPEM), base64.StdEncoding.EncodeToString(agentCAKeyPEM), base64.StdEncoding.EncodeToString(tlsCertPEM), base64.StdEncoding.EncodeToString(tlsKeyPEM), bundle.Spec.Workloads.PostgreSQLImage, yamlScalar(storageClass), bundle.Spec.Workloads.PlatformAPIImage, yamlScalar(bundle.Metadata.SourceReleaseDigest), yamlScalar(issuer), yamlScalar(redirect), yamlScalar(bundle.Spec.Workloads.FleetAgentImage), yamlScalar(bundle.Spec.Workloads.RuntimeProbeImage), yamlScalar(strings.TrimRight(request.Network.PublicEndpoint, "/")), yamlScalar(agentPublicURL), yamlScalar(enc(string(caPEM))))
}

func (r *Runner) waitHADatabase(ctx context.Context, run Run, name string) error {
	if run.Request.ProfileID != "production-standard-ha" || r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kc := "/etc/rancher/rke2/rke2.yaml"
	return waitUntil(ctx, 3*time.Second, 10*time.Minute, func() error {
		raw, err := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kc, "-n", "platform-system", "get", "database/" + name, "-o", "jsonpath={.status.applied}"}, nil)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(raw)) != "true" {
			return fmt.Errorf("database %s is not applied", name)
		}
		return nil
	})
}

func (r *Runner) verifyHAServices(ctx context.Context, run Run) error {
	if run.Request.ProfileID != "production-standard-ha" || r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kc := "/etc/rancher/rke2/rke2.yaml"
	if err := r.system.Run(ctx, kubectl, []string{"--kubeconfig", kc, "-n", "platform-system", "wait", "--for=condition=Ready", "cluster/platform-postgresql", "--timeout=15m"}, nil); err != nil {
		return err
	}
	raw, err := r.system.Output(ctx, kubectl, []string{"--kubeconfig", kc, "-n", "platform-system", "get", "deployment/platform-api", "-o", "jsonpath={.status.availableReplicas}"}, nil)
	if err != nil {
		return err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if n < 2 {
		return fmt.Errorf("HA control plane requires at least two available API replicas, got %d", n)
	}
	return nil
}

func (r *Runner) verifyOfflineImages(ctx context.Context, run Run, bundle BundleManifest) error {
	if run.Request.Connectivity != installation.ConnectivityDisconnected {
		return nil
	}
	images, _ := json.Marshal(bundle.Spec.Airgap.RequiredImages)
	manifest := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata: {name: platform-airgap-index, namespace: platform-system}
data:
  version: %q
  images.json: %q
---
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: platform-airgap-image-verification, namespace: platform-system}
spec:
  selector:
    matchLabels: {app: platform-airgap-image-verification}
  template:
    metadata:
      labels: {app: platform-airgap-image-verification}
      annotations: {platform.4so.io/airgap-index-digest: %q}
    spec:
      containers:
        - name: verify
          image: %s
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          command: ["/bin/sh", "-ec"]
          args:
            - >-
              test -s /index/images.json;
              tr ',' '\n' < /index/images.json | tr -d '[]\" ' | grep '@sha256:' > /tmp/required-images;
              test -s /tmp/required-images;
              while IFS= read -r image; do
                /usr/local/bin/crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock inspecti "$image" >/dev/null;
              done < /tmp/required-images;
              while true; do sleep 3600; done
          volumeMounts:
            - {name: index, mountPath: /index, readOnly: true}
            - {name: runtime-socket, mountPath: /run/k3s/containerd/containerd.sock}
            - {name: crictl, mountPath: /usr/local/bin/crictl, readOnly: true}
            - {name: tmp, mountPath: /tmp}
      volumes:
        - {name: index, configMap: {name: platform-airgap-index}}
        - {name: runtime-socket, hostPath: {path: /run/k3s/containerd/containerd.sock, type: Socket}}
        - {name: crictl, hostPath: {path: /var/lib/rancher/rke2/bin/crictl, type: File}}
        - {name: tmp, emptyDir: {}}
`, bundle.Metadata.Version, string(images), bundle.Spec.Airgap.Index.SHA256, bundle.Spec.Workloads.MaintenanceImage)
	path := "/var/lib/rancher/rke2/server/manifests/4so-platform-airgap.yaml"
	if err := r.system.WriteFile(path, []byte(manifest), 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	return r.system.Run(ctx, "/var/lib/rancher/rke2/bin/kubectl", []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system", "rollout", "status", "daemonset/platform-airgap-image-verification", "--timeout=15m"}, nil)
}

func (r *Runner) configureOffNodeBackup(ctx context.Context, run Run, bundle BundleManifest) error {
	if run.Request.ProfileID != "production-standard-ha" {
		return nil
	}
	object := run.Request.Services.ObjectStorage
	secretRef := strings.TrimPrefix(object.CredentialRef, "external-secret://")
	parts := strings.Split(secretRef, "/")
	if len(parts) != 2 {
		return fmt.Errorf("production object storage credentialRef must be external-secret://namespace/name")
	}
	prefix := object.Prefix
	if prefix == "" {
		prefix = "4so-platform-factory"
	}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata: {name: platform-disaster-recovery, namespace: platform-system}
data:
  endpoint: %q
  bucket: %q
  prefix: %q
  region: %q
  credentialSecretNamespace: %q
  credentialSecretName: %q
  maintenanceImage: %q
`, object.URL, object.Bucket, prefix, object.Region, parts[0], parts[1], bundle.Spec.Workloads.MaintenanceImage)
	if err := r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/4so-platform-disaster-recovery.yaml", []byte(manifest), 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	return r.system.Run(ctx, "/var/lib/rancher/rke2/bin/kubectl", []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system", "get", "configmap/platform-disaster-recovery"}, nil)
}

func (r *Runner) AirgapStatus() (map[string]any, error) {
	admission, err := InspectBundle(r.bundleDir, r.requireBundleLock)
	if err != nil {
		return nil, err
	}
	bundle, _, err := LoadBundle(r.bundleDir)
	if err != nil {
		return nil, err
	}
	digest := admission.BundleDigest
	status := map[string]any{"complete": bundle.Spec.Airgap.Complete, "bundleDigest": digest, "index": bundle.Spec.Airgap.Index, "requiredImages": len(bundle.Spec.Airgap.RequiredImages), "verified": false}
	run, loadErr := r.journal.Load()
	if loadErr != nil {
		return nil, loadErr
	}
	if run != nil {
		for _, step := range run.Steps {
			if step.Key == "seed-offline-registry" {
				status["state"] = step.State
				status["verified"] = step.State == StepSucceeded && run.Request.Connectivity == installation.ConnectivityDisconnected
			}
		}
	}
	return status, nil
}

func (r *Runner) HAStatus() (map[string]any, error) {
	run, err := r.journal.Load()
	if err != nil {
		return nil, err
	}
	status := map[string]any{"selected": false, "liveCertified": false}
	if run == nil {
		return status, nil
	}
	status["profileId"] = run.Request.ProfileID
	status["selected"] = run.Request.ProfileID == "production-standard-ha"
	status["nodes"] = run.Request.Infrastructure.NodeAddresses
	status["storageClass"] = run.Request.Infrastructure.StorageClass
	steps := map[string]StepState{}
	for _, step := range run.Steps {
		if step.Key == "verify-ha-quorum" || step.Key == "deploy-postgresql-operator" || step.Key == "verify-ha-services" {
			steps[step.Key] = step.State
		}
	}
	status["steps"] = steps
	return status, nil
}
