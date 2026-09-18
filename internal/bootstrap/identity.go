package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"platform.4so.io/factory/internal/installation"
)

func (r *Runner) deployIdentity(ctx context.Context, run Run, bundle BundleManifest) error {
	if err := r.waitHADatabase(ctx, run, "platform-keycloak-database"); err != nil {
		return err
	}
	manifest := keycloakManifest(bundle, run.Request)
	if err := r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/4so-platform-keycloak.yaml", []byte(manifest), 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	if err := r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "rollout", "status", "statefulset/platform-keycloak", "--timeout=12m"}, nil); err != nil {
		return err
	}
	adminEmail := strings.TrimSpace(run.Request.Services.Identity.AdminEmail)
	command := fmt.Sprintf(`set -eu
KCADM=/opt/keycloak/bin/kcadm.sh
$KCADM config credentials --server http://127.0.0.1:8080 --realm master --user platform-admin --password "$(cat /run/secrets/platform/admin-password)"
USER_ID="$($KCADM get users -r platform -q email=%s --fields id --format csv --noquotes | head -n1)"
if [ -z "$USER_ID" ]; then
  USER_ID="$($KCADM create users -r platform -s username=%s -s email=%s -s enabled=true -i)"
fi
$KCADM set-password -r platform --userid "$USER_ID" --new-password "$(cat /run/secrets/platform/admin-password)" --temporary=false
$KCADM add-roles -r platform --uid "$USER_ID" --rolename platform-admin || true
GROUP_ID="$($KCADM get groups -r platform --fields id,name --format csv --noquotes | awk -F, '$2=="platform-admins" {print $1; exit}')"
if [ -z "$GROUP_ID" ]; then
  GROUP_ID="$($KCADM create groups -r platform -s name=platform-admins -i)"
fi
$KCADM update users/$USER_ID/groups/$GROUP_ID -r platform -n || true
`, shellQuote(adminEmail), shellQuote(adminEmail), shellQuote(adminEmail))
	return r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "exec", "statefulset/platform-keycloak", "--", "/bin/sh", "-ec", command}, nil)
}

func (r *Runner) configureSecureExposure(ctx context.Context, run Run) error {
	cert, err := r.readFile(tlsCertPath)
	if err != nil {
		return err
	}
	key, err := r.readFile(tlsKeyPath)
	if err != nil {
		return err
	}
	ca, err := r.readFile(tlsCAPath)
	if err != nil {
		return err
	}
	manifest, err := exposureManifest(run.Request, cert, key, ca)
	if err != nil {
		return err
	}
	if err = r.system.WriteFile("/var/lib/rancher/rke2/server/manifests/4so-platform-exposure.yaml", []byte(manifest), 0o600); err != nil {
		return err
	}
	if r.simulation {
		return nil
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	return waitUntil(ctx, 2*time.Second, 5*time.Minute, func() error {
		return r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "get", "ingress", "platform-api", "platform-agent", "platform-forgejo", "platform-zot", "platform-keycloak"}, nil)
	})
}

func (r *Runner) bootstrapRepository(ctx context.Context, run Run, bundle BundleManifest) error {
	if r.simulation {
		return nil
	}
	payload, _ := json.Marshal(map[string]any{
		"organization": run.Request.Services.Git.Organization,
		"name":         run.Request.Services.Git.Repository,
		"description":  "Managed platform desired state",
		"private":      true,
	})
	bootstrapToken, err := r.readSecret("/var/lib/4so-platform-installer/secrets/bootstrap-token")
	if err != nil {
		return err
	}
	_, err = r.clusterHTTP(ctx, bundle, "POST", "http://platform-api:8080/api/v1/system-services/git/repositories", payload, map[string]string{
		"Content-Type":               "application/json",
		"X-Actor-ID":                 "bootstrap-installer",
		"X-Platform-Bootstrap-Token": bootstrapToken,
	})
	return err
}

func (r *Runner) clusterHTTP(ctx context.Context, bundle BundleManifest, method, endpoint string, payload []byte, headers map[string]string) ([]byte, error) {
	if r.simulation {
		switch {
		case strings.HasSuffix(endpoint, "/api/v1/system-services"):
			return []byte(`[{"name":"git","healthy":true},{"name":"registry","healthy":true},{"name":"identity","healthy":true},{"name":"gitops","healthy":true}]`), nil
		case strings.HasSuffix(endpoint, "/api/v1/organizations"):
			return []byte(`[{"id":"org_simulated","name":"bootstrap"}]`), nil
		case strings.Contains(endpoint, "/api/v1/projects"):
			return []byte(`[{"id":"prj_simulated","name":"platform"}]`), nil
		default:
			return []byte(`{"status":"ok"}`), nil
		}
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	name := fmt.Sprintf("platform-http-%d", time.Now().UnixNano())
	method = strings.ToUpper(strings.TrimSpace(method))
	if method != httpMethodGet && method != httpMethodPost {
		return nil, fmt.Errorf("unsupported bootstrap HTTP method %q", method)
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.ContainsAny(endpoint, "\r\n") {
		return nil, errors.New("bootstrap HTTP endpoint must be a single non-empty line")
	}
	actor := strings.TrimSpace(headers["X-Actor-ID"])
	contentType := strings.TrimSpace(headers["Content-Type"])
	for _, value := range []string{actor, contentType} {
		if strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("bootstrap HTTP header values must be single-line")
		}
	}
	bootstrapHeaderRequested := strings.TrimSpace(headers["X-Platform-Bootstrap-Token"]) != ""
	for key := range headers {
		switch key {
		case "X-Platform-Bootstrap-Token", "X-Actor-ID", "Content-Type":
		default:
			return nil, fmt.Errorf("unsupported bootstrap HTTP header %q", key)
		}
	}

	probeScript := `set -eu
IFS= read -r request_method
IFS= read -r request_endpoint
IFS= read -r request_actor
IFS= read -r request_content_type
request_payload="$(cat)"
set -- -qO-
if [ -n "${PLATFORM_FACTORY_BOOTSTRAP_TOKEN:-}" ]; then
  set -- "$@" "--header=X-Platform-Bootstrap-Token: ${PLATFORM_FACTORY_BOOTSTRAP_TOKEN}"
fi
if [ -n "$request_actor" ]; then
  set -- "$@" "--header=X-Actor-ID: $request_actor"
fi
if [ -n "$request_content_type" ]; then
  set -- "$@" "--header=Content-Type: $request_content_type"
fi
case "$request_method" in
  GET) exec wget "$@" "$request_endpoint" ;;
  POST) exec wget "$@" "--post-data=$request_payload" "$request_endpoint" ;;
  *) echo "unsupported bootstrap HTTP method" >&2; exit 64 ;;
esac`
	container := map[string]any{
		"name":            "probe",
		"image":           bundle.Spec.Workloads.MaintenanceImage,
		"imagePullPolicy": "IfNotPresent",
		"command":         []string{"/bin/sh", "-ec"},
		"args":            []string{probeScript},
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"capabilities":             map[string]any{"drop": []string{"ALL"}},
		},
	}
	if bootstrapHeaderRequested {
		container["env"] = []map[string]any{{
			"name": "PLATFORM_FACTORY_BOOTSTRAP_TOKEN",
			"valueFrom": map[string]any{"secretKeyRef": map[string]any{
				"name": "platform-internal-services",
				"key":  "bootstrap-token",
			}},
		}}
	}
	overrides, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"spec": map[string]any{
			"automountServiceAccountToken":  false,
			"activeDeadlineSeconds":         120,
			"terminationGracePeriodSeconds": 0,
			"restartPolicy":                 "Never",
			"containers":                    []map[string]any{container},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap HTTP probe Pod: %w", err)
	}
	input := bytes.NewBuffer(nil)
	fmt.Fprintf(input, "%s\n%s\n%s\n%s\n", method, endpoint, actor, contentType)
	input.Write(payload)
	args := []string{
		"--kubeconfig", kubeconfig, "-n", "platform-system", "run", name,
		"--rm", "-i", "--restart=Never", "--image=" + bundle.Spec.Workloads.MaintenanceImage,
		"--overrides=" + string(overrides),
	}
	inputSystem, ok := r.system.(interface {
		OutputInput(context.Context, string, []string, map[string]string, io.Reader) ([]byte, error)
	})
	if !ok {
		return nil, errors.New("bootstrap HTTP probe system does not support stdin/output execution")
	}
	return inputSystem.OutputInput(ctx, kubectl, args, nil, input)
}

const (
	httpMethodGet  = "GET"
	httpMethodPost = "POST"
)

func keycloakManifest(bundle BundleManifest, request installation.InstallRequest) string {
	redirect := strings.TrimRight(request.Network.PublicEndpoint, "/") + "/auth/callback"
	webOrigin := strings.TrimRight(request.Network.PublicEndpoint, "/")
	realm := map[string]any{
		"realm": "platform", "enabled": true, "organizationsEnabled": true, "displayName": "4SO Platform Factory", "registrationAllowed": false,
		"roles":  map[string]any{"realm": []map[string]any{{"name": "platform-admin"}, {"name": "platform-operator"}, {"name": "platform-viewer"}}},
		"groups": []map[string]any{{"name": "platform-admins"}},
		"clients": []map[string]any{{
			"clientId": "platform-console", "name": "4SO Platform Console", "enabled": true, "publicClient": true,
			"standardFlowEnabled": true, "directAccessGrantsEnabled": false, "redirectUris": []string{redirect}, "webOrigins": []string{webOrigin},
			"attributes":      map[string]string{"pkce.code.challenge.method": "S256"},
			"protocolMappers": []map[string]any{{"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper", "consentRequired": false, "config": map[string]string{"full.path": "false", "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true", "claim.name": "groups"}}},
		}},
	}
	realmJSON, _ := json.Marshal(realm)
	replicas := 1
	affinity := ""
	dbInit := `
      initContainers:
        - name: initialize-database
          image: %s
          imagePullPolicy: IfNotPresent
          env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: platform-database
                  key: password
          command: ["/bin/sh", "-ec"]
          args:
            - >-
              until pg_isready -h platform-postgresql -U platform -d postgres; do sleep 2; done;
              psql -h platform-postgresql -U platform -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='keycloak'" | grep -q 1 ||
              createdb -h platform-postgresql -U platform keycloak`
	dbUser := "platform"
	dbSecret := "platform-database"
	if request.ProfileID == "production-standard-ha" {
		replicas = 2
		dbInit = ""
		dbUser = "keycloak"
		dbSecret = "platform-keycloak-db"
		affinity = `
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector: {matchLabels: {app: platform-keycloak}}
              topologyKey: kubernetes.io/hostname`
	}
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: platform-keycloak-realm
  namespace: platform-system
data:
  platform-realm.json: %s
---
apiVersion: v1
kind: Service
metadata:
  name: platform-keycloak
  namespace: platform-system
spec:
  selector:
    app: platform-keycloak
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: platform-keycloak
  namespace: platform-system
spec:
  serviceName: platform-keycloak
  replicas: %d
  selector:
    matchLabels:
      app: platform-keycloak
  template:
    metadata:
      labels:
        app: platform-keycloak
    spec:%s%s
      containers:
        - name: keycloak
          image: %s
          imagePullPolicy: IfNotPresent
          args: ["start", "--import-realm", "--http-enabled=true", "--proxy-headers=xforwarded", "--health-enabled=true"]
          env:
            - name: KC_DB
              value: postgres
            - name: KC_DB_URL
              value: jdbc:postgresql://platform-postgresql:5432/keycloak
            - name: KC_DB_USERNAME
              value: %s
            - name: KC_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: %s
                  key: password
            - name: KC_HOSTNAME
              value: %s
            - name: KC_BOOTSTRAP_ADMIN_USERNAME
              value: platform-admin
            - name: KC_BOOTSTRAP_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: platform-internal-services
                  key: identity-admin-password
          ports:
            - {name: http, containerPort: 8080}
            - {name: management, containerPort: 9000}
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 9000
            initialDelaySeconds: 20
            periodSeconds: 5
          volumeMounts:
            - name: realm
              mountPath: /opt/keycloak/data/import
              readOnly: true
            - name: internal-services
              mountPath: /run/secrets/platform
              readOnly: true
      volumes:
        - name: realm
          configMap:
            name: platform-keycloak-realm
        - name: internal-services
          secret:
            secretName: platform-internal-services
            items:
              - key: identity-admin-password
                path: admin-password
`, yamlScalar(string(realmJSON)), replicas, affinity, fmt.Sprintf(dbInit, bundle.Spec.Workloads.PostgreSQLImage), bundle.Spec.Workloads.KeycloakImage, yamlScalar(dbUser), yamlScalar(dbSecret), yamlScalar("https://auth."+request.Network.DNSZone))
}

func exposureManifest(request installation.InstallRequest, cert, key, ca []byte) (string, error) {
	endpoint, err := url.Parse(request.Network.PublicEndpoint)
	if err != nil || endpoint.Hostname() == "" {
		return "", fmt.Errorf("invalid public endpoint")
	}
	zone := strings.TrimSpace(request.Network.DNSZone)
	if zone == "" {
		return "", fmt.Errorf("dnsZone is required for managed identity and service exposure")
	}
	return fmt.Sprintf(`apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-ingress-nginx
  namespace: kube-system
spec:
  valuesContent: |-
    controller:
      extraArgs:
        enable-ssl-passthrough: "true"
---
apiVersion: v1
kind: Secret
metadata:
  name: platform-ingress-tls
  namespace: platform-system
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
  ca.crt: %s
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: platform-api
  namespace: platform-system
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "20m"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [%s]
      secretName: platform-ingress-tls
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: platform-api
                port: {number: 8080}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: platform-agent
  namespace: platform-system
  annotations:
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [%s]
      secretName: platform-ingress-tls
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: platform-api
                port: {number: 8443}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: platform-forgejo
  namespace: platform-system
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "2g"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [%s]
      secretName: platform-ingress-tls
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: platform-forgejo
                port: {number: 3000}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: platform-zot
  namespace: platform-system
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [%s]
      secretName: platform-ingress-tls
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: platform-zot
                port: {number: 5000}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: platform-keycloak
  namespace: platform-system
spec:
  ingressClassName: nginx
  tls:
    - hosts: [%s]
      secretName: platform-ingress-tls
  rules:
    - host: %s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: platform-keycloak
                port: {number: 8080}
`, base64.StdEncoding.EncodeToString(cert), base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(ca), yamlScalar(endpoint.Hostname()), yamlScalar(endpoint.Hostname()), yamlScalar("agent."+zone), yamlScalar("agent."+zone), yamlScalar("git."+zone), yamlScalar("git."+zone), yamlScalar("registry."+zone), yamlScalar("registry."+zone), yamlScalar("auth."+zone), yamlScalar("auth."+zone)), nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
