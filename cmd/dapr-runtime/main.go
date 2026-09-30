package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/buildinfo"
	daprruntime "platform.4so.io/factory/internal/dapr"
)

const (
	executorAuthority  = "DAPR_TARGET_EXECUTOR_RUNTIME_V1"
	receiptAuthority   = "DAPR_TARGET_OBSERVED_RECEIPT_V1"
	ownerName          = "4so-dapr-runtime-owner"
	receiptName        = "4so-dapr-runtime-observed"
	runtimeNamespace   = "dapr-system"
	chartPath          = "/runtime/dapr-1.18.4.tgz"
	helmPath           = "/usr/local/bin/helm"
	serviceAccountRoot = "/var/run/secrets/kubernetes.io/serviceaccount"
)

type lifecycleConfig struct {
	Action                     daprruntime.LifecycleAction
	Lock                       daprruntime.RuntimeLock
	LockDigest                 string
	OperationID                string
	FenceToken                 int64
	ExpectedObservedLockDigest string
}

type ownerState struct {
	Authority         string `json:"authority"`
	Installed         bool   `json:"installed"`
	RuntimeLockDigest string `json:"runtimeLockDigest,omitempty"`
	OperationID       string `json:"operationId"`
	FenceToken        int64  `json:"fenceToken"`
	Version           string `json:"version,omitempty"`
	UpstreamCommit    string `json:"upstreamCommit,omitempty"`
	ObservedAt        string `json:"observedAt"`
	Phase             string `json:"phase"`
}

type kubeConfigMap struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Data map[string]string `json:"data"`
}

type kubeDeployment struct {
	Metadata struct {
		Name       string `json:"name"`
		Generation int64  `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int32 `json:"replicas,omitempty"`
		Template struct {
			Spec struct {
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
					Env   []struct {
						Name  string `json:"name"`
						Value string `json:"value,omitempty"`
					} `json:"env,omitempty"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64 `json:"observedGeneration"`
		Replicas           int32 `json:"replicas"`
		UpdatedReplicas    int32 `json:"updatedReplicas"`
		AvailableReplicas  int32 `json:"availableReplicas"`
	} `json:"status"`
}

type kubeClient struct {
	base  string
	token string
	http  *http.Client
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func strictRuntimeLock(raw string) (daprruntime.RuntimeLock, string, error) {
	var lock daprruntime.RuntimeLock
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return lock, "", fmt.Errorf("decode Dapr runtime lock: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return lock, "", errors.New("Dapr runtime lock contains trailing JSON")
	}
	if err := daprruntime.ValidateRuntimeLock(lock); err != nil {
		return lock, "", err
	}
	digest, err := daprruntime.RuntimeLockDigest(lock)
	return lock, digest, err
}

func loadConfig(args []string) (lifecycleConfig, error) {
	var cfg lifecycleConfig
	set := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	action := set.String("action", "", "install, upgrade, or remove")
	if err := set.Parse(args); err != nil || len(set.Args()) != 0 {
		return cfg, errors.New("Dapr lifecycle arguments are invalid")
	}
	var err error
	cfg.Action, err = daprruntime.NormalizeLifecycleAction(daprruntime.LifecycleAction(*action))
	if err != nil {
		return cfg, err
	}
	cfg.OperationID = strings.TrimSpace(os.Getenv("FOURSO_DAPR_OPERATION_ID"))
	cfg.ExpectedObservedLockDigest = strings.ToLower(strings.TrimSpace(os.Getenv("FOURSO_DAPR_EXPECTED_OBSERVED_LOCK_DIGEST")))
	fence, fenceErr := strconv.ParseInt(strings.TrimSpace(os.Getenv("FOURSO_DAPR_TASK_FENCE_TOKEN")), 10, 64)
	if cfg.OperationID == "" || fenceErr != nil || fence <= 0 {
		return cfg, errors.New("Dapr operation identity/fence environment is invalid")
	}
	cfg.FenceToken = fence
	cfg.Lock, cfg.LockDigest, err = strictRuntimeLock(os.Getenv("FOURSO_DAPR_RUNTIME_LOCK_JSON"))
	if err != nil {
		return cfg, err
	}
	if expected := strings.ToLower(strings.TrimSpace(os.Getenv("FOURSO_DAPR_RUNTIME_LOCK_DIGEST"))); expected == "" || expected != cfg.LockDigest {
		return cfg, errors.New("Dapr runtime lock digest does not match task authority")
	}
	if cfg.ExpectedObservedLockDigest != "" && !strings.HasPrefix(cfg.ExpectedObservedLockDigest, "sha256:") {
		return cfg, errors.New("Dapr expected observed lock digest is invalid")
	}
	return cfg, nil
}

func imageByRole(lock daprruntime.RuntimeLock, role string) (string, error) {
	for _, image := range lock.ImageLocks {
		if image.Role == role {
			return image.MirrorReference, nil
		}
	}
	return "", fmt.Errorf("Dapr runtime image role %q is missing", role)
}

func helmProfileArgs(lock daprruntime.RuntimeLock) ([]string, error) {
	operator, err := imageByRole(lock, "operator")
	if err != nil {
		return nil, err
	}
	injector, err := imageByRole(lock, "injector")
	if err != nil {
		return nil, err
	}
	sidecar, err := imageByRole(lock, "sidecar")
	if err != nil {
		return nil, err
	}
	sentry, err := imageByRole(lock, "sentry")
	if err != nil {
		return nil, err
	}
	return []string{
		"--set-string", "global.registry=" + lock.MirrorRegistry,
		"--set-string", "global.tag=1.18.4",
		"--set", "global.actors.enabled=false",
		"--set", "global.scheduler.enabled=false",
		"--set", "global.mtls.enabled=true",
		"--set", "global.prometheus.enabled=true",
		"--set", "dapr_config.dapr_config_chart_included=false",
		"--set", "dapr_rbac.secretReader.enabled=false",
		"--set", "dapr_sidecar_injector.sidecarRunAsNonRoot=true",
		"--set", "dapr_sidecar_injector.sidecarReadOnlyRootFilesystem=true",
		"--set", "dapr_sidecar_injector.sidecarDropALLCapabilities=true",
		"--set-string", "dapr_operator.image.name=" + operator,
		"--set-string", "dapr_sidecar_injector.injectorImage.name=" + injector,
		"--set-string", "dapr_sidecar_injector.image.name=" + sidecar,
		"--set-string", "dapr_sentry.image.name=" + sentry,
		"--set", "global.imagePullPolicy=IfNotPresent",
		"--set", "dapr_sidecar_injector.sidecarImagePullPolicy=IfNotPresent",
	}, nil
}

func prepareKubeconfig() (string, error) {
	tokenRaw, err := os.ReadFile(serviceAccountRoot + "/token")
	if err != nil || strings.TrimSpace(string(tokenRaw)) == "" {
		return "", errors.New("Dapr executor service-account token is unavailable")
	}
	caPath := serviceAccountRoot + "/ca.crt"
	if info, statErr := os.Stat(caPath); statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", errors.New("Dapr executor service-account CA is unavailable")
	}
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
	if port == "" {
		port = strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
	if host == "" || port == "" {
		return "", errors.New("Dapr executor Kubernetes service endpoint is unavailable")
	}
	serverHost := host
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		serverHost = "[" + host + "]"
	}
	server := "https://" + serverHost + ":" + port
	raw := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: target\n  cluster:\n    certificate-authority: %s\n    server: %s\nusers:\n- name: executor\n  user:\n    token: %s\ncontexts:\n- name: target\n  context:\n    cluster: target\n    user: executor\ncurrent-context: target\n", caPath, server, strings.TrimSpace(string(tokenRaw)))
	file, err := os.CreateTemp("", "4so-dapr-kubeconfig-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err = file.Chmod(0o600); err == nil {
		_, err = file.WriteString(raw)
	}
	closeErr := file.Close()
	if err != nil {
		os.Remove(path)
		return "", err
	}
	if closeErr != nil {
		os.Remove(path)
		return "", closeErr
	}
	return path, nil
}

func newKubeClient() (*kubeClient, error) {
	tokenRaw, err := os.ReadFile(serviceAccountRoot + "/token")
	if err != nil {
		return nil, err
	}
	caRaw, err := os.ReadFile(serviceAccountRoot + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caRaw) {
		return nil, errors.New("Dapr executor Kubernetes CA is invalid")
	}
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
	if port == "" {
		port = strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
	if host == "" || port == "" {
		return nil, errors.New("Dapr executor Kubernetes endpoint is unavailable")
	}
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return &kubeClient{
		base:  "https://" + host + ":" + port,
		token: strings.TrimSpace(string(tokenRaw)),
		http: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}},
		},
	}, nil
}

func (k *kubeClient) request(ctx context.Context, method, path string, body []byte, contentType string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := k.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	return res, raw, err
}

func (k *kubeClient) ensureRuntimeNamespace(ctx context.Context) error {
	path := "/api/v1/namespaces/" + runtimeNamespace
	res, raw, err := k.request(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusOK {
		return nil
	}
	if res.StatusCode != http.StatusNotFound {
		return fmt.Errorf("Dapr runtime namespace read failed: %s %s", res.Status, strings.TrimSpace(string(raw)))
	}
	body := []byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"dapr-system","labels":{"app.kubernetes.io/managed-by":"4so-platform-factory"}}}`)
	res, raw, err = k.request(ctx, http.MethodPost, "/api/v1/namespaces", body, "application/json")
	if err != nil {
		return err
	}
	if (res.StatusCode < 200 || res.StatusCode >= 300) && res.StatusCode != http.StatusConflict {
		return fmt.Errorf("Dapr runtime namespace create failed: %s %s", res.Status, strings.TrimSpace(string(raw)))
	}
	return nil
}

func (k *kubeClient) getDeployment(ctx context.Context, name string) (*kubeDeployment, bool, error) {
	path := "/apis/apps/v1/namespaces/" + runtimeNamespace + "/deployments/" + name
	res, raw, err := k.request(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("Dapr Deployment read failed for %s: %s %s", name, res.Status, strings.TrimSpace(string(raw)))
	}
	var deployment kubeDeployment
	if err = json.Unmarshal(raw, &deployment); err != nil {
		return nil, false, err
	}
	return &deployment, true, nil
}

func (k *kubeClient) statefulSetExists(ctx context.Context, name string) (bool, error) {
	path := "/apis/apps/v1/namespaces/" + runtimeNamespace + "/statefulsets/" + name
	res, raw, err := k.request(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return false, err
	}
	if res.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Dapr StatefulSet read failed for %s: %s %s", name, res.Status, strings.TrimSpace(string(raw)))
	}
	return true, nil
}

func deploymentContainer(deployment *kubeDeployment, name string) (image string, env map[string]string, err error) {
	if deployment == nil {
		return "", nil, errors.New("DAPR_OBSERVED_DEPLOYMENT_MISSING")
	}
	matches := 0
	env = map[string]string{}
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != name {
			continue
		}
		matches++
		image = strings.TrimSpace(container.Image)
		for _, item := range container.Env {
			key := strings.TrimSpace(item.Name)
			if key != "" {
				env[key] = strings.TrimSpace(item.Value)
			}
		}
	}
	if matches != 1 || image == "" {
		return "", nil, fmt.Errorf("DAPR_OBSERVED_CONTAINER_IDENTITY_INVALID %s", name)
	}
	return image, env, nil
}

func verifyDeploymentReadyExact(deployment *kubeDeployment, name, containerName, expectedImage string) (map[string]string, error) {
	if deployment == nil || deployment.Metadata.Name != name {
		return nil, fmt.Errorf("DAPR_OBSERVED_DEPLOYMENT_IDENTITY_INVALID %s", name)
	}
	replicas := int32(1)
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}
	if replicas <= 0 || deployment.Status.ObservedGeneration < deployment.Metadata.Generation ||
		deployment.Status.UpdatedReplicas != replicas || deployment.Status.AvailableReplicas != replicas {
		return nil, fmt.Errorf("DAPR_OBSERVED_DEPLOYMENT_NOT_READY %s desired=%d updated=%d available=%d generation=%d observedGeneration=%d",
			name, replicas, deployment.Status.UpdatedReplicas, deployment.Status.AvailableReplicas,
			deployment.Metadata.Generation, deployment.Status.ObservedGeneration)
	}
	image, env, err := deploymentContainer(deployment, containerName)
	if err != nil {
		return nil, err
	}
	if image != expectedImage {
		return nil, fmt.Errorf("DAPR_OBSERVED_IMAGE_MISMATCH %s got=%s want=%s", name, image, expectedImage)
	}
	return env, nil
}

func verifyInjectorObservedPolicy(env map[string]string, sidecarImage string) error {
	for key, want := range map[string]string{
		"SIDECAR_IMAGE": sidecarImage,
		"SIDECAR_RUN_AS_NON_ROOT": "true",
		"SIDECAR_DROP_ALL_CAPABILITIES": "true",
		"SIDECAR_READ_ONLY_ROOT_FILESYSTEM": "true",
	} {
		if strings.TrimSpace(env[key]) != want {
			return fmt.Errorf("DAPR_OBSERVED_INJECTOR_POLICY_MISMATCH %s got=%q want=%q", key, env[key], want)
		}
	}
	return nil
}

func (k *kubeClient) verifyInstalledRuntime(ctx context.Context, lock daprruntime.RuntimeLock) error {
	operatorImage, err := imageByRole(lock, "operator")
	if err != nil { return err }
	injectorImage, err := imageByRole(lock, "injector")
	if err != nil { return err }
	sidecarImage, err := imageByRole(lock, "sidecar")
	if err != nil { return err }
	sentryImage, err := imageByRole(lock, "sentry")
	if err != nil { return err }

	checks := []struct {
		name, container, image string
	}{
		{"dapr-operator", "dapr-operator", operatorImage},
		{"dapr-sidecar-injector", "dapr-sidecar-injector", injectorImage},
		{"dapr-sentry", "dapr-sentry", sentryImage},
	}
	var injectorEnv map[string]string
	for _, check := range checks {
		deployment, found, getErr := k.getDeployment(ctx, check.name)
		if getErr != nil {
			return getErr
		}
		if !found {
			return fmt.Errorf("DAPR_OBSERVED_DEPLOYMENT_MISSING %s", check.name)
		}
		env, verifyErr := verifyDeploymentReadyExact(deployment, check.name, check.container, check.image)
		if verifyErr != nil {
			return verifyErr
		}
		if check.name == "dapr-sidecar-injector" {
			injectorEnv = env
		}
	}
	if err = verifyInjectorObservedPolicy(injectorEnv, sidecarImage); err != nil {
		return err
	}
	for _, forbidden := range []string{"dapr-placement-server", "dapr-scheduler-server"} {
		exists, getErr := k.statefulSetExists(ctx, forbidden)
		if getErr != nil {
			return getErr
		}
		if exists {
			return fmt.Errorf("DAPR_FORBIDDEN_RUNTIME_AUTHORITY_PRESENT %s", forbidden)
		}
	}
	return nil
}

func (k *kubeClient) verifyRemovedRuntime(ctx context.Context) error {
	for _, name := range []string{"dapr-operator", "dapr-sidecar-injector", "dapr-sentry"} {
		_, found, err := k.getDeployment(ctx, name)
		if err != nil {
			return err
		}
		if found {
			return fmt.Errorf("DAPR_RUNTIME_RESOURCE_REMAINS %s", name)
		}
	}
	for _, name := range []string{"dapr-placement-server", "dapr-scheduler-server"} {
		exists, err := k.statefulSetExists(ctx, name)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("DAPR_FORBIDDEN_RUNTIME_AUTHORITY_PRESENT %s", name)
		}
	}
	return nil
}

func (k *kubeClient) getState(ctx context.Context, name string) (*ownerState, string, error) {
	path := "/api/v1/namespaces/" + runtimeNamespace + "/configmaps/" + name
	res, raw, err := k.request(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, "", err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, "", nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("Dapr ConfigMap read failed: %s", res.Status)
	}
	var cm kubeConfigMap
	if err = json.Unmarshal(raw, &cm); err != nil {
		return nil, "", err
	}
	stateRaw := cm.Data["state.json"]
	if strings.TrimSpace(stateRaw) == "" {
		return nil, "", errors.New("Dapr observed ConfigMap state is missing")
	}
	var state ownerState
	decoder := json.NewDecoder(strings.NewReader(stateRaw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&state); err != nil {
		return nil, "", err
	}
	if state.Authority != receiptAuthority {
		return nil, "", errors.New("Dapr observed ConfigMap authority is invalid")
	}
	return &state, cm.Metadata.ResourceVersion, nil
}

func (k *kubeClient) putState(ctx context.Context, name string, state ownerState) error {
	_, rv, err := k.getState(ctx, name)
	if err != nil {
		return err
	}
	stateRaw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	var cm kubeConfigMap
	cm.APIVersion = "v1"
	cm.Kind = "ConfigMap"
	cm.Metadata.Name = name
	cm.Metadata.Namespace = runtimeNamespace
	cm.Metadata.ResourceVersion = rv
	cm.Data = map[string]string{"state.json": string(stateRaw)}
	raw, err := json.Marshal(cm)
	if err != nil {
		return err
	}
	method := http.MethodPost
	path := "/api/v1/namespaces/" + runtimeNamespace + "/configmaps"
	if rv != "" {
		method = http.MethodPut
		path += "/" + name
	}
	res, response, err := k.request(ctx, method, path, raw, "application/json")
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("Dapr ConfigMap write failed: %s %s", res.Status, strings.TrimSpace(string(response)))
	}
	return nil
}

func helmStatus(ctx context.Context, env []string) (bool, error) {
	cmd := exec.CommandContext(ctx, helmPath, "status", "dapr", "--namespace", runtimeNamespace)
	cmd.Env = env
	raw, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	text := strings.ToLower(string(raw))
	if strings.Contains(text, "release: not found") || strings.Contains(text, "release not found") ||
		(strings.Contains(text, "not found") && strings.Contains(text, runtimeNamespace)) {
		return false, nil
	}
	return false, fmt.Errorf("Dapr Helm status failed: %w: %s", err, strings.TrimSpace(string(raw)))
}

func runHelm(ctx context.Context, env []string, args ...string) error {
	cmd := exec.CommandContext(ctx, helmPath, args...)
	cmd.Env = env
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Dapr Helm command failed: %w: %s", err, strings.TrimSpace(string(raw)))
	}
	return nil
}

func verifyRuntimeArtifacts(lock daprruntime.RuntimeLock) error {
	got, err := sha256File(chartPath)
	if err != nil {
		return err
	}
	if got != lock.HelmPackageDigest {
		return errors.New("Dapr embedded Helm package digest mismatch")
	}
	if info, err := os.Stat(helmPath); err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return errors.New("Dapr executor Helm binary is unavailable")
	}
	return nil
}

func runLifecycle(args []string) error {
	cfg, err := loadConfig(args)
	if err != nil {
		return err
	}
	if err = verifyRuntimeArtifacts(cfg.Lock); err != nil {
		return err
	}
	kubeconfig, err := prepareKubeconfig()
	if err != nil {
		return err
	}
	defer os.Remove(kubeconfig)
	env := append(os.Environ(), "KUBECONFIG="+kubeconfig)
	kube, err := newKubeClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	owner, _, err := kube.getState(ctx, ownerName)
	if err != nil {
		return err
	}
	releaseExists, err := helmStatus(ctx, env)
	if err != nil {
		return err
	}
	sameOperation := owner != nil && owner.OperationID == cfg.OperationID && owner.FenceToken == cfg.FenceToken
	samePending := sameOperation && owner.Phase == "Mutating"

	if sameOperation && !samePending {
		switch cfg.Action {
		case daprruntime.ActionInstall, daprruntime.ActionUpgrade:
			if owner.Installed && owner.RuntimeLockDigest == cfg.LockDigest && releaseExists {
				if err = kube.verifyInstalledRuntime(ctx, cfg.Lock); err != nil {
					return err
				}
				return kube.putState(ctx, receiptName, *owner)
			}
		case daprruntime.ActionRemove:
			if !owner.Installed && !releaseExists {
				if err = kube.verifyRemovedRuntime(ctx); err != nil {
					return err
				}
				return kube.putState(ctx, receiptName, *owner)
			}
		}
		return errors.New("DAPR_SAME_OPERATION_OBSERVED_STATE_AMBIGUOUS")
	}

	var observed *daprruntime.ObservedState
	if owner != nil {
		observed = &daprruntime.ObservedState{Installed: owner.Installed, RuntimeLockDigest: owner.RuntimeLockDigest}
	}
	if err = daprruntime.ValidateLifecycleDispatchFence(cfg.Action, observed, cfg.LockDigest, cfg.ExpectedObservedLockDigest); err != nil {
		return err
	}
	if cfg.Action == daprruntime.ActionInstall && releaseExists && (owner == nil || !owner.Installed) && !samePending {
		return errors.New("DAPR_UNOWNED_EXISTING_RELEASE_RECOVERY_REQUIRED")
	}
	if (cfg.Action == daprruntime.ActionUpgrade || cfg.Action == daprruntime.ActionRemove) && !releaseExists {
		if cfg.Action == daprruntime.ActionRemove && samePending {
			if err = kube.verifyRemovedRuntime(ctx); err != nil {
				return err
			}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			final := ownerState{Authority: receiptAuthority, Installed: false, OperationID: cfg.OperationID, FenceToken: cfg.FenceToken, ObservedAt: now, Phase: "Removed"}
			if err = kube.putState(ctx, ownerName, final); err != nil { return err }
			return kube.putState(ctx, receiptName, final)
		}
		return errors.New("DAPR_OWNED_RELEASE_MISSING_RECOVERY_REQUIRED")
	}
	if err = kube.ensureRuntimeNamespace(ctx); err != nil {
		return err
	}
	if !samePending {
		pending := ownerState{
			Authority: receiptAuthority,
			OperationID: cfg.OperationID,
			FenceToken: cfg.FenceToken,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Phase: "Mutating",
		}
		if owner != nil && owner.Installed {
			pending.Installed = true
			pending.RuntimeLockDigest = owner.RuntimeLockDigest
			pending.Version = owner.Version
			pending.UpstreamCommit = owner.UpstreamCommit
		}
		if err = kube.putState(ctx, ownerName, pending); err != nil {
			return err
		}
	}

	switch cfg.Action {
	case daprruntime.ActionInstall, daprruntime.ActionUpgrade:
		profile, profileErr := helmProfileArgs(cfg.Lock)
		if profileErr != nil {
			return profileErr
		}
		helmArgs := []string{"upgrade", "--install", "dapr", chartPath, "--namespace", runtimeNamespace, "--create-namespace", "--wait", "--timeout", "15m"}
		helmArgs = append(helmArgs, profile...)
		if err = runHelm(ctx, env, helmArgs...); err != nil {
			return err
		}
		if err = kube.verifyInstalledRuntime(ctx, cfg.Lock); err != nil {
			return err
		}
	case daprruntime.ActionRemove:
		if err = runHelm(ctx, env, "uninstall", "dapr", "--namespace", runtimeNamespace, "--wait", "--timeout", "10m"); err != nil {
			return err
		}
		if err = kube.verifyRemovedRuntime(ctx); err != nil {
			return err
		}
	default:
		return errors.New("Dapr lifecycle action unsupported")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	installed := cfg.Action != daprruntime.ActionRemove
	phase := "Installed"
	if cfg.Action == daprruntime.ActionUpgrade {
		phase = "Upgraded"
	}
	if cfg.Action == daprruntime.ActionRemove {
		phase = "Removed"
	}
	state := ownerState{
		Authority: receiptAuthority,
		Installed: installed,
		OperationID: cfg.OperationID,
		FenceToken: cfg.FenceToken,
		ObservedAt: now,
		Phase: phase,
	}
	if installed {
		state.RuntimeLockDigest = cfg.LockDigest
		state.Version = cfg.Lock.Version
		state.UpstreamCommit = cfg.Lock.UpstreamCommit
	}
	if err = kube.putState(ctx, ownerName, state); err != nil {
		return err
	}
	if err = kube.putState(ctx, receiptName, state); err != nil {
		return err
	}
	return nil
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(buildinfo.Version)
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "lifecycle" {
		fmt.Fprintf(os.Stderr, "%s_BLOCKED usage: dapr-runtime lifecycle --action install|upgrade|remove\n", executorAuthority)
		os.Exit(2)
	}
	if err := runLifecycle(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s_BLOCKED %v\n", executorAuthority, err)
		os.Exit(2)
	}
}
