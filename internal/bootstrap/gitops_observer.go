package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	gitOpsObserverAccount   = "platform-observer"
	gitOpsObserverTokenID   = "platform-factory-observer"
	gitOpsObserverSecretKey = "argocd-observer-token"
)

type argoAccount struct {
	Name   string `json:"name"`
	Tokens []struct {
		ID string `json:"id"`
	} `json:"tokens"`
}

func argoHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		},
		Timeout:       8 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func argoJSONRequest(ctx context.Context, client *http.Client, method, endpoint string, payload any, bearer string, out any) (int, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(bearer) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearer))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return resp.StatusCode, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("Argo CD API returned HTTP %d", resp.StatusCode)
	}
	if out != nil && len(bytes.TrimSpace(raw)) != 0 {
		if err = json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode Argo CD API response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func argoTokenValid(ctx context.Context, client *http.Client, baseURL, token string) bool {
	if strings.TrimSpace(token) == "" {
		return false
	}
	var info struct {
		LoggedIn bool   `json:"loggedIn"`
		Username string `json:"username"`
	}
	_, err := argoJSONRequest(ctx, client, http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/v1/session/userinfo", nil, token, &info)
	if err != nil || !info.LoggedIn || info.Username != gitOpsObserverAccount {
		return false
	}
	var permission struct {
		Value string `json:"value"`
	}
	_, err = argoJSONRequest(ctx, client, http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/v1/account/can-i/applications/get/platform/platform-appliance", nil, token, &permission)
	return err == nil && permission.Value == "yes"
}

func bootstrapArgoObserverToken(ctx context.Context, client *http.Client, baseURL, adminPassword, existingToken string) (string, bool, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return "", false, errors.New("Argo CD base URL is required")
	}
	if argoTokenValid(ctx, client, baseURL, existingToken) {
		return strings.TrimSpace(existingToken), false, nil
	}
	adminPassword = strings.TrimSpace(adminPassword)
	if adminPassword == "" {
		return "", false, errors.New("Argo CD initial admin password is unavailable while observer token requires recovery")
	}
	var session struct {
		Token string `json:"token"`
	}
	if _, err := argoJSONRequest(ctx, client, http.MethodPost, baseURL+"/api/v1/session", map[string]string{"username": "admin", "password": adminPassword}, "", &session); err != nil {
		return "", false, fmt.Errorf("create Argo CD bootstrap session: %w", err)
	}
	if strings.TrimSpace(session.Token) == "" {
		return "", false, errors.New("Argo CD bootstrap session did not return a token")
	}
	var account argoAccount
	if _, err := argoJSONRequest(ctx, client, http.MethodGet, baseURL+"/api/v1/account/"+gitOpsObserverAccount, nil, session.Token, &account); err != nil {
		return "", false, fmt.Errorf("inspect Argo CD observer account: %w", err)
	}
	for _, token := range account.Tokens {
		if token.ID != gitOpsObserverTokenID {
			continue
		}
		if _, err := argoJSONRequest(ctx, client, http.MethodDelete, baseURL+"/api/v1/account/"+gitOpsObserverAccount+"/token/"+gitOpsObserverTokenID, nil, session.Token, nil); err != nil {
			return "", false, fmt.Errorf("remove orphaned Argo CD observer token: %w", err)
		}
		break
	}
	var created struct {
		Token string `json:"token"`
	}
	payload := map[string]any{"name": gitOpsObserverAccount, "id": gitOpsObserverTokenID, "expiresIn": int64(0)}
	if _, err := argoJSONRequest(ctx, client, http.MethodPost, baseURL+"/api/v1/account/"+gitOpsObserverAccount+"/token", payload, session.Token, &created); err != nil {
		return "", false, fmt.Errorf("create Argo CD observer token: %w", err)
	}
	created.Token = strings.TrimSpace(created.Token)
	if !argoTokenValid(ctx, client, baseURL, created.Token) {
		return "", false, errors.New("new Argo CD observer token failed authenticated user-info validation")
	}
	return created.Token, true, nil
}

type kubeSecretEnvelope struct {
	Data map[string]string `json:"data"`
}

type kubeConfigMapEnvelope struct {
	Data map[string]string `json:"data"`
}

type kubeServiceEnvelope struct {
	Spec struct {
		ClusterIP string `json:"clusterIP"`
		Ports     []struct {
			Port int `json:"port"`
		} `json:"ports"`
	} `json:"spec"`
}

func decodeSecretValue(secret kubeSecretEnvelope, key string) (string, error) {
	encoded := strings.TrimSpace(secret.Data[key])
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode secret key %s: %w", key, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func mergeObserverRBAC(existing string) string {
	required := []string{
		"p, role:platform-observer, applications, get, platform/platform-appliance, allow",
		"g, platform-observer, role:platform-observer",
	}
	lines := strings.Split(strings.TrimSpace(existing), "\n")
	seen := map[string]bool{}
	out := make([]string, 0, len(lines)+len(required))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	for _, line := range required {
		if !seen[line] {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

func (r *Runner) kubeJSON(ctx context.Context, namespace, resource string, out any) error {
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	args := []string{"--kubeconfig", kubeconfig}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	args = append(args, "get", resource, "-o", "json")
	raw, err := r.system.Output(ctx, kubectl, args, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (r *Runner) configureGitOpsObserverAccount(ctx context.Context) error {
	var rbacCM kubeConfigMapEnvelope
	if err := r.kubeJSON(ctx, "platform-gitops", "configmap/argocd-rbac-cm", &rbacCM); err != nil {
		return fmt.Errorf("read Argo CD RBAC config: %w", err)
	}
	policy := mergeObserverRBAC(rbacCM.Data["policy.csv"])
	rbacPatch, _ := json.Marshal(map[string]any{"data": map[string]string{"policy.csv": policy}})
	cmPatch, _ := json.Marshal(map[string]any{"data": map[string]string{"accounts." + gitOpsObserverAccount: "apiKey"}})
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	base := []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-gitops", "patch"}
	if err := r.system.Run(ctx, kubectl, append(append([]string{}, base...), "configmap/argocd-cm", "--type=merge", "-p", string(cmPatch)), nil); err != nil {
		return fmt.Errorf("configure Argo CD observer account: %w", err)
	}
	if err := r.system.Run(ctx, kubectl, append(append([]string{}, base...), "configmap/argocd-rbac-cm", "--type=merge", "-p", string(rbacPatch)), nil); err != nil {
		return fmt.Errorf("configure Argo CD observer RBAC: %w", err)
	}
	return nil
}

func (r *Runner) gitOpsInternalURL(ctx context.Context) (string, error) {
	var service kubeServiceEnvelope
	if err := r.kubeJSON(ctx, "platform-gitops", "service/argocd-server", &service); err != nil {
		return "", fmt.Errorf("read Argo CD service: %w", err)
	}
	ip := strings.TrimSpace(service.Spec.ClusterIP)
	if net.ParseIP(ip) == nil || len(service.Spec.Ports) == 0 || service.Spec.Ports[0].Port <= 0 {
		return "", errors.New("Argo CD service has no usable ClusterIP/port")
	}
	return "http://" + net.JoinHostPort(ip, strconv.Itoa(service.Spec.Ports[0].Port)), nil
}

func (r *Runner) gitOpsBootstrapSecrets(ctx context.Context) (existingToken, adminPassword string, err error) {
	var product kubeSecretEnvelope
	if err = r.kubeJSON(ctx, "platform-system", "secret/platform-internal-services", &product); err != nil {
		return "", "", fmt.Errorf("read platform internal services secret: %w", err)
	}
	if existingToken, err = decodeSecretValue(product, gitOpsObserverSecretKey); err != nil {
		return "", "", err
	}
	var admin kubeSecretEnvelope
	if adminErr := r.kubeJSON(ctx, "platform-gitops", "secret/argocd-initial-admin-secret", &admin); adminErr == nil {
		adminPassword, err = decodeSecretValue(admin, "password")
		if err != nil {
			return "", "", err
		}
	}
	return existingToken, adminPassword, nil
}

func upsertGitOpsObserverTokenInFoundationManifest(raw []byte, token string) ([]byte, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("Argo CD observer token is empty")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(token))
	documents := strings.Split(string(raw), "\n---\n")
	matched := 0
	for index, document := range documents {
		if !strings.Contains(document, "kind: Secret") ||
			!strings.Contains(document, "metadata: {name: platform-internal-services, namespace: platform-system") {
			continue
		}
		matched++
		lines := strings.Split(document, "\n")
		dataIndex := -1
		keyIndex := -1
		for i, line := range lines {
			if line == "data:" {
				dataIndex = i
			}
			if strings.HasPrefix(line, "  "+gitOpsObserverSecretKey+":") {
				keyIndex = i
			}
		}
		if dataIndex < 0 {
			return nil, errors.New("platform-internal-services desired state has no data section")
		}
		entry := "  " + gitOpsObserverSecretKey + ": " + encoded
		if keyIndex >= 0 {
			lines[keyIndex] = entry
		} else {
			insertAt := dataIndex + 1
			for insertAt < len(lines) && (strings.HasPrefix(lines[insertAt], "  ") || strings.TrimSpace(lines[insertAt]) == "") {
				insertAt++
			}
			lines = append(lines[:insertAt], append([]string{entry}, lines[insertAt:]...)...)
		}
		documents[index] = strings.Join(lines, "\n")
	}
	if matched != 1 {
		return nil, fmt.Errorf("expected exactly one platform-internal-services Secret in foundation desired state, found %d", matched)
	}
	updated := []byte(strings.Join(documents, "\n---\n"))
	if !bytes.Contains(updated, []byte("  "+gitOpsObserverSecretKey+": "+encoded)) {
		return nil, errors.New("Argo CD observer token did not persist into foundation desired state")
	}
	return updated, nil
}

func (r *Runner) persistGitOpsObserverTokenDesiredState(token string) error {
	raw, err := r.readFile(foundationManifestPath)
	if err != nil {
		return fmt.Errorf("read authoritative foundation manifest before persisting Argo CD observer token: %w", err)
	}
	updated, err := upsertGitOpsObserverTokenInFoundationManifest(raw, token)
	if err != nil {
		return err
	}
	if err = r.system.WriteFile(foundationManifestPath, updated, 0o600); err != nil {
		return fmt.Errorf("persist Argo CD observer token in authoritative foundation manifest: %w", err)
	}
	return nil
}

func (r *Runner) persistGitOpsObserverToken(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("Argo CD observer token is empty")
	}
	if err := r.persistGitOpsObserverTokenDesiredState(token); err != nil {
		return err
	}
	patchRaw, _ := json.Marshal(map[string]any{"data": map[string]string{gitOpsObserverSecretKey: base64.StdEncoding.EncodeToString([]byte(token))}})
	path := "/var/lib/4so-platform-installer/secrets/argocd-observer-token.patch.json"
	if err := r.system.WriteFile(path, patchRaw, 0o600); err != nil {
		return err
	}
	defer func() {
		if remover, ok := r.system.(interface{ Remove(string) error }); ok {
			_ = remover.Remove(path)
		}
	}()
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	if err := r.system.Run(ctx, kubectl, []string{"--kubeconfig", "/etc/rancher/rke2/rke2.yaml", "-n", "platform-system", "patch", "secret/platform-internal-services", "--type=merge", "--patch-file", path}, nil); err != nil {
		return fmt.Errorf("persist Argo CD observer token: %w", err)
	}
	return nil
}

func (r *Runner) ensureGitOpsObserverToken(ctx context.Context) error {
	if r.simulation {
		return nil
	}
	if err := r.configureGitOpsObserverAccount(ctx); err != nil {
		return err
	}
	baseURL, err := r.gitOpsInternalURL(ctx)
	if err != nil {
		return err
	}
	existing, adminPassword, err := r.gitOpsBootstrapSecrets(ctx)
	if err != nil {
		return err
	}
	var token string
	var generated bool
	client := argoHTTPClient()
	err = waitUntil(ctx, 2*time.Second, 2*time.Minute, func() error {
		var probeErr error
		token, generated, probeErr = bootstrapArgoObserverToken(ctx, client, baseURL, adminPassword, existing)
		return probeErr
	})
	if err != nil {
		return fmt.Errorf("establish Argo CD observer token: %w", err)
	}
	if generated || strings.TrimSpace(existing) != strings.TrimSpace(token) {
		if err = r.persistGitOpsObserverToken(ctx, token); err != nil {
			return err
		}
	} else if err = r.persistGitOpsObserverTokenDesiredState(token); err != nil {
		// A valid live token can predate the current desired-state authority.
		// Reconcile it into the static foundation manifest without rotating it.
		return err
	}
	kubectl := "/var/lib/rancher/rke2/bin/kubectl"
	kubeconfig := "/etc/rancher/rke2/rke2.yaml"
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "rollout", "restart", "deployment/platform-api"}, nil); err != nil {
		return fmt.Errorf("restart Platform API after Argo CD observer bootstrap: %w", err)
	}
	if err = r.system.Run(ctx, kubectl, []string{"--kubeconfig", kubeconfig, "-n", "platform-system", "rollout", "status", "deployment/platform-api", "--timeout=10m"}, nil); err != nil {
		return fmt.Errorf("wait for Platform API after Argo CD observer bootstrap: %w", err)
	}
	return nil
}
