package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/openchoreo"
)

type kubeObject struct {
	Metadata struct {
		ResourceVersion string            `json:"resourceVersion"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Data map[string]string `json:"data"`
}

func kubeClient() (*http.Client, string, error) {
	token, err := os.ReadFile(serviceAccountRoot + "/token")
	if err != nil || strings.TrimSpace(string(token)) == "" {
		return nil, "", errors.New("OpenChoreo executor service-account token is unavailable")
	}
	ca, err := os.ReadFile(serviceAccountRoot + "/ca.crt")
	if err != nil {
		return nil, "", errors.New("OpenChoreo executor service-account CA is unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, "", errors.New("OpenChoreo executor service-account CA is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, strings.TrimSpace(string(token)), nil
}

func kubeRequest(ctx context.Context, client *http.Client, token, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://kubernetes.default.svc"+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if len(body) != 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxKubeResponseBytes+1))
	if err != nil {
		return res.StatusCode, nil, err
	}
	if len(raw) > maxKubeResponseBytes {
		return res.StatusCode, nil, errors.New("Kubernetes API response exceeds bound")
	}
	return res.StatusCode, raw, nil
}

func configMapPath(namespace, name string) string {
	return "/api/v1/namespaces/" + url.PathEscape(namespace) + "/configmaps/" + url.PathEscape(name)
}

func getConfigMap(ctx context.Context, namespace, name string) (kubeObject, bool, error) {
	var out kubeObject
	client, token, err := kubeClient()
	if err != nil {
		return out, false, err
	}
	status, raw, err := kubeRequest(ctx, client, token, http.MethodGet, configMapPath(namespace, name), nil)
	if err != nil {
		return out, false, err
	}
	if status == http.StatusNotFound {
		return out, false, nil
	}
	if status != http.StatusOK {
		return out, false, fmt.Errorf("Kubernetes ConfigMap read failed: status=%d body=%s", status, boundedOutput(raw))
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		return out, false, err
	}
	return out, true, nil
}

func upsertConfigMap(ctx context.Context, namespace, name, authority string, data map[string]string) error {
	client, token, err := kubeClient()
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		current, found, getErr := getConfigMap(ctx, namespace, name)
		if getErr != nil {
			return getErr
		}
		metadata := map[string]any{
			"name": name, "namespace": namespace,
			"annotations": map[string]string{"platform.4so.io/authority": authority, "platform.4so.io/managed": "true"},
		}
		method := http.MethodPost
		path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/configmaps"
		if found {
			metadata["resourceVersion"] = current.Metadata.ResourceVersion
			method = http.MethodPut
			path = configMapPath(namespace, name)
		}
		body, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata, "data": data})
		status, raw, reqErr := kubeRequest(ctx, client, token, method, path, body)
		if reqErr != nil {
			return reqErr
		}
		if status == http.StatusOK || status == http.StatusCreated {
			return nil
		}
		if status == http.StatusConflict {
			continue
		}
		return fmt.Errorf("Kubernetes ConfigMap write failed: status=%d body=%s", status, boundedOutput(raw))
	}
	return errors.New("Kubernetes ConfigMap write conflict did not converge")
}

func deleteConfigMap(ctx context.Context, namespace, name string) error {
	client, token, err := kubeClient()
	if err != nil {
		return err
	}
	status, raw, err := kubeRequest(ctx, client, token, http.MethodDelete, configMapPath(namespace, name), []byte(`{"propagationPolicy":"Background"}`))
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusAccepted || status == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("Kubernetes ConfigMap delete failed: status=%d body=%s", status, boundedOutput(raw))
}

func validateOwnership(ctx context.Context, cfg lifecycleConfig, require bool) error {
	current, found, err := getConfigMap(ctx, cfg.ReceiptNamespace, ownershipName)
	if err != nil {
		return err
	}
	if !found {
		if require {
			return errors.New("OpenChoreo managed ownership receipt is missing")
		}
		return nil
	}
	if current.Metadata.Annotations["platform.4so.io/authority"] != ownershipAuthority || current.Data["managed"] != "true" {
		return errors.New("OpenChoreo runtime ownership is foreign or ambiguous")
	}
	if !require {
		return errors.New("OpenChoreo managed ownership already exists")
	}
	expected := cfg.SourceDigest
	if cfg.Action != openchoreo.ActionInstall {
		expected = strings.TrimSpace(os.Getenv("FOURSO_OPENCHOREO_EXPECTED_OBSERVED_SOURCE_DIGEST"))
		if expected == "" {
			return errors.New("OpenChoreo expected observed source fence is missing")
		}
	}
	if got := strings.TrimSpace(current.Data["runtimeSourceDigest"]); expected != "" && got != expected {
		return errors.New("OpenChoreo target ownership source fence changed")
	}
	return nil
}

func writeOwnership(ctx context.Context, cfg lifecycleConfig) error {
	suppressions, _ := json.Marshal(cfg.Suppressions)
	return upsertConfigMap(ctx, cfg.ReceiptNamespace, ownershipName, ownershipAuthority, map[string]string{
		"managed": "true", "runtimeSourceDigest": cfg.SourceDigest, "version": cfg.Source.Version,
		"upstreamCommit": cfg.Source.UpstreamCommit, "operationId": cfg.OperationID,
		"taskFenceToken": strconv.FormatInt(cfg.FenceToken, 10), "nativeSuppressions": string(suppressions),
	})
}

func writeReceipt(ctx context.Context, cfg lifecycleConfig, installed bool, phase string) error {
	suppressions, _ := json.Marshal(cfg.Suppressions)
	data := map[string]string{
		"operationId": cfg.OperationID,
		"taskFenceToken": strconv.FormatInt(cfg.FenceToken, 10),
		"installed": strconv.FormatBool(installed),
		"phase": phase,
		"action": string(cfg.Action),
		"nativeSuppressions": string(suppressions),
	}
	if installed {
		data["runtimeSourceDigest"] = cfg.SourceDigest
		data["version"] = cfg.Source.Version
		data["upstreamCommit"] = cfg.Source.UpstreamCommit
	}
	return upsertConfigMap(ctx, cfg.ReceiptNamespace, cfg.ReceiptName, cfg.ReceiptAuthority, data)
}
