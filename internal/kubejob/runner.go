package kubejob

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/durablefile"
)

const (
	AnnotationOwner       = "platform.4so.io/job-owner"
	AnnotationOperationID = "platform.4so.io/operation-id"
	AnnotationJobName     = "platform.4so.io/job-name"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

type Options struct {
	System       bootstrap.System
	StateDir     string
	StateSubdir  string
	Kubeconfig   string
	Namespace    string
	Owner        string
	OperationID  string
	Name         string
	LegacyName   string
	Manifest     string
	Timeout      time.Duration
	PollInterval time.Duration
}

type identity struct {
	Owner           string `json:"owner"`
	OperationID     string `json:"operationId"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
	ManifestDigest  string `json:"manifestDigest"`
}

type snapshot struct {
	Metadata struct {
		Name            string            `json:"name"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Status struct {
		Conditions []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

func Execute(ctx context.Context, options Options) error {
	if options.System == nil {
		return errors.New("Kubernetes Job system is required")
	}
	if strings.TrimSpace(options.StateDir) == "" || strings.TrimSpace(options.StateSubdir) == "" {
		return errors.New("Kubernetes Job durable state directory is required")
	}
	if strings.TrimSpace(options.Kubeconfig) == "" || strings.TrimSpace(options.Namespace) == "" {
		return errors.New("Kubernetes Job kubeconfig and namespace are required")
	}
	if strings.TrimSpace(options.Owner) == "" || strings.TrimSpace(options.OperationID) == "" {
		return errors.New("Kubernetes Job owner and operation identity are required")
	}
	if !validName(options.Name) {
		return fmt.Errorf("Kubernetes Job name %q is invalid", options.Name)
	}
	if options.LegacyName != "" && !validName(options.LegacyName) {
		return fmt.Errorf("legacy Kubernetes Job name %q is invalid", options.LegacyName)
	}
	if strings.TrimSpace(options.Manifest) == "" {
		return errors.New("Kubernetes Job manifest is required")
	}
	if options.Timeout <= 0 {
		return errors.New("Kubernetes Job timeout must be positive")
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 500 * time.Millisecond
	}

	manifestDir := filepath.Join(options.StateDir, options.StateSubdir)
	manifestPath := filepath.Join(manifestDir, options.Name+".yaml")
	manifestDigest := digestManifest(options.Manifest)
	identityPath := filepath.Join(manifestDir, "job-identities", options.Name+".json")
	stored, hasIdentity, err := loadIdentity(identityPath)
	if err != nil {
		return err
	}
	if hasIdentity {
		if stored.Owner != options.Owner || stored.OperationID != options.OperationID || stored.Name != options.Name || stored.UID == "" {
			return fmt.Errorf("durable Kubernetes Job identity does not match requested operation %s/%s", options.Owner, options.OperationID)
		}
		if stored.ManifestDigest == "" {
			return fmt.Errorf("Kubernetes Job %s durable identity predates manifest-digest authority; blind replay is forbidden", options.Name)
		}
		if stored.ManifestDigest != manifestDigest {
			return fmt.Errorf("Kubernetes Job %s manifest digest changed from %s to %s; replay is forbidden", options.Name, stored.ManifestDigest, manifestDigest)
		}
		current, exists, inspectErr := inspect(ctx, options, options.Name)
		if inspectErr != nil {
			return inspectErr
		}
		if !exists {
			return fmt.Errorf("Kubernetes Job %s with durable UID %s disappeared; side effect is uncertain and blind replay is forbidden", options.Name, stored.UID)
		}
		if err = verify(current, options, stored.UID); err != nil {
			return err
		}
		return wait(ctx, options, stored.UID)
	}

	if current, exists, inspectErr := inspect(ctx, options, options.Name); inspectErr != nil {
		return inspectErr
	} else if exists {
		return fmt.Errorf("Kubernetes Job %s exists without durable identity (UID %s); refusing adoption or replay", options.Name, current.Metadata.UID)
	}
	if options.LegacyName != "" && options.LegacyName != options.Name {
		if legacy, exists, inspectErr := inspect(ctx, options, options.LegacyName); inspectErr != nil {
			return inspectErr
		} else if exists {
			return fmt.Errorf("legacy Kubernetes Job %s exists with UID %s but has no durable identity; refusing upgrade-time replay", options.LegacyName, legacy.Metadata.UID)
		}
	}
	if err = durablefile.Replace(manifestPath, []byte(options.Manifest), 0o700, 0o600); err != nil {
		return fmt.Errorf("persist Kubernetes Job manifest: %w", err)
	}

	raw, err := kubectlOutput(ctx, options, "create", "-f", manifestPath, "-o", "json")
	if err != nil {
		return fmt.Errorf("create Kubernetes Job %s: %w", options.Name, err)
	}
	created, err := decodeSnapshot(raw)
	if err != nil {
		return fmt.Errorf("Kubernetes Job %s was created but returned identity is unusable; refusing replay: %w", options.Name, err)
	}
	if err = verify(created, options, ""); err != nil {
		return fmt.Errorf("created Kubernetes Job identity is invalid: %w", err)
	}
	stored = identity{Owner: options.Owner, OperationID: options.OperationID, Name: options.Name, UID: created.Metadata.UID, ResourceVersion: created.Metadata.ResourceVersion, ManifestDigest: manifestDigest}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Kubernetes Job identity: %w", err)
	}
	if err = durablefile.Replace(identityPath, append(encoded, '\n'), 0o700, 0o600); err != nil {
		return fmt.Errorf("Kubernetes Job %s was created with UID %s but durable identity persistence failed; refusing replay: %w", options.Name, created.Metadata.UID, err)
	}
	return wait(ctx, options, created.Metadata.UID)
}

func digestManifest(manifest string) string {
	sum := sha256.Sum256([]byte(manifest))
	return fmt.Sprintf("sha256:%x", sum[:])
}

func validName(value string) bool {
	return len(value) > 0 && len(value) <= 63 && dnsLabel.MatchString(value)
}

func loadIdentity(path string) (identity, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return identity{}, false, nil
	}
	if err != nil {
		return identity{}, false, fmt.Errorf("read durable Kubernetes Job identity: %w", err)
	}
	var value identity
	if err = json.Unmarshal(raw, &value); err != nil {
		return identity{}, false, fmt.Errorf("decode durable Kubernetes Job identity: %w", err)
	}
	return value, true, nil
}

func inspect(ctx context.Context, options Options, name string) (snapshot, bool, error) {
	raw, err := kubectlOutput(ctx, options, "get", "job", name, "--ignore-not-found=true", "-o", "json")
	if err != nil {
		return snapshot{}, false, fmt.Errorf("inspect Kubernetes Job %s: %w", name, err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return snapshot{}, false, nil
	}
	value, err := decodeSnapshot(raw)
	if err != nil {
		return snapshot{}, false, fmt.Errorf("decode Kubernetes Job %s: %w", name, err)
	}
	return value, true, nil
}

func decodeSnapshot(raw []byte) (snapshot, error) {
	var value snapshot
	if len(raw) == 0 {
		return value, errors.New("empty Kubernetes Job response")
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, err
	}
	if strings.TrimSpace(value.Metadata.Name) == "" || strings.TrimSpace(value.Metadata.UID) == "" || strings.TrimSpace(value.Metadata.ResourceVersion) == "" {
		return value, errors.New("name, UID and resourceVersion are required")
	}
	return value, nil
}

func verify(value snapshot, options Options, expectedUID string) error {
	if value.Metadata.Name != options.Name {
		return fmt.Errorf("Kubernetes Job name changed from %s to %s", options.Name, value.Metadata.Name)
	}
	if expectedUID != "" && value.Metadata.UID != expectedUID {
		return fmt.Errorf("Kubernetes Job %s UID changed from %s to %s; refusing same-name replacement", options.Name, expectedUID, value.Metadata.UID)
	}
	annotations := value.Metadata.Annotations
	if annotations[AnnotationOwner] != options.Owner || annotations[AnnotationOperationID] != options.OperationID || annotations[AnnotationJobName] != options.Name {
		return fmt.Errorf("Kubernetes Job %s ownership annotations do not match operation %s/%s", options.Name, options.Owner, options.OperationID)
	}
	return nil
}

func wait(ctx context.Context, options Options, uid string) error {
	waitCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	for {
		current, exists, err := inspect(waitCtx, options, options.Name)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("Kubernetes Job %s with UID %s disappeared before durable completion", options.Name, uid)
		}
		if err = verify(current, options, uid); err != nil {
			return err
		}
		for _, condition := range current.Status.Conditions {
			if !strings.EqualFold(condition.Status, "True") {
				continue
			}
			switch condition.Type {
			case "Complete":
				return nil
			case "Failed":
				detail := strings.TrimSpace(strings.Join([]string{condition.Reason, condition.Message}, ": "))
				if detail == ":" || detail == "" {
					detail = "Job reported Failed=True"
				}
				return fmt.Errorf("Kubernetes Job %s failed: %s", options.Name, detail)
			}
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("wait for Kubernetes Job %s UID %s: %w", options.Name, uid, waitCtx.Err())
		case <-time.After(options.PollInterval):
		}
	}
}

func kubectlOutput(ctx context.Context, options Options, args ...string) ([]byte, error) {
	all := []string{"--kubeconfig", options.Kubeconfig, "-n", options.Namespace}
	all = append(all, args...)
	return options.System.Output(ctx, "/var/lib/rancher/rke2/bin/kubectl", all, nil)
}
