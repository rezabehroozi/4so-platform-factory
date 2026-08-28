package kubeworkload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/durablefile"
)

type Options struct {
	System                                       bootstrap.System
	StateDir, StateSubdir, Kubeconfig, Namespace string
	Owner, OperationID, Kind, Name               string
}

type identity struct {
	Owner       string `json:"owner"`
	OperationID string `json:"operationId"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	UID         string `json:"uid"`
}
type snapshot struct {
	Metadata struct {
		UID             string `json:"uid"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int `json:"replicas"`
		Template struct {
			Spec struct {
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

func validate(o Options) error {
	if o.System == nil || strings.TrimSpace(o.StateDir) == "" || strings.TrimSpace(o.StateSubdir) == "" || strings.TrimSpace(o.Kubeconfig) == "" || strings.TrimSpace(o.Namespace) == "" || strings.TrimSpace(o.Owner) == "" || strings.TrimSpace(o.OperationID) == "" || strings.TrimSpace(o.Kind) == "" || strings.TrimSpace(o.Name) == "" {
		return errors.New("Kubernetes workload identity options are incomplete")
	}
	for _, v := range []string{o.Owner, o.OperationID, o.Kind, o.Name} {
		if strings.ContainsAny(v, "/\\\x00") {
			return errors.New("Kubernetes workload identity contains an unsafe path token")
		}
	}
	return nil
}
func identityPath(o Options) string {
	return filepath.Join(o.StateDir, o.StateSubdir, "workload-identities", o.OperationID, o.Kind+"-"+o.Name+".json")
}
func kubectlOutput(ctx context.Context, o Options, args ...string) ([]byte, error) {
	all := []string{"--kubeconfig", o.Kubeconfig, "-n", o.Namespace}
	all = append(all, args...)
	return o.System.Output(ctx, "/var/lib/rancher/rke2/bin/kubectl", all, nil)
}
func inspect(ctx context.Context, o Options) (snapshot, error) {
	raw, err := kubectlOutput(ctx, o, "get", o.Kind, o.Name, "-o", "json")
	if err != nil {
		return snapshot{}, fmt.Errorf("inspect Kubernetes workload %s/%s: %w", o.Kind, o.Name, err)
	}
	var s snapshot
	if err = json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("decode Kubernetes workload %s/%s: %w", o.Kind, o.Name, err)
	}
	if s.Metadata.UID == "" || s.Metadata.ResourceVersion == "" {
		return s, errors.New("Kubernetes workload UID and resourceVersion are required")
	}
	return s, nil
}
func bind(ctx context.Context, o Options) (snapshot, error) {
	if err := validate(o); err != nil {
		return snapshot{}, err
	}
	s, err := inspect(ctx, o)
	if err != nil {
		return s, err
	}
	p := identityPath(o)
	raw, readErr := os.ReadFile(p)
	if readErr == nil {
		var id identity
		if err = json.Unmarshal(raw, &id); err != nil {
			return s, fmt.Errorf("decode durable workload identity: %w", err)
		}
		if id.Owner != o.Owner || id.OperationID != o.OperationID || id.Kind != o.Kind || id.Name != o.Name || id.UID == "" {
			return s, errors.New("durable Kubernetes workload identity does not match operation")
		}
		if id.UID != s.Metadata.UID {
			return s, fmt.Errorf("Kubernetes workload %s/%s UID changed from %s to %s; refusing same-name replacement", o.Kind, o.Name, id.UID, s.Metadata.UID)
		}
		return s, nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return s, fmt.Errorf("read durable workload identity: %w", readErr)
	}
	id := identity{Owner: o.Owner, OperationID: o.OperationID, Kind: o.Kind, Name: o.Name, UID: s.Metadata.UID}
	enc, _ := json.MarshalIndent(id, "", "  ")
	if err = durablefile.Replace(p, append(enc, '\n'), 0o700, 0o600); err != nil {
		return s, fmt.Errorf("persist Kubernetes workload UID before mutation: %w", err)
	}
	return s, nil
}

func Verify(ctx context.Context, o Options) error { _, err := bind(ctx, o); return err }
func VerifyReplicas(ctx context.Context, o Options, replicas int) error {
	s, err := bind(ctx, o)
	if err != nil {
		return err
	}
	if s.Spec.Replicas == nil {
		return fmt.Errorf("Kubernetes workload %s/%s replicas postcondition is unavailable; want %d", o.Kind, o.Name, replicas)
	}
	if *s.Spec.Replicas != replicas {
		return fmt.Errorf("Kubernetes workload %s/%s replicas postcondition mismatch: got %d want %d", o.Kind, o.Name, *s.Spec.Replicas, replicas)
	}
	return nil
}
func VerifyImage(ctx context.Context, o Options, container, image string) error {
	s, err := bind(ctx, o)
	if err != nil {
		return err
	}
	for _, c := range s.Spec.Template.Spec.Containers {
		if c.Name == container {
			if c.Image != image {
				return fmt.Errorf("Kubernetes workload %s/%s container %s image postcondition mismatch: got %s want %s", o.Kind, o.Name, container, c.Image, image)
			}
			return nil
		}
	}
	return fmt.Errorf("container %s not found in %s/%s", container, o.Kind, o.Name)
}
func CurrentImage(ctx context.Context, o Options, container string) (string, error) {
	s, err := bind(ctx, o)
	if err != nil {
		return "", err
	}
	for _, c := range s.Spec.Template.Spec.Containers {
		if c.Name == container {
			return c.Image, nil
		}
	}
	return "", fmt.Errorf("container %s not found in %s/%s", container, o.Kind, o.Name)
}
func Scale(ctx context.Context, o Options, replicas int) error {
	s, err := bind(ctx, o)
	if err != nil {
		return err
	}
	patch := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": s.Metadata.UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": s.Metadata.ResourceVersion}, {"op": "replace", "path": "/spec/replicas", "value": replicas}}
	raw, _ := json.Marshal(patch)
	appliedRaw, err := kubectlOutput(ctx, o, "patch", o.Kind, o.Name, "--type=json", "-p", string(raw))
	if err != nil {
		return fmt.Errorf("identity-fenced scale %s/%s: %w", o.Kind, o.Name, err)
	}
	var applied snapshot
	if err = json.Unmarshal(appliedRaw, &applied); err != nil {
		return fmt.Errorf("decode identity-fenced scale response %s/%s: %w", o.Kind, o.Name, err)
	}
	if applied.Metadata.UID != s.Metadata.UID {
		return fmt.Errorf("identity-fenced scale %s/%s returned UID %s; expected %s", o.Kind, o.Name, applied.Metadata.UID, s.Metadata.UID)
	}
	if applied.Spec.Replicas == nil || *applied.Spec.Replicas != replicas {
		return fmt.Errorf("identity-fenced scale %s/%s did not apply replicas postcondition %d", o.Kind, o.Name, replicas)
	}
	return Verify(ctx, o)
}
func SetImage(ctx context.Context, o Options, container, image string) (string, error) {
	s, err := bind(ctx, o)
	if err != nil {
		return "", err
	}
	idx := -1
	current := ""
	for i, c := range s.Spec.Template.Spec.Containers {
		if c.Name == container {
			idx = i
			current = c.Image
			break
		}
	}
	if idx < 0 {
		return "", fmt.Errorf("container %s not found in %s/%s", container, o.Kind, o.Name)
	}
	if current == image {
		if err = VerifyImage(ctx, o, container, image); err != nil {
			return current, err
		}
		return current, nil
	}
	patch := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": s.Metadata.UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": s.Metadata.ResourceVersion}, {"op": "test", "path": fmt.Sprintf("/spec/template/spec/containers/%d/name", idx), "value": container}, {"op": "test", "path": fmt.Sprintf("/spec/template/spec/containers/%d/image", idx), "value": current}, {"op": "replace", "path": fmt.Sprintf("/spec/template/spec/containers/%d/image", idx), "value": image}}
	raw, _ := json.Marshal(patch)
	appliedRaw, err := kubectlOutput(ctx, o, "patch", o.Kind, o.Name, "--type=json", "-p", string(raw))
	if err != nil {
		return current, fmt.Errorf("identity-fenced image update %s/%s: %w", o.Kind, o.Name, err)
	}
	var applied snapshot
	if err = json.Unmarshal(appliedRaw, &applied); err != nil {
		return current, fmt.Errorf("decode identity-fenced image update response %s/%s: %w", o.Kind, o.Name, err)
	}
	if applied.Metadata.UID != s.Metadata.UID {
		return current, fmt.Errorf("identity-fenced image update %s/%s returned UID %s; expected %s", o.Kind, o.Name, applied.Metadata.UID, s.Metadata.UID)
	}
	appliedImage := ""
	for _, c := range applied.Spec.Template.Spec.Containers {
		if c.Name == container {
			appliedImage = c.Image
			break
		}
	}
	if appliedImage != image {
		return current, fmt.Errorf("identity-fenced image update %s/%s did not apply image postcondition for container %s", o.Kind, o.Name, container)
	}
	if err = Verify(ctx, o); err != nil {
		return current, err
	}
	return current, nil
}
