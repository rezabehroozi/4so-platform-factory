package main

import (
	"strings"
	"testing"
)

func readyDaprDeployment(name, container, image string) *kubeDeployment {
	replicas := int32(1)
	var deployment kubeDeployment
	deployment.Metadata.Name = name
	deployment.Metadata.Generation = 7
	deployment.Spec.Replicas = &replicas
	deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, struct {
		Name  string `json:"name"`
		Image string `json:"image"`
		Env   []struct {
			Name  string `json:"name"`
			Value string `json:"value,omitempty"`
		} `json:"env,omitempty"`
	}{Name: container, Image: image})
	deployment.Status.ObservedGeneration = 7
	deployment.Status.Replicas = 1
	deployment.Status.UpdatedReplicas = 1
	deployment.Status.AvailableReplicas = 1
	return &deployment
}

func TestVerifyDeploymentReadyExactRejectsImageAndReadinessDrift(t *testing.T) {
	const image = "zot.internal.example/dapr/operator@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	deployment := readyDaprDeployment("dapr-operator", "dapr-operator", image)
	if _, err := verifyDeploymentReadyExact(deployment, "dapr-operator", "dapr-operator", image); err != nil {
		t.Fatalf("valid observed Dapr Deployment rejected: %v", err)
	}

	deployment = readyDaprDeployment("dapr-operator", "dapr-operator", image)
	deployment.Spec.Template.Spec.Containers[0].Image = strings.Replace(image, "aaaa", "bbbb", 1)
	if _, err := verifyDeploymentReadyExact(deployment, "dapr-operator", "dapr-operator", image); err == nil || !strings.Contains(err.Error(), "DAPR_OBSERVED_IMAGE_MISMATCH") {
		t.Fatalf("Dapr observed image substitution accepted: %v", err)
	}

	deployment = readyDaprDeployment("dapr-operator", "dapr-operator", image)
	deployment.Status.ObservedGeneration = 6
	if _, err := verifyDeploymentReadyExact(deployment, "dapr-operator", "dapr-operator", image); err == nil || !strings.Contains(err.Error(), "DAPR_OBSERVED_DEPLOYMENT_NOT_READY") {
		t.Fatalf("stale Dapr Deployment generation accepted: %v", err)
	}

	deployment = readyDaprDeployment("dapr-operator", "dapr-operator", image)
	deployment.Status.AvailableReplicas = 0
	if _, err := verifyDeploymentReadyExact(deployment, "dapr-operator", "dapr-operator", image); err == nil || !strings.Contains(err.Error(), "DAPR_OBSERVED_DEPLOYMENT_NOT_READY") {
		t.Fatalf("unavailable Dapr Deployment accepted: %v", err)
	}
}

func TestVerifyInjectorObservedPolicyPinsSidecarAndHardening(t *testing.T) {
	const sidecar = "zot.internal.example/dapr/sidecar@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	env := map[string]string{
		"SIDECAR_IMAGE": sidecar,
		"SIDECAR_RUN_AS_NON_ROOT": "true",
		"SIDECAR_DROP_ALL_CAPABILITIES": "true",
		"SIDECAR_READ_ONLY_ROOT_FILESYSTEM": "true",
	}
	if err := verifyInjectorObservedPolicy(env, sidecar); err != nil {
		t.Fatalf("valid observed injector policy rejected: %v", err)
	}
	for _, key := range []string{"SIDECAR_IMAGE", "SIDECAR_RUN_AS_NON_ROOT", "SIDECAR_DROP_ALL_CAPABILITIES", "SIDECAR_READ_ONLY_ROOT_FILESYSTEM"} {
		drifted := map[string]string{}
		for k, v := range env {
			drifted[k] = v
		}
		if key == "SIDECAR_IMAGE" {
			drifted[key] = "ghcr.io/dapr/daprd:latest"
		} else {
			drifted[key] = "false"
		}
		if err := verifyInjectorObservedPolicy(drifted, sidecar); err == nil || !strings.Contains(err.Error(), "DAPR_OBSERVED_INJECTOR_POLICY_MISMATCH") {
			t.Fatalf("injector policy drift %s accepted: %v", key, err)
		}
	}
}
