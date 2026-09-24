package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"platform.4so.io/factory/internal/openchoreo"
)

func boundedOutput(raw []byte) string {
	const limit = 4096
	if len(raw) > limit {
		raw = raw[len(raw)-limit:]
	}
	return strings.TrimSpace(string(raw))
}

func runHelm(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "/usr/local/bin/helm", args...)
	cmd.Env = append(os.Environ(), "HOME=/home/nonroot")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("helm %s failed: %s", strings.Join(args, " "), boundedOutput(raw))
	}
	return nil
}

func helmReleaseExists(ctx context.Context, release, namespace string) (bool, error) {
	cmd := exec.CommandContext(ctx, "/usr/local/bin/helm", "status", release, "--namespace", namespace, "--output", "json")
	cmd.Env = append(os.Environ(), "HOME=/home/nonroot")
	raw, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	lower := strings.ToLower(string(raw))
	if strings.Contains(lower, "release: not found") || strings.Contains(lower, "release not found") {
		return false, nil
	}
	return false, fmt.Errorf("helm status %s failed: %s", release, boundedOutput(raw))
}

func planeArgs(source openchoreo.RuntimeSource, planeName string) (release, namespace, chart, values string, err error) {
	switch planeName {
	case "control-plane":
		return "openchoreo-control-plane", "openchoreo-control-plane", "/runtime/openchoreo-control-plane.tgz", "/runtime/control-plane-values.yaml", nil
	case "data-plane":
		return "openchoreo-data-plane", "openchoreo-data-plane", "/runtime/openchoreo-data-plane.tgz", "/runtime/data-plane-values.yaml", nil
	default:
		return "", "", "", "", fmt.Errorf("unsupported OpenChoreo plane %s", planeName)
	}
}

func installOrUpgrade(ctx context.Context, cfg lifecycleConfig) error {
	if err := validateOwnership(ctx, cfg, cfg.Action == openchoreo.ActionUpgrade); err != nil {
		return err
	}
	if cfg.Action == openchoreo.ActionInstall {
		for _, name := range []string{"control-plane", "data-plane"} {
			release, namespace, _, _, _ := planeArgs(cfg.Source, name)
			exists, err := helmReleaseExists(ctx, release, namespace)
			if err != nil {
				return err
			}
			if exists {
				return fmt.Errorf("OpenChoreo foreign/pre-existing Helm release blocks managed install: %s", release)
			}
		}
	}
	for _, name := range []string{"control-plane", "data-plane"} {
		release, namespace, chart, values, err := planeArgs(cfg.Source, name)
		if err != nil {
			return err
		}
		if cfg.Action == openchoreo.ActionUpgrade {
			exists, statusErr := helmReleaseExists(ctx, release, namespace)
			if statusErr != nil {
				return statusErr
			}
			if !exists {
				return fmt.Errorf("OpenChoreo managed upgrade requires existing Helm release: %s", release)
			}
		}
		args := []string{"upgrade", "--install", release, chart, "--namespace", namespace, "--create-namespace", "--values", values,
			"--post-renderer", "/usr/local/bin/openchoreo-runtime", "--wait", "--timeout", "10m", "--history-max", "5"}
		if err = runHelm(ctx, args...); err != nil {
			return err
		}
	}
	return writeOwnership(ctx, cfg)
}

func removeRuntime(ctx context.Context, cfg lifecycleConfig) error {
	if err := validateOwnership(ctx, cfg, true); err != nil {
		return err
	}
	for _, name := range []string{"data-plane", "control-plane"} {
		release, namespace, _, _, err := planeArgs(cfg.Source, name)
		if err != nil {
			return err
		}
		if err = runHelm(ctx, "uninstall", release, "--namespace", namespace, "--ignore-not-found", "--wait", "--timeout", "10m"); err != nil {
			return err
		}
	}
	return deleteConfigMap(ctx, cfg.ReceiptNamespace, ownershipName)
}
