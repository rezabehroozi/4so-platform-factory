package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"platform.4so.io/factory/internal/buildinfo"
	"platform.4so.io/factory/internal/openchoreo"
)

const (
	executorAuthority        = "OPENCHOREO_TARGET_EXECUTOR_RUNTIME_V1"
	ownershipAuthority       = "OPENCHOREO_TARGET_OWNERSHIP_RECEIPT_V1"
	observedReceiptAuthority = "OPENCHOREO_TARGET_OBSERVED_RECEIPT_V1"
	ownershipName            = "4so-openchoreo-runtime-owner"
	maxRenderBytes           = 64 * 1024 * 1024
	maxKubeResponseBytes     = 4 * 1024 * 1024
	serviceAccountRoot       = "/var/run/secrets/kubernetes.io/serviceaccount"
)

type lifecycleConfig struct {
	Action           openchoreo.LifecycleAction
	ReceiptNamespace string
	ReceiptName      string
	Source           openchoreo.RuntimeSource
	SourceDigest     string
	OperationID      string
	FenceToken       int64
	ReceiptAuthority string
	Suppressions     []string
}

func parseSuppressions(raw string) ([]string, error) {
	var values []string
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(raw)))
	if err := decoder.Decode(&values); err != nil {
		return nil, fmt.Errorf("decode OpenChoreo native suppressions: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("OpenChoreo native suppressions contain trailing JSON")
	}
	allowed := map[string]bool{
		"networking-and-ingress-native": true,
		"observability-native":          true,
		"operator-lifecycle-native":     true,
		"tenancy-native":                true,
	}
	seen := map[string]bool{}
	order := []string{"networking-and-ingress-native", "observability-native", "operator-lifecycle-native", "tenancy-native"}
	for _, rawValue := range values {
		value := strings.ToLower(strings.TrimSpace(rawValue))
		if !allowed[value] || seen[value] {
			return nil, fmt.Errorf("OpenChoreo native suppression is invalid: %q", rawValue)
		}
		seen[value] = true
	}
	out := make([]string, 0, len(seen))
	for _, value := range order {
		if seen[value] {
			out = append(out, value)
		}
	}
	return out, nil
}

func strictRuntimeSource(raw string) (openchoreo.RuntimeSource, string, error) {
	var source openchoreo.RuntimeSource
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return source, "", fmt.Errorf("decode OpenChoreo runtime source: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return source, "", errors.New("OpenChoreo runtime source contains trailing JSON")
	}
	if err := openchoreo.ValidateRuntimeExecutionSource(source); err != nil {
		return source, "", err
	}
	digest, err := openchoreo.RuntimeSourceDigest(source)
	if err != nil {
		return source, "", err
	}
	return source, digest, nil
}

func loadLifecycleConfig(args []string) (lifecycleConfig, error) {
	var cfg lifecycleConfig
	set := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	action := set.String("action", "", "install, upgrade, or remove")
	set.StringVar(&cfg.ReceiptNamespace, "receipt-namespace", "", "namespace for product-owned observed receipt")
	set.StringVar(&cfg.ReceiptName, "receipt-name", "", "name for product-owned observed receipt")
	if err := set.Parse(args); err != nil || len(set.Args()) != 0 {
		return cfg, errors.New("OpenChoreo lifecycle arguments are invalid")
	}
	var err error
	cfg.Action, err = openchoreo.NormalizeLifecycleAction(openchoreo.LifecycleAction(*action))
	if err != nil {
		return cfg, err
	}
	cfg.ReceiptNamespace = strings.TrimSpace(cfg.ReceiptNamespace)
	cfg.ReceiptName = strings.TrimSpace(cfg.ReceiptName)
	if cfg.ReceiptNamespace == "" || cfg.ReceiptName == "" || strings.ContainsAny(cfg.ReceiptNamespace+cfg.ReceiptName, " /\\\t\r\n") {
		return cfg, errors.New("OpenChoreo receipt identity is invalid")
	}
	cfg.OperationID = strings.TrimSpace(os.Getenv("FOURSO_OPENCHOREO_OPERATION_ID"))
	cfg.ReceiptAuthority = strings.TrimSpace(os.Getenv("FOURSO_OPENCHOREO_RECEIPT_AUTHORITY"))
	if cfg.ReceiptAuthority != observedReceiptAuthority {
		return cfg, errors.New("OpenChoreo observed receipt authority is invalid")
	}
	cfg.Suppressions, err = parseSuppressions(os.Getenv("FOURSO_OPENCHOREO_NATIVE_SUPPRESSIONS_JSON"))
	if err != nil {
		return cfg, err
	}
	fence, fenceErr := strconv.ParseInt(strings.TrimSpace(os.Getenv("FOURSO_OPENCHOREO_TASK_FENCE_TOKEN")), 10, 64)
	if cfg.OperationID == "" || cfg.ReceiptAuthority == "" || fenceErr != nil || fence <= 0 {
		return cfg, errors.New("OpenChoreo operation identity/fence environment is invalid")
	}
	cfg.FenceToken = fence
	cfg.Source, cfg.SourceDigest, err = strictRuntimeSource(os.Getenv("FOURSO_OPENCHOREO_RUNTIME_SOURCE_JSON"))
	if err != nil {
		return cfg, err
	}
	if expected := strings.TrimSpace(os.Getenv("FOURSO_OPENCHOREO_RUNTIME_SOURCE_DIGEST")); expected == "" || expected != cfg.SourceDigest {
		return cfg, errors.New("OpenChoreo runtime source digest does not match task authority")
	}
	return cfg, nil
}

func runLifecycle(args []string) error {
	cfg, err := loadLifecycleConfig(args)
	if err != nil {
		return err
	}
	if err = verifyRuntimeArtifacts(cfg.Source); err != nil {
		return err
	}
	kubeconfig, err := prepareHelmKubeconfig()
	if err != nil {
		return err
	}
	defer os.Remove(kubeconfig)
	previousKubeconfig, hadKubeconfig := os.LookupEnv("KUBECONFIG")
	if err = os.Setenv("KUBECONFIG", kubeconfig); err != nil {
		return err
	}
	defer func() {
		if hadKubeconfig {
			_ = os.Setenv("KUBECONFIG", previousKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	switch cfg.Action {
	case openchoreo.ActionInstall, openchoreo.ActionUpgrade:
		if err = installOrUpgrade(ctx, cfg); err != nil {
			return err
		}
		phase := "Installed"
		if cfg.Action == openchoreo.ActionUpgrade {
			phase = "Upgraded"
		}
		return writeReceipt(ctx, cfg, true, phase)
	case openchoreo.ActionRemove:
		if err = removeRuntime(ctx, cfg); err != nil {
			return err
		}
		return writeReceipt(ctx, cfg, false, "Removed")
	default:
		return errors.New("OpenChoreo lifecycle action is unsupported")
	}
}

func runPostRenderer() error {
	source, digest, err := strictRuntimeSource(os.Getenv("FOURSO_OPENCHOREO_RUNTIME_SOURCE_JSON"))
	if err != nil {
		return err
	}
	if expected := strings.TrimSpace(os.Getenv("FOURSO_OPENCHOREO_RUNTIME_SOURCE_DIGEST")); expected == "" || expected != digest {
		return errors.New("OpenChoreo post-render source digest mismatch")
	}
	return postRender(os.Stdin, os.Stdout, source)
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(buildinfo.Version)
		return
	}
	var err error
	if len(os.Args) == 1 {
		err = runPostRenderer()
	} else if os.Args[1] == "lifecycle" {
		err = runLifecycle(os.Args[2:])
	} else {
		err = errors.New("usage: openchoreo-runtime [version|--version|lifecycle ...]")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s_BLOCKED %v\n", executorAuthority, err)
		os.Exit(2)
	}
}
