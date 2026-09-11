package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"platform.4so.io/factory/internal/airuntime"
	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/redaction"
	"platform.4so.io/factory/internal/releaseartifact"
)

func aiCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
	case "policy":
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		config, err := airuntime.ConfigFromEnv(os.Getenv)
		if err != nil {
			fatal(err)
		}
		runtime, err := airuntime.New(config)
		if err != nil {
			fatal(err)
		}
		printJSON(runtime.Policy())
	case "redact":
		aiRedact(args[1:])
	case "diagnose":
		aiDiagnose(args[1:])
	case "certify-provider":
		aiCertifyProvider(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func loadStrictAIInput(path string) (any, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("AI input file is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > airuntime.AbsoluteMaxInputBytes {
		return nil, fmt.Errorf("AI input file must contain 1-%d bytes", airuntime.AbsoluteMaxInputBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err = dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("AI input must be strict JSON: %w", err)
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("AI input must contain exactly one JSON value")
	}
	return value, nil
}

func aiRedact(args []string) {
	fs := flag.NewFlagSet("ai redact", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "strict JSON input file")
	if err := fs.Parse(args); err != nil || strings.TrimSpace(*file) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	value, err := loadStrictAIInput(*file)
	if err != nil {
		fatal(err)
	}
	clean, count := redaction.Value(value)
	raw, err := json.Marshal(clean)
	if err != nil {
		fatal(err)
	}
	if findings := redaction.Detect(raw); len(findings) != 0 {
		fatal(fmt.Errorf("redaction invariant failed: %s", strings.Join(findings, ",")))
	}
	printJSON(map[string]any{"redacted": clean, "redactionCount": count, "safeForAIEgress": true})
}

func aiDiagnose(args []string) {
	fs := flag.NewFlagSet("ai diagnose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "strict JSON failure packet")
	if err := fs.Parse(args); err != nil || strings.TrimSpace(*file) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	value, err := loadStrictAIInput(*file)
	if err != nil {
		fatal(err)
	}
	config, err := airuntime.ConfigFromEnv(os.Getenv)
	if err != nil {
		fatal(err)
	}
	runtime, err := airuntime.New(config)
	if err != nil {
		fatal(err)
	}
	if !runtime.Enabled() {
		fatal(errors.New("AI runtime is disabled"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := runtime.Generate(ctx, airuntime.Request{
		Purpose:    "lab-failure-diagnosis",
		PromptID:   airuntime.PromptLabFailureDiagnosis,
		System:     airuntime.DiagnosisSystem(),
		Input:      map[string]any{"failurePacket": value, "constraints": []string{"advisory-only", "no PASS authority", "no Physical PASS authority", "no mutation authority"}},
		JSONSchema: airuntime.DiagnosisSchema(),
	})
	if err != nil {
		fatal(err)
	}
	diagnosis, err := airuntime.ParseDiagnosis(result.JSON)
	if err != nil {
		fatal(fmt.Errorf("AI diagnosis output rejected: %w", err))
	}
	printJSON(map[string]any{
		"status":       "OK",
		"advisoryOnly": true,
		"diagnosis":    diagnosis,
		"runtime": map[string]any{
			"provider": result.Provider, "model": result.Model, "promptId": result.PromptID,
			"promptDigest": result.PromptDigest, "contextDigest": result.ContextDigest, "outputDigest": result.OutputDigest,
			"redactionCount": result.RedactionCount, "inputBytes": result.InputBytes, "usage": result.Usage,
		},
	})
}

func aiCertifyProvider(args []string) {
	fs := flag.NewFlagSet("ai certify-provider", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	releasePath := fs.String("release-artifact", "", "exact release ZIP to bind into certification evidence")
	outPath := fs.String("out", "", "private certification evidence JSON output")
	confirmation := fs.String("confirmation", "", "must be CERTIFY because live provider calls may incur cost")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*releasePath) == "" || strings.TrimSpace(*outPath) == "" || *confirmation != "CERTIFY" {
		usage()
		os.Exit(2)
	}
	inspection, err := releaseartifact.Inspect(*releasePath, version)
	if err != nil {
		fatal(fmt.Errorf("inspect exact release artifact: %w", err))
	}
	if inspection.Version != version {
		fatal(fmt.Errorf("platformctl version %s does not match release artifact version %s", version, inspection.Version))
	}
	runningCertifierDigest := bindRunningPlatformctlToExactRelease(inspection)
	config, err := airuntime.ConfigFromEnv(os.Getenv)
	if err != nil {
		fatal(err)
	}
	runtime, err := airuntime.New(config)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	evidence, err := airuntime.CertifyExternalProvider(ctx, runtime, inspection.Version, inspection.Digest, runningCertifierDigest, time.Now().UTC())
	if err != nil {
		fatal(err)
	}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		fatal(err)
	}
	raw = append(raw, '\n')
	if err = durablefile.Replace(strings.TrimSpace(*outPath), raw, 0o700, 0o600); err != nil {
		fatal(fmt.Errorf("persist AI provider certification evidence: %w", err))
	}
	printJSON(map[string]any{
		"status":                     "PASS",
		"authority":                  evidence.Authority,
		"releaseVersion":             evidence.ReleaseVersion,
		"releaseDigest":              evidence.ReleaseDigest,
		"certifierBinaryDigest":      evidence.CertifierBinaryDigest,
		"provider":                   evidence.Provider,
		"model":                      evidence.Model,
		"providerTransportAuthority": evidence.ProviderTransportAuthority,
		"evidenceDigest":             evidence.EvidenceDigest,
		"evidenceFile":               strings.TrimSpace(*outPath),
		"advisoryOnly":               true,
		"canDecidePass":              false,
		"canDecidePhysicalPass":      false,
	})
}
