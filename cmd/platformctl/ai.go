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
	"platform.4so.io/factory/internal/redaction"
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
