package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"platform.4so.io/factory/internal/fielddiagnostics"
)

func fieldDiagnosticsCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "verify-report":
		verifyFieldDiagnosticReport(args[1:])
	case "fetch-report":
		fetchFieldDiagnosticReport(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func verifyFieldDiagnosticReport(args []string) {
	fs := flag.NewFlagSet("field-diagnostics verify-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("f", "", "field diagnostic report (JSON)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*file) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	raw, err := readLimitedFile(*file, maxFieldEvidenceReportBytes)
	if err != nil {
		fatal(err)
	}
	result, err := fielddiagnostics.Verify(raw)
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func fetchFieldDiagnosticReport(args []string) {
	fs := flag.NewFlagSet("field-diagnostics fetch-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
	output := fs.String("out", "", "output diagnostic report path")
	tokenFile := fs.String("token-file", "", "file containing bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*installerURL) == "" || strings.TrimSpace(*output) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	base, err := validateAPIURL(*installerURL)
	if err != nil {
		fatal(err)
	}
	token, err := namedAccessToken(*tokenFile, "PLATFORM_INSTALLER_TOKEN")
	if err != nil {
		fatal(err)
	}
	if strings.TrimSpace(token) == "" {
		fatal(errors.New("bootstrap token is required"))
	}
	client, err := closureHTTPClient(*caFile)
	if err != nil {
		fatal(err)
	}
	raw, result, err := downloadFieldDiagnosticReport(client, base, token)
	if err != nil {
		fatal(err)
	}
	if err = writeAtomicPrivate(*output, raw); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"output": *output, "verification": result})
}

func downloadFieldDiagnosticReport(client *http.Client, base *url.URL, token string) ([]byte, fielddiagnostics.Verification, error) {
	var empty fielddiagnostics.Verification
	endpoint := strings.TrimRight(base.String(), "/") + "/api/v1/diagnostics/report"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, empty, err
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, empty, fmt.Errorf("download field diagnostics: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFieldEvidenceReportBytes+1))
	if err != nil {
		return nil, empty, err
	}
	if len(raw) > maxFieldEvidenceReportBytes {
		return nil, empty, errors.New("field diagnostic report exceeds 4 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, empty, fmt.Errorf("installer returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	result, err := fielddiagnostics.Verify(raw)
	if err != nil {
		return nil, empty, fmt.Errorf("verify downloaded field diagnostics: %w", err)
	}
	return raw, result, nil
}
