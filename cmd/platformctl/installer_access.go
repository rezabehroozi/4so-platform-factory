package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"platform.4so.io/factory/internal/installeraccess"
)

const maxInstallerAccessResponseBytes = 1 << 20

func installerAccessCommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "status":
		installerAccessStatusCommand(args[1:])
	case "rotate-token":
		installerAccessRotateCommand(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func installerAccessStatusCommand(args []string) {
	fs := flag.NewFlagSet("installer-access status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
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
	if strings.TrimSpace(*installerURL) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	base, token, client := installerAccessClient(*installerURL, *tokenFile, *caFile)
	status, err := fetchInstallerAccessStatus(client, base, token)
	if err != nil {
		fatal(err)
	}
	printJSON(status)
}

func installerAccessRotateCommand(args []string) {
	fs := flag.NewFlagSet("installer-access rotate-token", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
	tokenFile := fs.String("token-file", "", "file containing current bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	output := fs.String("out-token-file", "", "private file that will receive the new bootstrap token")
	confirmation := fs.String("confirmation", "", "must be exactly ROTATE")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*installerURL) == "" || strings.TrimSpace(*output) == "" || *confirmation != "ROTATE" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	base, token, client := installerAccessClient(*installerURL, *tokenFile, *caFile)
	newToken, err := installeraccess.GenerateToken()
	if err != nil {
		fatal(err)
	}
	pending, absolute, err := stagePrivateToken(*output, []byte(newToken+"\n"))
	if err != nil {
		fatal(err)
	}
	status, err := rotateInstallerToken(client, base, token, newToken)
	if err != nil {
		// A connection can disappear after the server has committed the rotation.
		// Verify with the candidate before declaring the operation failed.
		if recovered, probeErr := fetchInstallerAccessStatus(client, base, newToken); probeErr == nil {
			status = recovered
		} else {
			_ = os.Remove(pending)
			fatal(err)
		}
	}
	if err = commitPrivateToken(pending, absolute); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR token rotated; recovery token remains in %s: %v\n", pending, err)
		os.Exit(1)
	}
	printJSON(map[string]any{"rotated": true, "tokenFile": absolute, "status": status})
}

func installerAccessClient(installerURL, tokenFile, caFile string) (*url.URL, string, *http.Client) {
	base, err := validateAPIURL(installerURL)
	if err != nil {
		fatal(err)
	}
	token, err := namedAccessToken(tokenFile, "PLATFORM_INSTALLER_TOKEN")
	if err != nil {
		fatal(err)
	}
	if strings.TrimSpace(token) == "" {
		fatal(errors.New("bootstrap token is required"))
	}
	client, err := closureHTTPClient(caFile)
	if err != nil {
		fatal(err)
	}
	return base, token, client
}

func fetchInstallerAccessStatus(client *http.Client, base *url.URL, token string) (installeraccess.AccessStatus, error) {
	var status installeraccess.AccessStatus
	raw, code, err := installerAccessRequest(client, http.MethodGet, base, "/api/v1/access/status", token, nil)
	if err != nil {
		return status, err
	}
	if code != http.StatusOK {
		return status, fmt.Errorf("installer returned %d: %s", code, strings.TrimSpace(string(raw)))
	}
	if err = decodeStrict(raw, &status); err != nil {
		return status, fmt.Errorf("decode installer access status: %w", err)
	}
	return status, nil
}

func rotateInstallerToken(client *http.Client, base *url.URL, currentToken, newToken string) (installeraccess.AccessStatus, error) {
	var status installeraccess.AccessStatus
	if err := installeraccess.ValidateToken(newToken); err != nil {
		return status, err
	}
	payload, err := json.Marshal(map[string]string{"confirmation": "ROTATE", "newToken": newToken})
	if err != nil {
		return status, err
	}
	raw, code, err := installerAccessRequest(client, http.MethodPost, base, "/api/v1/access/token/rotate", currentToken, payload)
	if err != nil {
		return status, err
	}
	if code != http.StatusOK {
		return status, fmt.Errorf("installer returned %d: %s", code, strings.TrimSpace(string(raw)))
	}
	var response struct {
		Rotated bool                        `json:"rotated"`
		Token   installeraccess.TokenStatus `json:"token"`
	}
	if err = decodeStrict(raw, &response); err != nil {
		return status, fmt.Errorf("decode token rotation response: %w", err)
	}
	if !response.Rotated {
		return status, errors.New("installer did not confirm token rotation")
	}
	return fetchInstallerAccessStatus(client, base, newToken)
}

func installerAccessRequest(client *http.Client, method string, base *url.URL, path, token string, payload []byte) ([]byte, int, error) {
	endpoint := strings.TrimRight(base.String(), "/") + path
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("installer access request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxInstallerAccessResponseBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(raw) > maxInstallerAccessResponseBytes {
		return nil, 0, errors.New("installer access response exceeds 1 MiB")
	}
	return raw, resp.StatusCode, nil
}

func stagePrivateToken(path string, raw []byte) (string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return "", "", err
	}
	temp, err := os.CreateTemp(filepath.Dir(absolute), ".bootstrap-token-rotation-*.pending")
	if err != nil {
		return "", "", err
	}
	name := temp.Name()
	if err = temp.Chmod(0o600); err == nil {
		_, err = temp.Write(raw)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", "", err
	}
	return name, absolute, nil
}

func commitPrivateToken(pending, absolute string) error {
	if err := os.Rename(pending, absolute); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(absolute))
	if err != nil {
		return fmt.Errorf("open token parent directory after commit: %w", err)
	}
	if err = directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync token parent directory after commit: %w", err)
	}
	if err = directory.Close(); err != nil {
		return fmt.Errorf("close token parent directory after commit: %w", err)
	}
	return nil
}
