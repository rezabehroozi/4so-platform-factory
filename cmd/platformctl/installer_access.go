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
const installerBootstrapActionGuidanceAuthority = "INSTALLER_BOOTSTRAP_ACTION_GUIDANCE_V1"
const installerBootstrapMachineNextActionAuthority = "INSTALLER_BOOTSTRAP_MACHINE_NEXT_ACTION_V1"

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
	case "run-status":
		installerAccessRunStatusCommand(args[1:])
	case "resume":
		installerAccessResumeCommand(args[1:])
	case "reset":
		installerAccessResetCommand(args[1:])
	case "reset-resume":
		installerAccessResetResumeCommand(args[1:])
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

type installerRuntimeRunStatus struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	LastError string `json:"lastError,omitempty"`
}

type installerBootstrapRuntimeStatus struct {
	ExecutionEnabled bool                        `json:"executionEnabled"`
	BootstrapActive bool                        `json:"bootstrapActive"`
	ResetActive     bool                        `json:"resetActive"`
	Run             *installerRuntimeRunStatus  `json:"run"`
	ResetRuns       []installerRuntimeRunStatus `json:"resetRuns"`
}

func installerBootstrapNextActionGuidance(status installerBootstrapRuntimeStatus) (string, string) {
	if !status.ExecutionEnabled {
		return "REDEPLOY_EXECUTION_ENABLED", "redeploy the reviewed Bootstrap Installer with execution enabled before attempting install/resume/reset"
	}
	if status.ResetActive {
		return "MONITOR_RESET", "monitor bootstrap-status until the active reset is terminal; do not replay reset or reset-resume"
	}
	if reset := latestIncompleteInstallerReset(status); reset != nil {
		return "RESUME_RESET", "review the interrupted reset, then run reset-resume --confirmation RESUME-RESET; do not start another reset"
	}
	if status.BootstrapActive {
		return "MONITOR_INSTALL", "monitor bootstrap-status until the active installation is terminal; do not submit another resume"
	}
	if status.Run == nil {
		return "START_BROWSER_INSTALL", "open the Browser Installer, complete request/preflight review, and start installation explicitly"
	}
	switch strings.ToUpper(strings.TrimSpace(status.Run.State)) {
	case "SUCCEEDED":
		return "VERIFY_INSTALL", "installation succeeded; verify evidence/status and continue platform onboarding instead of resuming"
	case "FAILED", "PENDING", "RUNNING":
		return "RESUME_INSTALL", "review the durable run/error, then run resume --confirmation RESUME if recovery is intended"
	default:
		return "REVIEW_STATE", "review the durable bootstrap state before selecting any mutation; automatic replay is forbidden"
	}
}

func installerBootstrapNextAction(status installerBootstrapRuntimeStatus) string {
	_, action := installerBootstrapNextActionGuidance(status)
	return action
}

func installerAccessRunStatusCommand(args []string) {
	fs := flag.NewFlagSet("installer-access run-status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
	tokenFile := fs.String("token-file", "", "file containing bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	if err := fs.Parse(args); err != nil || strings.TrimSpace(*installerURL) == "" || fs.NArg() != 0 {
		usage()
		if err != nil && errors.Is(err, flag.ErrHelp) { return }
		os.Exit(2)
	}
	base, token, client := installerAccessClient(*installerURL, *tokenFile, *caFile)
	status, err := fetchInstallerBootstrapRuntimeStatus(client, base, token)
	if err != nil { fatal(err) }
	nextActionCode, nextAction := installerBootstrapNextActionGuidance(status)
	printJSON(map[string]any{
		"authority": "INSTALLER_BOOTSTRAP_RUNTIME_STATUS_V1",
		"actionGuidanceAuthority": installerBootstrapActionGuidanceAuthority,
		"nextActionAuthority": installerBootstrapMachineNextActionAuthority,
		"executionEnabled": status.ExecutionEnabled,
		"bootstrapActive": status.BootstrapActive,
		"resetActive": status.ResetActive,
		"run": status.Run,
		"resetRuns": status.ResetRuns,
		"automaticReplay": false,
		"nextActionAuthority": installerBootstrapMachineNextActionAuthority,
		"nextActionCode": nextActionCode,
		"nextAction": nextAction,
	})
}

type installerMutationReadback struct {
	After         installerBootstrapRuntimeStatus
	StatusPending bool
}

func installerStatusChangedForResume(before, after installerBootstrapRuntimeStatus) bool {
	if after.BootstrapActive { return true }
	if before.Run == nil || after.Run == nil { return before.Run != after.Run }
	return after.Run.ID != before.Run.ID || after.Run.State != before.Run.State || after.Run.LastError != before.Run.LastError
}

func performInstallerMutationWithReadback(
	client *http.Client,
	base *url.URL,
	token string,
	path string,
	headers map[string]string,
	before installerBootstrapRuntimeStatus,
	changed func(installerBootstrapRuntimeStatus, installerBootstrapRuntimeStatus) bool,
	label string,
) (installerMutationReadback, error) {
	var outcome installerMutationReadback
	raw, code, requestErr := installerAccessRequestWithHeaders(client, http.MethodPost, base, path, token, nil, headers)
	if requestErr == nil && code != http.StatusAccepted {
		return outcome, fmt.Errorf("installer %s returned %d: %s", label, code, strings.TrimSpace(string(raw)))
	}
	after, readbackErr := fetchInstallerBootstrapRuntimeStatus(client, base, token)
	if requestErr != nil {
		if readbackErr != nil {
			return outcome, fmt.Errorf("%s response was lost (%v) and authoritative status readback also failed: %w", label, requestErr, readbackErr)
		}
		if changed == nil || !changed(before, after) {
			return outcome, fmt.Errorf("%s response was lost and status readback does not prove acceptance; automatic replay is forbidden: %w", label, requestErr)
		}
		outcome.After = after
		return outcome, nil
	}
	if readbackErr != nil {
		// HTTP 202 proves acceptance but never terminal completion. The caller
		// must surface status-pending and must not replay the mutation merely
		// because this immediate readback failed.
		outcome.StatusPending = true
		return outcome, nil
	}
	outcome.After = after
	return outcome, nil
}

func installerAccessResumeCommand(args []string) {
	fs := flag.NewFlagSet("installer-access resume", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
	tokenFile := fs.String("token-file", "", "file containing bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	confirmation := fs.String("confirmation", "", "must be exactly RESUME")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*installerURL) == "" || strings.TrimSpace(*confirmation) != "RESUME" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	base, token, client := installerAccessClient(*installerURL, *tokenFile, *caFile)
	before, err := fetchInstallerBootstrapRuntimeStatus(client, base, token)
	if err != nil {
		fatal(fmt.Errorf("read bootstrap status before resume: %w", err))
	}
	if !before.ExecutionEnabled {
		fatal(errors.New("Bootstrap Installer execution is disabled; redeploy the reviewed Installer with execution enabled before resuming"))
	}
	if before.ResetActive {
		fatal(errors.New("installer reset is active; bootstrap resume is fenced until reset completes or is explicitly resumed"))
	}
	if before.BootstrapActive {
		printJSON(map[string]any{
			"authority": "INSTALLER_MANUAL_BOOTSTRAP_RESUME_V1",
			"status": "ALREADY_RUNNING",
			"run": before.Run,
			"automaticReplay": false,
			"nextActionAuthority":installerBootstrapMachineNextActionAuthority,"nextActionCode":"MONITOR_INSTALL",
			"nextAction": "monitor the existing durable bootstrap run; do not submit another resume",
		})
		return
	}
	if before.Run == nil {
		fatal(errors.New("no durable bootstrap run exists to resume"))
	}
	if strings.EqualFold(strings.TrimSpace(before.Run.State), "SUCCEEDED") {
		printJSON(map[string]any{
			"authority": "INSTALLER_MANUAL_BOOTSTRAP_RESUME_V1",
			"status": "ALREADY_SUCCEEDED",
			"run": before.Run,
			"automaticReplay": false,
			"nextActionAuthority":installerBootstrapMachineNextActionAuthority,"nextActionCode":"VERIFY_INSTALL",
			"nextAction": "installation already succeeded; verify evidence instead of resuming",
		})
		return
	}
	outcome, err := performInstallerMutationWithReadback(client, base, token, "/api/v1/resume", nil, before, installerStatusChangedForResume, "resume")
	if err != nil { fatal(err) }
	if outcome.StatusPending {
		printJSON(map[string]any{
			"authority": "INSTALLER_MANUAL_BOOTSTRAP_RESUME_V1",
			"status": "ACCEPTED_STATUS_PENDING",
			"runId": before.Run.ID,
			"automaticReplay": false,
			"nextActionAuthority":installerBootstrapMachineNextActionAuthority,"nextActionCode":"MONITOR_INSTALL",
			"nextAction": "resume was accepted; retry installer-access run-status instead of replaying the mutation",
		})
		return
	}
	after := outcome.After
	printJSON(map[string]any{
		"authority": "INSTALLER_MANUAL_BOOTSTRAP_RESUME_V1",
		"status": "ACCEPTED",
		"run": after.Run,
		"bootstrapActive": after.BootstrapActive,
		"automaticReplay": false,
		"nextActionAuthority":installerBootstrapMachineNextActionAuthority,"nextActionCode":"MONITOR_INSTALL",
		"nextAction": "monitor durable status until terminal; if interrupted again, read status before another explicit RESUME",
	})
}

func fetchInstallerBootstrapRuntimeStatus(client *http.Client, base *url.URL, token string) (installerBootstrapRuntimeStatus, error) {
	var status installerBootstrapRuntimeStatus
	raw, code, err := installerAccessRequest(client, http.MethodGet, base, "/api/v1/status", token, nil)
	if err != nil {
		return status, err
	}
	if code != http.StatusOK {
		return status, fmt.Errorf("installer returned %d: %s", code, strings.TrimSpace(string(raw)))
	}
	if err = json.Unmarshal(raw, &status); err != nil {
		return status, fmt.Errorf("decode bootstrap runtime status: %w", err)
	}
	return status, nil
}

func latestIncompleteInstallerReset(status installerBootstrapRuntimeStatus) *installerRuntimeRunStatus {
	if len(status.ResetRuns) == 0 { return nil }
	latest := status.ResetRuns[len(status.ResetRuns)-1]
	if strings.EqualFold(strings.TrimSpace(latest.State), "SUCCEEDED") { return nil }
	return &latest
}

func installerResetReadbackChanged(before, after installerBootstrapRuntimeStatus) bool {
	if after.ResetActive || len(after.ResetRuns) != len(before.ResetRuns) { return true }
	if len(after.ResetRuns) == 0 { return false }
	if len(before.ResetRuns) == 0 { return true }
	a, b := after.ResetRuns[len(after.ResetRuns)-1], before.ResetRuns[len(before.ResetRuns)-1]
	return a.ID != b.ID || a.State != b.State || a.LastError != b.LastError
}

func installerAccessResetCommand(args []string) {
	fs := flag.NewFlagSet("installer-access reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
	tokenFile := fs.String("token-file", "", "file containing bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	confirmation := fs.String("confirmation", "", "must be exactly RESET")
	if err := fs.Parse(args); err != nil || strings.TrimSpace(*installerURL) == "" || *confirmation != "RESET" || fs.NArg() != 0 {
		usage()
		if err != nil && errors.Is(err, flag.ErrHelp) { return }
		os.Exit(2)
	}
	base, token, client := installerAccessClient(*installerURL, *tokenFile, *caFile)
	before, err := fetchInstallerBootstrapRuntimeStatus(client, base, token)
	if err != nil { fatal(fmt.Errorf("read bootstrap status before reset: %w", err)) }
	if !before.ExecutionEnabled { fatal(errors.New("Bootstrap Installer execution is disabled")) }
	if before.BootstrapActive { fatal(errors.New("bootstrap mutation is active; reset is fenced")) }
	if before.ResetActive {
		printJSON(map[string]any{"authority":"INSTALLER_MANUAL_BOOTSTRAP_RESET_V1","status":"ALREADY_RUNNING","reset":latestIncompleteInstallerReset(before),"automaticReplay":false,"nextActionCode":"MONITOR_RESET","nextAction":"monitor run-status until the active reset is terminal; do not submit another reset"})
		return
	}
	if before.Run == nil { fatal(errors.New("no installation authority exists to reset")) }
	headers := map[string]string{"X-Confirm-Reset": "reset:" + before.Run.ID}
	outcome, err := performInstallerMutationWithReadback(client, base, token, "/api/v1/reset/start", headers, before, installerResetReadbackChanged, "reset")
	if err != nil { fatal(err) }
	if outcome.StatusPending {
		printJSON(map[string]any{"authority":"INSTALLER_MANUAL_BOOTSTRAP_RESET_V1","status":"ACCEPTED_STATUS_PENDING","sourceRunId":before.Run.ID,"automaticReplay":false,"nextActionCode":"MONITOR_RESET","nextAction":"retry run-status; do not replay reset"})
		return
	}
	after := outcome.After
	printJSON(map[string]any{"authority":"INSTALLER_MANUAL_BOOTSTRAP_RESET_V1","status":"ACCEPTED","resetActive":after.ResetActive,"reset":latestIncompleteInstallerReset(after),"automaticReplay":false,"nextActionCode":"MONITOR_RESET","nextAction":"monitor run-status until reset is terminal; use reset-resume only after interruption/failure"})
}

func installerAccessResetResumeCommand(args []string) {
	fs := flag.NewFlagSet("installer-access reset-resume", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	installerURL := fs.String("installer-url", "", "bootstrap installer base URL")
	tokenFile := fs.String("token-file", "", "file containing bootstrap token; PLATFORM_INSTALLER_TOKEN is used when omitted")
	caFile := fs.String("ca-file", "", "PEM CA file for a private installer endpoint")
	confirmation := fs.String("confirmation", "", "must be exactly RESUME-RESET")
	if err := fs.Parse(args); err != nil || strings.TrimSpace(*installerURL) == "" || *confirmation != "RESUME-RESET" || fs.NArg() != 0 {
		usage()
		if err != nil && errors.Is(err, flag.ErrHelp) { return }
		os.Exit(2)
	}
	base, token, client := installerAccessClient(*installerURL, *tokenFile, *caFile)
	before, err := fetchInstallerBootstrapRuntimeStatus(client, base, token)
	if err != nil { fatal(fmt.Errorf("read bootstrap status before reset resume: %w", err)) }
	if !before.ExecutionEnabled { fatal(errors.New("Bootstrap Installer execution is disabled")) }
	if before.BootstrapActive { fatal(errors.New("bootstrap mutation is active; reset resume is fenced")) }
	reset := latestIncompleteInstallerReset(before)
	if reset == nil { fatal(errors.New("no reset run requires resume")) }
	if before.ResetActive {
		printJSON(map[string]any{"authority":"INSTALLER_MANUAL_BOOTSTRAP_RESET_V1","status":"ALREADY_RUNNING","reset":reset,"automaticReplay":false,"nextActionCode":"MONITOR_RESET","nextAction":"monitor run-status until the active reset is terminal; do not submit another reset-resume"})
		return
	}
	headers := map[string]string{"X-Confirm-Reset-Resume": "resume:" + reset.ID}
	outcome, err := performInstallerMutationWithReadback(client, base, token, "/api/v1/reset/resume", headers, before, installerResetReadbackChanged, "reset-resume")
	if err != nil { fatal(err) }
	if outcome.StatusPending {
		printJSON(map[string]any{"authority":"INSTALLER_MANUAL_BOOTSTRAP_RESET_V1","status":"ACCEPTED_STATUS_PENDING","resetId":reset.ID,"automaticReplay":false,"nextActionCode":"MONITOR_RESET","nextAction":"retry run-status; do not replay reset-resume"})
		return
	}
	after := outcome.After
	printJSON(map[string]any{"authority":"INSTALLER_MANUAL_BOOTSTRAP_RESET_V1","status":"ACCEPTED","resetActive":after.ResetActive,"reset":latestIncompleteInstallerReset(after),"automaticReplay":false,"nextActionCode":"MONITOR_RESET","nextAction":"monitor run-status until reset is terminal"})
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
	return installerAccessRequestWithHeaders(client, method, base, path, token, payload, nil)
}

func installerAccessRequestWithHeaders(client *http.Client, method string, base *url.URL, path, token string, payload []byte, headers map[string]string) ([]byte, int, error) {
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
	for key, value := range headers {
		if strings.TrimSpace(key) != "" { req.Header.Set(key, value) }
	}
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
