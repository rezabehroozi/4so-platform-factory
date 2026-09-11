package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const autopilotConsoleAuthority = "AUTOPILOT_CAMPAIGN_CONSOLE_AUTHORITY_V1"
const autopilotStateLimit = 1 << 20

type autopilotStageSummary struct {
	Name           string  `json:"name,omitempty"`
	Specialist     string  `json:"specialist,omitempty"`
	Status         string  `json:"status,omitempty"`
	ReturnCode     int     `json:"returncode,omitempty"`
	ElapsedSeconds float64 `json:"elapsedSeconds,omitempty"`
	Fingerprint    string  `json:"fingerprint,omitempty"`
}

type autopilotFailureSummary struct {
	Stage       string `json:"stage,omitempty"`
	Specialist  string `json:"specialist,omitempty"`
	Status      string `json:"status,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type autopilotConsoleStatus struct {
	Authority           string                   `json:"authority"`
	Derived             bool                     `json:"derived"`
	NotProductAuthority bool                     `json:"notProductAuthority"`
	Configured          bool                     `json:"configured"`
	Available           bool                     `json:"available"`
	Status              string                   `json:"status,omitempty"`
	Phase               string                   `json:"phase,omitempty"`
	StageCount          int                      `json:"stageCount,omitempty"`
	NextIndex           int                      `json:"nextIndex,omitempty"`
	CurrentStage        string                   `json:"currentStage,omitempty"`
	CurrentSpecialist   string                   `json:"currentSpecialist,omitempty"`
	RepairCount         int                      `json:"repairCount,omitempty"`
	ResumeEligible      bool                     `json:"resumeEligible"`
	UpdatedAt           string                   `json:"updatedAt,omitempty"`
	ActiveProcess       string                   `json:"activeProcess,omitempty"`
	StageResults        []autopilotStageSummary  `json:"stageResults,omitempty"`
	LastFailure         *autopilotFailureSummary `json:"lastFailure,omitempty"`
	Message             string                   `json:"message,omitempty"`
}

func autopilotStateDir() (string, bool) {
	if value := strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_AUTOPILOT_STATE_DIR")); value != "" {
		return value, true
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PLATFORM_FACTORY_DEVELOPMENT_MODE")), "true") {
		return ".state", true
	}
	return "", false
}

func readSafeJSONFile(path string, dst any) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.New("state input must be a non-symlink regular file")
	}
	if before.Size() > autopilotStateLimit {
		return fmt.Errorf("state input exceeds %d bytes", autopilotStateLimit)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) {
		return errors.New("state input changed during open")
	}
	limited := io.LimitReader(f, autopilotStateLimit+1)
	dec := json.NewDecoder(limited)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("state input contains trailing JSON content")
	}
	return nil
}

func (s *Server) autopilotStatus(w http.ResponseWriter, r *http.Request) {
	if err := requirePlatformAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "Autopilot campaign evidence is restricted to platform-admin")
		return
	}
	status := autopilotConsoleStatus{Authority: autopilotConsoleAuthority, Derived: true, NotProductAuthority: true}
	dir, configured := autopilotStateDir()
	status.Configured = configured
	if !configured {
		status.Message = "Local Autopilot campaign evidence is not configured on this API instance."
		writeJSON(w, http.StatusOK, status)
		return
	}
	reportPath := filepath.Join(dir, "codex-autopilot-report.json")
	var report struct {
		Authority         string                   `json:"authority"`
		Status            string                   `json:"status"`
		Phase             string                   `json:"phase"`
		StageCount        int                      `json:"stageCount"`
		NextIndex         int                      `json:"nextIndex"`
		CurrentStage      string                   `json:"currentStage"`
		CurrentSpecialist string                   `json:"currentSpecialist"`
		RepairCount       int                      `json:"repairCount"`
		ResumeEligible    bool                     `json:"resumeEligible"`
		UpdatedAt         string                   `json:"updatedAt"`
		StageResults      []autopilotStageSummary  `json:"stageResults"`
		LastFailure       *autopilotFailureSummary `json:"lastFailure"`
	}
	if err := readSafeJSONFile(reportPath, &report); err != nil {
		if os.IsNotExist(err) {
			status.Message = "No Autopilot campaign report exists yet."
			writeJSON(w, http.StatusOK, status)
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "AUTOPILOT_REPORT_INVALID", err.Error())
		return
	}
	if report.Authority != "AUTOPILOT_CAMPAIGN_REPORT_V1" {
		writeError(w, http.StatusUnprocessableEntity, "AUTOPILOT_REPORT_AUTHORITY_INVALID", "unexpected Autopilot campaign report authority")
		return
	}
	status.Available = true
	status.Status, status.Phase, status.StageCount, status.NextIndex = report.Status, report.Phase, report.StageCount, report.NextIndex
	status.CurrentStage, status.CurrentSpecialist, status.RepairCount = report.CurrentStage, report.CurrentSpecialist, report.RepairCount
	status.ResumeEligible, status.UpdatedAt = report.ResumeEligible, report.UpdatedAt
	if len(report.StageResults) > 50 {
		report.StageResults = report.StageResults[len(report.StageResults)-50:]
	}
	status.StageResults, status.LastFailure = report.StageResults, report.LastFailure
	// The checkpoint is consulted only for a non-sensitive active process label.
	var checkpoint struct {
		ActiveProcess struct {
			Label string `json:"label"`
		} `json:"activeProcess"`
	}
	if err := readSafeJSONFile(filepath.Join(dir, "codex-autopilot-run.json"), &checkpoint); err == nil {
		status.ActiveProcess = strings.TrimSpace(checkpoint.ActiveProcess.Label)
	}
	writeJSON(w, http.StatusOK, status)
}
