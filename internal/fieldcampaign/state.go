package fieldcampaign

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/durablefile"
	"platform.4so.io/factory/internal/installation"
)

const (
	APIVersion            = "platform.4so.io/v1alpha1"
	Kind                  = "FieldExecutionCampaign"
	SchemaVersion         = 3
	ExactSHASchemaVersion = 2
	LegacySchemaVersion   = 1

	StatePrepared       = "PREPARED"
	StateStartRequested = "START_REQUESTED"
	StateRunning        = "RUNNING"
	StateFailed         = "FAILED"
	StateSucceeded      = "SUCCEEDED"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Event struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	State  string    `json:"state"`
	Detail string    `json:"detail"`
}

type Campaign struct {
	APIVersion            string                      `json:"apiVersion"`
	Kind                  string                      `json:"kind"`
	SchemaVersion         int                         `json:"schemaVersion"`
	ID                    string                      `json:"id"`
	InstallerURL          string                      `json:"installerUrl"`
	Request               installation.InstallRequest `json:"request"`
	RequestDigest         string                      `json:"requestDigest"`
	BundleDigest          string                      `json:"bundleDigest"`
	ReleaseArtifactDigest string                      `json:"releaseArtifactDigest,omitempty"`
	InstallerBinaryDigest string                      `json:"installerBinaryDigest,omitempty"`
	PlanID                string                      `json:"planId"`
	PreflightDigest       string                      `json:"preflightDigest"`
	ExecutionEnabled      bool                        `json:"executionEnabled"`
	State                 string                      `json:"state"`
	RunID                 string                      `json:"runId,omitempty"`
	RunState              string                      `json:"runState,omitempty"`
	Simulation            *bool                       `json:"simulation,omitempty"`
	LastError             string                      `json:"lastError,omitempty"`
	EvidenceVerified      bool                        `json:"evidenceVerified"`
	EvidenceReportID      string                      `json:"evidenceReportId,omitempty"`
	EvidenceDigest        string                      `json:"evidenceDigest,omitempty"`
	CreatedAt             time.Time                   `json:"createdAt"`
	UpdatedAt             time.Time                   `json:"updatedAt"`
	Events                []Event                     `json:"events"`
	IntegrityDigest       string                      `json:"integrityDigest"`
}

type digestPayload struct {
	APIVersion            string                      `json:"apiVersion"`
	Kind                  string                      `json:"kind"`
	SchemaVersion         int                         `json:"schemaVersion"`
	ID                    string                      `json:"id"`
	InstallerURL          string                      `json:"installerUrl"`
	Request               installation.InstallRequest `json:"request"`
	RequestDigest         string                      `json:"requestDigest"`
	BundleDigest          string                      `json:"bundleDigest"`
	ReleaseArtifactDigest string                      `json:"releaseArtifactDigest,omitempty"`
	InstallerBinaryDigest string                      `json:"installerBinaryDigest,omitempty"`
	PlanID                string                      `json:"planId"`
	PreflightDigest       string                      `json:"preflightDigest"`
	ExecutionEnabled      bool                        `json:"executionEnabled"`
	State                 string                      `json:"state"`
	RunID                 string                      `json:"runId,omitempty"`
	RunState              string                      `json:"runState,omitempty"`
	Simulation            *bool                       `json:"simulation,omitempty"`
	LastError             string                      `json:"lastError,omitempty"`
	EvidenceVerified      bool                        `json:"evidenceVerified"`
	EvidenceReportID      string                      `json:"evidenceReportId,omitempty"`
	EvidenceDigest        string                      `json:"evidenceDigest,omitempty"`
	CreatedAt             time.Time                   `json:"createdAt"`
	UpdatedAt             time.Time                   `json:"updatedAt"`
	Events                []Event                     `json:"events"`
}

func New(installerURL string, request installation.InstallRequest, requestDigest, bundleDigest, releaseArtifactDigest, installerBinaryDigest, planID, preflightDigest string, executionEnabled bool, now time.Time) (Campaign, error) {
	id, err := randomID()
	if err != nil {
		return Campaign{}, err
	}
	when := now.UTC()
	c := Campaign{
		APIVersion: APIVersion, Kind: Kind, SchemaVersion: SchemaVersion,
		ID: id, InstallerURL: strings.TrimRight(strings.TrimSpace(installerURL), "/"), Request: request,
		RequestDigest: requestDigest, BundleDigest: bundleDigest, ReleaseArtifactDigest: strings.TrimSpace(releaseArtifactDigest), InstallerBinaryDigest: strings.TrimSpace(installerBinaryDigest), PlanID: strings.TrimSpace(planID), PreflightDigest: preflightDigest,
		ExecutionEnabled: executionEnabled, State: StatePrepared, CreatedAt: when, UpdatedAt: when,
	}
	c.Events = []Event{{At: when, Action: "prepare", State: StatePrepared, Detail: "bundle, plan and preflight verified; explicit start approval is required"}}
	if err := c.Seal(); err != nil {
		return Campaign{}, err
	}
	return c, nil
}

func (c *Campaign) Transition(next, action, detail string, now time.Time) error {
	if !allowedTransition(c.State, next) {
		return fmt.Errorf("field campaign transition %s -> %s is not allowed", c.State, next)
	}
	c.State = next
	c.UpdatedAt = now.UTC()
	c.Events = append(c.Events, Event{At: c.UpdatedAt, Action: strings.TrimSpace(action), State: next, Detail: strings.TrimSpace(detail)})
	return c.Seal()
}

func (c *Campaign) Record(action, detail string, now time.Time) error {
	c.UpdatedAt = now.UTC()
	c.Events = append(c.Events, Event{At: c.UpdatedAt, Action: strings.TrimSpace(action), State: c.State, Detail: strings.TrimSpace(detail)})
	return c.Seal()
}

func allowedTransition(current, next string) bool {
	if current == next && current == StateRunning {
		return true
	}
	switch current {
	case StatePrepared:
		return next == StateStartRequested
	case StateStartRequested:
		return next == StateRunning || next == StateFailed || next == StateSucceeded
	case StateRunning:
		return next == StateFailed || next == StateSucceeded
	case StateFailed:
		return next == StateStartRequested
	default:
		return false
	}
}

func (c *Campaign) Seal() error {
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = time.Now().UTC()
	}
	digest, err := c.computeDigest()
	if err != nil {
		return err
	}
	c.IntegrityDigest = digest
	return c.Verify()
}

func (c Campaign) Verify() error {
	if c.APIVersion != APIVersion || c.Kind != Kind || (c.SchemaVersion != SchemaVersion && c.SchemaVersion != ExactSHASchemaVersion && c.SchemaVersion != LegacySchemaVersion) {
		return errors.New("unsupported field campaign contract")
	}
	if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.PlanID) == "" {
		return errors.New("field campaign identity is incomplete")
	}
	parsed, err := url.Parse(c.InstallerURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return errors.New("field campaign installer URL is invalid")
	}
	digests := map[string]string{"requestDigest": c.RequestDigest, "bundleDigest": c.BundleDigest, "preflightDigest": c.PreflightDigest}
	switch c.SchemaVersion {
	case SchemaVersion:
		digests["releaseArtifactDigest"] = c.ReleaseArtifactDigest
		digests["installerBinaryDigest"] = c.InstallerBinaryDigest
	case ExactSHASchemaVersion:
		digests["releaseArtifactDigest"] = c.ReleaseArtifactDigest
		if strings.TrimSpace(c.InstallerBinaryDigest) != "" {
			return errors.New("schema v2 field campaign must not contain installerBinaryDigest")
		}
	case LegacySchemaVersion:
		if strings.TrimSpace(c.ReleaseArtifactDigest) != "" || strings.TrimSpace(c.InstallerBinaryDigest) != "" {
			return errors.New("legacy field campaign must not contain exact-release runtime binding")
		}
	}
	for name, value := range digests {
		if !digestPattern.MatchString(value) {
			return fmt.Errorf("field campaign %s is invalid", name)
		}
	}
	switch c.State {
	case StatePrepared, StateStartRequested, StateRunning, StateFailed, StateSucceeded:
	default:
		return fmt.Errorf("invalid field campaign state %q", c.State)
	}
	if c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() || c.UpdatedAt.Before(c.CreatedAt) || len(c.Events) == 0 {
		return errors.New("field campaign timeline is incomplete")
	}
	if c.State == StateRunning || c.State == StateFailed || c.State == StateSucceeded {
		if strings.TrimSpace(c.RunID) == "" {
			return errors.New("observed campaign state requires a run ID")
		}
	}
	if c.State == StateRunning && c.RunState != string(bootstrap.RunRunning) {
		return errors.New("running campaign must reference a running installation")
	}
	if c.State == StateFailed && c.RunState != string(bootstrap.RunFailed) {
		return errors.New("failed campaign must reference a failed installation")
	}
	if c.State == StateSucceeded && c.RunState != string(bootstrap.RunSucceeded) {
		return errors.New("succeeded campaign must reference a succeeded installation")
	}
	if c.EvidenceVerified {
		if c.State != StateFailed && c.State != StateSucceeded {
			return errors.New("field evidence can only bind a terminal installation run")
		}
		if strings.TrimSpace(c.EvidenceReportID) == "" || !digestPattern.MatchString(c.EvidenceDigest) {
			return errors.New("verified field evidence metadata is incomplete")
		}
	} else if c.EvidenceReportID != "" || c.EvidenceDigest != "" {
		return errors.New("unverified field campaign must not contain evidence metadata")
	}
	for _, event := range c.Events {
		if event.At.IsZero() || strings.TrimSpace(event.Action) == "" || strings.TrimSpace(event.State) == "" || strings.TrimSpace(event.Detail) == "" {
			return errors.New("field campaign event is incomplete")
		}
	}
	computed, err := c.computeDigest()
	if err != nil {
		return err
	}
	if c.IntegrityDigest != computed {
		return errors.New("field campaign integrity digest mismatch")
	}
	return nil
}

func (c Campaign) computeDigest() (string, error) {
	payload := digestPayload{
		APIVersion: c.APIVersion, Kind: c.Kind, SchemaVersion: c.SchemaVersion, ID: c.ID, InstallerURL: c.InstallerURL,
		Request: c.Request, RequestDigest: c.RequestDigest, BundleDigest: c.BundleDigest, ReleaseArtifactDigest: c.ReleaseArtifactDigest, InstallerBinaryDigest: c.InstallerBinaryDigest, PlanID: c.PlanID, PreflightDigest: c.PreflightDigest,
		ExecutionEnabled: c.ExecutionEnabled, State: c.State, RunID: c.RunID, RunState: c.RunState, Simulation: c.Simulation,
		LastError: c.LastError, EvidenceVerified: c.EvidenceVerified, EvidenceReportID: c.EvidenceReportID, EvidenceDigest: c.EvidenceDigest,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, Events: c.Events,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func Load(path string) (Campaign, error) {
	var c Campaign
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, fmt.Errorf("decode field campaign: %w", err)
	}
	var extra any
	if err = dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return c, errors.New("field campaign has multiple JSON values")
		}
		return c, err
	}
	if err = c.Verify(); err != nil {
		return c, err
	}
	return c, nil
}

func Save(path string, c Campaign) error {
	if err := c.Verify(); err != nil {
		return err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return durablefile.Replace(absolute, raw, 0o700, 0o600)
}

func randomID() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "field-campaign-" + hex.EncodeToString(raw), nil
}
