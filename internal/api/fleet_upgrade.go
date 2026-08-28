package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"platform.4so.io/factory/internal/baseline"
	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/fleethealth"
	"sort"
	"strings"
	"time"
)

type createFleetGroupInput struct {
	ProjectID   string   `json:"projectId"`
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	ClusterIDs  []string `json:"clusterIds"`
}

type gitDriftSourceInput struct {
	Organization string `json:"organization"`
	Repository   string `json:"repository"`
	Branch       string `json:"branch,omitempty"`
}

type createDriftScanInput struct {
	ProjectID    string               `json:"projectId"`
	FleetGroupID string               `json:"fleetGroupId,omitempty"`
	ClusterIDs   []string             `json:"clusterIds,omitempty"`
	Git          *gitDriftSourceInput `json:"git,omitempty"`
}

type createUpgradeCampaignInput struct {
	ProjectID              string    `json:"projectId"`
	FleetGroupID           string    `json:"fleetGroupId"`
	BaselineID             string    `json:"baselineId"`
	TargetVersion          string    `json:"targetVersion"`
	CanaryCount            int       `json:"canaryCount"`
	WaveSize               int       `json:"waveSize"`
	HaltAfterFailures      int       `json:"haltAfterFailures"`
	MaintenanceWindowStart time.Time `json:"maintenanceWindowStart"`
	MaintenanceWindowEnd   time.Time `json:"maintenanceWindowEnd"`
	RecoveryCheckpointIDs  []string  `json:"recoveryCheckpointIds"`
}

func jsonDigest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func requiredIdempotencyKey(r *http.Request) (string, error) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		return "", fmt.Errorf("Idempotency-Key is required and must be at most 200 characters")
	}
	return key, nil
}

func (s *Server) createFleetGroup(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, err := requiredIdempotencyKey(r)
	if err != nil {
		writeError(w, 400, "IDEMPOTENCY_KEY_REQUIRED", err.Error())
		return
	}
	var in createFleetGroupInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	requestDigest := jsonDigest(in)
	v, replay, err := s.store.CreateFleetGroup(r.Context(), controlplane.FleetGroup{ProjectID: strings.TrimSpace(in.ProjectID), Name: in.Name, DisplayName: in.DisplayName, ClusterIDs: in.ClusterIDs, IdempotencyKey: key, RequestDigest: requestDigest}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"fleetGroup": v, "idempotentReplay": replay})
}
func (s *Server) listFleetGroups(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	v, err := s.store.ListFleetGroups(r.Context(), projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	v = filterProjectScoped(v, allowed, all, func(item controlplane.FleetGroup) string { return item.ProjectID })
	writeJSON(w, 200, v)
}
func (s *Server) getFleetGroup(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetFleetGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) latestSuccessfulBaseline(r *http.Request, projectID, clusterID, baselineID string) (controlplane.BaselineDeployment, error) {
	all, err := s.store.ListBaselineDeployments(r.Context(), projectID, clusterID)
	if err != nil {
		return controlplane.BaselineDeployment{}, err
	}
	for i := len(all) - 1; i >= 0; i-- {
		v := all[i]
		if v.BaselineID == baselineID && v.State == controlplane.BaselineDeploymentSucceeded && v.DesiredDigest == v.ObservedDigest {
			return v, nil
		}
	}
	return controlplane.BaselineDeployment{}, controlplane.ErrNotFound
}

func resolveClusterIDs(group controlplane.FleetGroup, explicit []string) ([]string, error) {
	ids := append([]string(nil), explicit...)
	if group.ID != "" {
		ids = append([]string(nil), group.ClusterIDs...)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return nil, fmt.Errorf("cluster IDs must be non-empty and unique")
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one cluster is required")
	}
	sort.Strings(out)
	return out, nil
}

func healthDriftFindings(health fleethealth.ClusterHealth) []controlplane.DriftFinding {
	findings := []controlplane.DriftFinding{}
	resource := health.KubernetesVersion
	switch health.KubernetesSupport.Status {
	case "EOL":
		findings = append(findings, controlplane.DriftFinding{Category: "VERSION", Code: "KUBERNETES_EOL", Severity: controlplane.DriftSeverityCritical, Owner: "cluster-admin", Resource: resource, Summary: "Kubernetes minor release is end-of-life in the bundled support policy", Remediation: controlplane.DriftRemediation{Action: "UPGRADE_KUBERNETES", Mode: "GUIDANCE", Eligible: false}})
	case "EOL_SOON":
		findings = append(findings, controlplane.DriftFinding{Category: "VERSION", Code: "KUBERNETES_EOL_SOON", Severity: controlplane.DriftSeverityHigh, Owner: "cluster-admin", Resource: resource, Summary: fmt.Sprintf("Kubernetes minor release reaches end-of-life in %d days", health.KubernetesSupport.DaysUntilEndOfLife), Remediation: controlplane.DriftRemediation{Action: "UPGRADE_KUBERNETES", Mode: "GUIDANCE", Eligible: false}})
	case "MAINTENANCE":
		findings = append(findings, controlplane.DriftFinding{Category: "VERSION", Code: "KUBERNETES_MAINTENANCE", Severity: controlplane.DriftSeverityMedium, Owner: "cluster-admin", Resource: resource, Summary: "Kubernetes minor release is in maintenance support", Remediation: controlplane.DriftRemediation{Action: "PLAN_KUBERNETES_UPGRADE", Mode: "GUIDANCE", Eligible: false}})
	case "UNKNOWN":
		findings = append(findings, controlplane.DriftFinding{Category: "VERSION", Code: "KUBERNETES_SUPPORT_UNKNOWN", Severity: controlplane.DriftSeverityMedium, Owner: "cluster-admin", Resource: resource, Summary: "Kubernetes minor release is not present in the bundled support policy", Remediation: controlplane.DriftRemediation{Action: "VERIFY_KUBERNETES_SUPPORT", Mode: "GUIDANCE", Eligible: false}})
	}
	for _, certificate := range health.Certificates {
		switch certificate.State {
		case "EXPIRED":
			findings = append(findings, controlplane.DriftFinding{Category: "CERTIFICATE", Code: "CERTIFICATE_EXPIRED", Severity: controlplane.DriftSeverityCritical, Owner: "platform-operator", Resource: certificate.Name + ":" + certificate.Fingerprint, Summary: certificate.Name + " certificate is expired", Remediation: controlplane.DriftRemediation{Action: "ROTATE_CERTIFICATE", Mode: "GUIDANCE", Eligible: false}})
		case "EXPIRING":
			findings = append(findings, controlplane.DriftFinding{Category: "CERTIFICATE", Code: "CERTIFICATE_EXPIRING", Severity: controlplane.DriftSeverityHigh, Owner: "platform-operator", Resource: certificate.Name + ":" + certificate.Fingerprint, Summary: fmt.Sprintf("%s certificate expires in %d days", certificate.Name, certificate.DaysLeft), Remediation: controlplane.DriftRemediation{Action: "ROTATE_CERTIFICATE", Mode: "GUIDANCE", Eligible: false}})
		}
	}
	return findings
}

func (s *Server) createDriftScan(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, err := requiredIdempotencyKey(r)
	if err != nil {
		writeError(w, 400, "IDEMPOTENCY_KEY_REQUIRED", err.Error())
		return
	}
	var in createDriftScanInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	var group controlplane.FleetGroup
	if strings.TrimSpace(in.FleetGroupID) != "" {
		group, err = s.store.GetFleetGroup(r.Context(), strings.TrimSpace(in.FleetGroupID))
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if group.ProjectID != in.ProjectID {
			writeError(w, 422, "FLEET_GROUP_PROJECT_MISMATCH", "fleet group does not belong to project")
			return
		}
	}
	ids, err := resolveClusterIDs(group, in.ClusterIDs)
	if err != nil {
		writeError(w, 422, "DRIFT_TARGETS_INVALID", err.Error())
		return
	}
	var gitEvidence *controlplane.GitDriftEvidence
	if in.Git != nil {
		if s.services == nil {
			writeError(w, 422, "GIT_INTEGRATION_REQUIRED", "Forgejo-compatible Git integration is required for three-way drift")
			return
		}
		branch := strings.TrimSpace(in.Git.Branch)
		if branch == "" {
			branch = "main"
		}
		base, e := s.store.GetLatestManagedGitRevision(r.Context(), in.Git.Organization, in.Git.Repository, branch)
		if e != nil {
			writeError(w, 422, "GIT_BASE_REVISION_REQUIRED", "publish at least one signed platform revision before running three-way Git drift")
			return
		}
		current, e := s.services.InspectGitRevision(r.Context(), in.Git.Organization, in.Git.Repository, branch, base.CommitSHA, base.PublicKeyFingerprint)
		if e != nil {
			writeError(w, 502, "GIT_SNAPSHOT_FAILED", e.Error())
			return
		}
		gitEvidence = &controlplane.GitDriftEvidence{Organization: current.Organization, Repository: current.Repository, Branch: current.Branch, BaseRevisionID: base.RevisionID, BaseDigest: base.Digest, BaseCommitSHA: base.CommitSHA, CurrentRevisionID: current.RevisionID, CurrentDigest: current.Digest, CurrentCommitSHA: current.CommitSHA, PublicKeyFingerprint: base.PublicKeyFingerprint, CurrentTrusted: current.Trusted, ChangedFiles: current.ChangedFiles, Classification: controlplane.GitDriftNotRequested}
	}
	priorScans, err := s.store.ListDriftScans(r.Context(), in.ProjectID, "")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	targets := make([]controlplane.DriftScanTarget, 0, len(ids))
	for _, clusterID := range ids {
		deployment, e := s.latestSuccessfulBaseline(r, in.ProjectID, clusterID, baseline.SecureNamespaceID)
		if e != nil {
			writeError(w, 422, "MANAGED_BASELINE_REQUIRED", "cluster "+clusterID+" has no successful managed baseline deployment")
			return
		}
		target := controlplane.DriftScanTarget{ClusterID: clusterID, BaselineDeploymentID: deployment.ID, BaselineID: deployment.BaselineID, BaselineVersion: deployment.BaselineVersion, DesiredDigest: deployment.DesiredDigest}
		cluster, clusterErr := s.store.GetManagedCluster(r.Context(), clusterID)
		if clusterErr != nil {
			writeStoreError(w, clusterErr)
			return
		}
		inventory, inventoryErr := optionalClusterInventory(s.store, r.Context(), clusterID)
		if inventoryErr != nil {
			writeStoreError(w, inventoryErr)
			return
		}
		certificates, certificateErr := s.store.ListAgentCertificates(r.Context(), clusterID)
		if certificateErr != nil {
			writeStoreError(w, certificateErr)
			return
		}
		target.Findings = controlplane.MergeDriftFindingHistory(clusterID, priorScans, healthDriftFindings(fleethealth.Evaluate(cluster, inventory, certificates, now)), now)
		if gitEvidence != nil {
			g := *gitEvidence
			g.ChangedFiles = append([]string(nil), gitEvidence.ChangedFiles...)
			target.Git = &g
		}
		targets = append(targets, target)
	}
	digest := jsonDigest(struct {
		ProjectID, FleetGroupID string
		ClusterIDs              []string
		Git                     *gitDriftSourceInput
	}{in.ProjectID, in.FleetGroupID, ids, in.Git})
	v, replay, err := s.store.CreateDriftScan(r.Context(), controlplane.DriftScan{ProjectID: in.ProjectID, FleetGroupID: in.FleetGroupID, Targets: targets, IdempotencyKey: key, RequestDigest: digest}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := 201
	if replay {
		status = 200
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"driftScan": v, "idempotentReplay": replay, "next": "agent-live-drift-read"})
}
func (s *Server) convergeOperationToQueued(ctx context.Context, op controlplane.Operation, actor string) (controlplane.Operation, error) {
	// Composite API workflows can be retried after a lost response or process
	// restart. Converge only the monotonic pre-queue states and refresh after a
	// concurrent transition so identical retries do not fail solely because they
	// raced on the same revision.
	for attempt := 0; attempt < 4; attempt++ {
		var target controlplane.OperationState
		switch op.State {
		case controlplane.OperationDraft:
			target = controlplane.OperationPlanning
		case controlplane.OperationPlanning:
			target = controlplane.OperationQueued
		default:
			return op, nil
		}
		next, err := s.store.TransitionOperation(ctx, op.ID, op.Revision, target, "", actor)
		if err == nil {
			op = next
			continue
		}
		if !errors.Is(err, controlplane.ErrConflict) {
			return controlplane.Operation{}, err
		}
		op, err = s.store.GetOperation(ctx, op.ID)
		if err != nil {
			return controlplane.Operation{}, err
		}
	}
	if op.State == controlplane.OperationDraft || op.State == controlplane.OperationPlanning {
		return controlplane.Operation{}, controlplane.ErrConflict
	}
	return op, nil
}

func driftRisk(severity controlplane.DriftSeverity) string {
	switch severity {
	case controlplane.DriftSeverityCritical:
		return "critical"
	case controlplane.DriftSeverityHigh:
		return "high"
	case controlplane.DriftSeverityMedium:
		return "medium"
	default:
		return "low"
	}
}

func (s *Server) remediateDriftFinding(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, err := requiredIdempotencyKey(r)
	if err != nil {
		writeError(w, 400, "IDEMPOTENCY_KEY_REQUIRED", err.Error())
		return
	}
	scan, err := s.store.GetDriftScan(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, scan.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	clusterID, fingerprint := strings.TrimSpace(r.PathValue("clusterId")), strings.TrimSpace(r.PathValue("fingerprint"))
	var target *controlplane.DriftScanTarget
	var finding *controlplane.DriftFinding
	for i := range scan.Targets {
		if scan.Targets[i].ClusterID != clusterID {
			continue
		}
		target = &scan.Targets[i]
		for j := range scan.Targets[i].Findings {
			if scan.Targets[i].Findings[j].Fingerprint == fingerprint {
				finding = &scan.Targets[i].Findings[j]
				break
			}
		}
		break
	}
	if target == nil || finding == nil {
		writeError(w, 404, "DRIFT_FINDING_NOT_FOUND", "drift finding not found for this scan target")
		return
	}
	if !finding.Remediation.Eligible || finding.Remediation.Mode != "OPERATION" {
		writeError(w, 422, "DRIFT_REMEDIATION_NOT_EXECUTABLE", "this finding requires guidance or a dedicated direct action and cannot be queued as a generic operation")
		return
	}
	action := strings.ToLower(strings.ReplaceAll(finding.Remediation.Action, "_", "-"))
	op, replay, err := s.store.CreateOperation(r.Context(), controlplane.OperationRequest{
		ProjectID: scan.ProjectID, Kind: "drift.remediate." + action,
		TargetRef:       "drift-finding:" + scan.ID + ":" + clusterID + ":" + fingerprint,
		DesiredRevision: target.DesiredDigest, Risk: driftRisk(finding.Severity), Class: controlplane.OperationClassMutating,
	}, key, actor, r.Header.Get("X-Request-ID"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// Idempotent replay is also the crash-recovery path for this composite
	// workflow. A prior request may have durably created the operation but
	// failed before PLANNING or QUEUED was persisted.
	op, err = s.convergeOperationToQueued(r.Context(), op, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, op.Revision)
	status := 201
	if replay {
		status = 200
		w.Header().Set("Idempotent-Replay", "true")
	}
	writeJSON(w, status, map[string]any{"operation": op, "finding": finding, "idempotentReplay": replay, "automaticGitOverwrite": false})
}

func (s *Server) listDriftScans(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	v, err := s.store.ListDriftScans(r.Context(), projectID, r.URL.Query().Get("fleetGroupId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	v = filterProjectScoped(v, allowed, all, func(item controlplane.DriftScan) string { return item.ProjectID })
	writeJSON(w, 200, v)
}
func (s *Server) getDriftScan(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetDriftScan(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) nextDriftTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, 401, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	scan, target, err := s.store.NextDriftTask(r.Context(), r.PathValue("id"), agentDigest)
	if errors.Is(err, controlplane.ErrNotFound) {
		w.WriteHeader(204)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	def, ok := baseline.GetVersion(target.BaselineID, target.BaselineVersion)
	if !ok {
		writeError(w, 500, "BASELINE_VERSION_MISSING", "managed baseline version is not available")
		return
	}
	resources := baseline.ResourcesForVersion(target.BaselineDeploymentID, target.DesiredDigest, target.BaselineVersion)
	setRevisionETag(w, scan.Revision)
	writeJSON(w, 200, controlplane.DriftTask{ScanID: scan.ID, ScanRevision: scan.Revision, ClusterID: target.ClusterID, BaselineDeploymentID: target.BaselineDeploymentID, BaselineID: target.BaselineID, BaselineVersion: target.BaselineVersion, TargetNamespace: def.TargetNamespace, DesiredDigest: target.DesiredDigest, Resources: resources, Git: target.Git})
}
func (s *Server) reportDriftTask(w http.ResponseWriter, r *http.Request) {
	agentDigest, err := s.agentCredentialDigest(r, r.PathValue("id"))
	if err != nil {
		writeError(w, 401, "AGENT_TOKEN_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var result controlplane.DriftTaskResult
	if err = decodeJSON(w, r, &result); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	result.ScanID = r.PathValue("scanId")
	result.ClusterID = r.PathValue("id")
	v, err := s.store.ReportDriftTask(r.Context(), result.ClusterID, agentDigest, rev, result)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) createUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	key, err := requiredIdempotencyKey(r)
	if err != nil {
		writeError(w, 400, "IDEMPOTENCY_KEY_REQUIRED", err.Error())
		return
	}
	var in createUpgradeCampaignInput
	if err = decodeJSON(w, r, &in); err != nil {
		writeError(w, 400, "INVALID_REQUEST", err.Error())
		return
	}
	if _, err = s.requireProjectAccess(r, in.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	if in.BaselineID == "" {
		in.BaselineID = baseline.SecureNamespaceID
	}
	if in.TargetVersion == "" {
		in.TargetVersion = baseline.SecureNamespaceUpgradeVersion
	}
	if in.CanaryCount <= 0 {
		in.CanaryCount = 1
	}
	if in.WaveSize <= 0 {
		in.WaveSize = 2
	}
	if in.HaltAfterFailures <= 0 {
		in.HaltAfterFailures = 1
	}
	def, ok := baseline.GetVersion(in.BaselineID, in.TargetVersion)
	if !ok {
		writeError(w, 422, "TARGET_BASELINE_VERSION_NOT_FOUND", "target baseline version is unavailable")
		return
	}
	group, err := s.store.GetFleetGroup(r.Context(), in.FleetGroupID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if group.ProjectID != in.ProjectID {
		writeError(w, 422, "FLEET_GROUP_PROJECT_MISMATCH", "fleet group does not belong to project")
		return
	}
	ids := append([]string(nil), group.ClusterIDs...)
	sort.Strings(ids)
	canary := in.CanaryCount
	if canary > len(ids) {
		canary = len(ids)
	}
	targets := make([]controlplane.UpgradeCampaignTarget, 0, len(ids))
	for i, clusterID := range ids {
		current, e := s.latestSuccessfulBaseline(r, in.ProjectID, clusterID, in.BaselineID)
		if e != nil {
			writeError(w, 422, "MANAGED_BASELINE_REQUIRED", "cluster "+clusterID+" has no successful managed baseline")
			return
		}
		allowed := false
		for _, from := range def.UpgradeFrom {
			if from == current.BaselineVersion {
				allowed = true
				break
			}
		}
		if !allowed {
			writeError(w, 422, "UPGRADE_PATH_UNAVAILABLE", "cluster "+clusterID+" baseline "+current.BaselineVersion+" cannot upgrade to "+def.Version)
			return
		}
		wave := 1
		if i >= canary {
			wave = 2 + (i-canary)/in.WaveSize
		}
		targets = append(targets, controlplane.UpgradeCampaignTarget{ClusterID: clusterID, Wave: wave, State: controlplane.UpgradeTargetPending, PreviousBaselineDeploymentID: current.ID, PreviousVersion: current.BaselineVersion, PreviousDigest: current.DesiredDigest})
	}
	digest := jsonDigest(in)
	v, replay, err := s.store.CreateUpgradeCampaign(r.Context(), controlplane.UpgradeCampaign{ProjectID: in.ProjectID, FleetGroupID: in.FleetGroupID, BaselineID: def.ID, TargetVersion: def.Version, CanaryCount: canary, WaveSize: in.WaveSize, HaltAfterFailures: in.HaltAfterFailures, Targets: targets, IdempotencyKey: key, RequestDigest: digest, MaintenanceWindowStart: in.MaintenanceWindowStart, MaintenanceWindowEnd: in.MaintenanceWindowEnd, RecoveryCheckpointIDs: append([]string(nil), in.RecoveryCheckpointIDs...)}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := 201
	if replay {
		status = 200
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, status, map[string]any{"campaign": v, "idempotentReplay": replay, "next": "explicit-campaign-approval"})
}
func (s *Server) listUpgradeCampaigns(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID != "" {
		if _, err := s.requireProjectAccess(r, projectID, organizationRead); err != nil {
			writeScopeError(w, err)
			return
		}
	}
	v, err := s.store.ListUpgradeCampaigns(r.Context(), projectID, r.URL.Query().Get("fleetGroupId"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed, all, err := s.accessibleProjectSet(r)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	v = filterProjectScoped(v, allowed, all, func(item controlplane.UpgradeCampaign) string { return item.ProjectID })
	writeJSON(w, 200, v)
}
func (s *Server) getUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetUpgradeCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, v.ProjectID, organizationRead); err != nil {
		writeScopeError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}
func (s *Server) approveUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetUpgradeCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := approvalActor(r, current.RequestedBy)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.ApproveUpgradeCampaign(r.Context(), r.PathValue("id"), rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

type revalidateUpgradeCampaignInput struct {
	RecoveryCheckpointIDs  []string  `json:"recoveryCheckpointIds,omitempty"`
	MaintenanceWindowStart time.Time `json:"maintenanceWindowStart,omitempty"`
	MaintenanceWindowEnd   time.Time `json:"maintenanceWindowEnd,omitempty"`
}

func (s *Server) revalidateUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetUpgradeCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in revalidateUpgradeCampaignInput
	if r.ContentLength != 0 {
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
	}
	v, err := s.store.RevalidateUpgradeCampaign(r.Context(), current.ID, rev, controlplane.UpgradeCampaignRevalidation{RecoveryCheckpointIDs: in.RecoveryCheckpointIDs, MaintenanceWindowStart: in.MaintenanceWindowStart, MaintenanceWindowEnd: in.MaintenanceWindowEnd}, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

type campaignControlInput struct {
	Reason string `json:"reason,omitempty"`
}

func (s *Server) pauseUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetUpgradeCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in campaignControlInput
	if r.ContentLength != 0 {
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
	}
	v, err := s.store.PauseUpgradeCampaign(r.Context(), current.ID, rev, actor, in.Reason)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) resumeUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetUpgradeCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	v, err := s.store.ResumeUpgradeCampaign(r.Context(), current.ID, rev, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) cancelUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	current, err := s.store.GetUpgradeCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, current.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	rev, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	var in campaignControlInput
	if r.ContentLength != 0 {
		if err = decodeJSON(w, r, &in); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
	}
	v, err := s.store.CancelUpgradeCampaign(r.Context(), current.ID, rev, actor, in.Reason)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, v.Revision)
	writeJSON(w, 200, v)
}

func (s *Server) campaignBaselineDeployment(r *http.Request, c controlplane.UpgradeCampaign, t controlplane.UpgradeCampaignTarget, version, keySuffix string) (controlplane.BaselineDeployment, error) {
	def, ok := baseline.GetVersion(c.BaselineID, version)
	if !ok {
		return controlplane.BaselineDeployment{}, fmt.Errorf("baseline version unavailable")
	}
	desired, err := baseline.DesiredDigestVersion(c.ProjectID, t.ClusterID, c.BaselineID, version)
	if err != nil {
		return controlplane.BaselineDeployment{}, err
	}
	request := struct{ Campaign, Cluster, Version, Digest string }{c.ID, t.ClusterID, version, desired}
	digest := jsonDigest(request)
	v, _, err := s.store.CreateBaselineDeployment(r.Context(), controlplane.BaselineDeployment{ProjectID: c.ProjectID, ClusterID: t.ClusterID, BaselineID: def.ID, BaselineVersion: def.Version, TargetNamespace: def.TargetNamespace, Risk: def.Risk, DesiredDigest: desired, RequestDigest: digest, IdempotencyKey: "campaign:" + c.ID + ":" + keySuffix + ":" + t.ClusterID}, "upgrade-campaign:"+c.ID)
	return v, err
}
func (s *Server) campaignRuntimeVerification(r *http.Request, c controlplane.UpgradeCampaign, deployment controlplane.BaselineDeployment, keySuffix string) (controlplane.RuntimeVerification, error) {
	if !strings.Contains(s.runtimeProbeImage, "@sha256:") {
		return controlplane.RuntimeVerification{}, fmt.Errorf("runtime probe image is unavailable")
	}
	request := struct{ Campaign, Deployment, Digest string }{c.ID, deployment.ID, deployment.DesiredDigest}
	digest := jsonDigest(request)
	v, _, err := s.store.CreateRuntimeVerification(r.Context(), controlplane.RuntimeVerification{ProjectID: c.ProjectID, ClusterID: deployment.ClusterID, BaselineDeploymentID: deployment.ID, ProbeImage: s.runtimeProbeImage, RequestDigest: digest, IdempotencyKey: "campaign:" + c.ID + ":" + keySuffix + ":" + deployment.ClusterID}, "upgrade-campaign:"+c.ID)
	return v, err
}

func (s *Server) advanceUpgradeCampaign(w http.ResponseWriter, r *http.Request) {
	actor, err := actorID(r)
	if err != nil {
		writeError(w, 401, "ACTOR_REQUIRED", err.Error())
		return
	}
	expected, err := parseExpectedRevision(r)
	if err != nil {
		writeError(w, 428, "EXPECTED_REVISION_REQUIRED", err.Error())
		return
	}
	c, err := s.store.GetUpgradeCampaign(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err = s.requireProjectAccess(r, c.ProjectID, organizationWrite); err != nil {
		writeScopeError(w, err)
		return
	}
	if c.Revision != expected {
		writeStoreError(w, controlplane.ErrConflict)
		return
	}
	if c.State == controlplane.UpgradeCampaignAwaitingApproval {
		writeError(w, 409, "CAMPAIGN_APPROVAL_REQUIRED", "approve the campaign before advancing")
		return
	}
	if c.State == controlplane.UpgradeCampaignSucceeded || c.State == controlplane.UpgradeCampaignFailed || c.State == controlplane.UpgradeCampaignCancelled {
		writeJSON(w, 200, c)
		return
	}
	if c.State == controlplane.UpgradeCampaignPaused {
		writeError(w, 409, "CAMPAIGN_PAUSED", "resume the campaign before advancing")
		return
	}
	now := time.Now().UTC()
	if c.State == controlplane.UpgradeCampaignQueued {
		c.State = controlplane.UpgradeCampaignRunning
		if c.CurrentWave < 1 {
			c.CurrentWave = 1
		}
		if c.StartedAt == nil {
			c.StartedAt = &now
		}
	}
	failures := 0
	for i := range c.Targets {
		t := &c.Targets[i]
		if t.Wave > c.CurrentWave || t.State == controlplane.UpgradeTargetSucceeded || t.State == controlplane.UpgradeTargetRolledBack {
			continue
		}
		if t.State == controlplane.UpgradeTargetPending {
			if c.State == controlplane.UpgradeCampaignPauseRequested || c.State == controlplane.UpgradeCampaignCancelRequested {
				continue
			}
			dep, e := s.campaignBaselineDeployment(r, c, *t, c.TargetVersion, "upgrade")
			if e != nil {
				t.State = controlplane.UpgradeTargetFailed
				t.LastError = e.Error()
				failures++
				continue
			}
			t.UpgradeDeploymentID = dep.ID
			t.State = controlplane.UpgradeTargetPlanning
		}
		if t.UpgradeDeploymentID != "" && t.State != controlplane.UpgradeTargetRollingBack {
			dep, e := s.store.GetBaselineDeployment(r.Context(), t.UpgradeDeploymentID)
			if e != nil {
				t.State = controlplane.UpgradeTargetFailed
				t.LastError = e.Error()
				failures++
				continue
			}
			switch dep.State {
			case controlplane.BaselineDeploymentPlanning:
				t.State = controlplane.UpgradeTargetPlanning
			case controlplane.BaselineDeploymentAwaitingApproval:
				if _, e = s.store.ApproveBaselineDeployment(r.Context(), dep.ID, dep.Revision, "upgrade-campaign:"+c.ID); e != nil {
					t.State = controlplane.UpgradeTargetFailed
					t.LastError = e.Error()
					failures++
				} else {
					t.State = controlplane.UpgradeTargetApplying
				}
			case controlplane.BaselineDeploymentQueued, controlplane.BaselineDeploymentApplying:
				t.State = controlplane.UpgradeTargetApplying
			case controlplane.BaselineDeploymentSucceeded:
				if !controlplane.BaselineCompletionEvidenceReady(dep, time.Now().UTC()) {
					t.State = controlplane.UpgradeTargetFailed
					t.LastError = "baseline completion evidence is missing, invalid or expired"
					failures++
					continue
				}
				if t.RuntimeVerificationID == "" {
					verify, e := s.campaignRuntimeVerification(r, c, dep, "verify-upgrade")
					if e != nil {
						t.State = controlplane.UpgradeTargetFailed
						t.LastError = e.Error()
						failures++
					} else {
						t.RuntimeVerificationID = verify.ID
						t.State = controlplane.UpgradeTargetVerifying
					}
				}
				if t.RuntimeVerificationID != "" {
					verify, e := s.store.GetRuntimeVerification(r.Context(), t.RuntimeVerificationID)
					if e == nil {
						if verify.State == controlplane.RuntimeVerificationSucceeded {
							t.State = controlplane.UpgradeTargetSucceeded
							t.LastError = ""
						} else if verify.State == controlplane.RuntimeVerificationFailed {
							t.State = controlplane.UpgradeTargetFailed
							t.LastError = verify.LastError
							failures++
						} else {
							t.State = controlplane.UpgradeTargetVerifying
						}
					}
				}
			case controlplane.BaselineDeploymentFailed, controlplane.BaselineDeploymentRolledBack:
				t.State = controlplane.UpgradeTargetFailed
				t.LastError = dep.LastError
				failures++
			}
		}
		if t.State == controlplane.UpgradeTargetFailed || t.State == controlplane.UpgradeTargetRollingBack {
			if t.RollbackDeploymentID == "" {
				rollback, e := s.campaignBaselineDeployment(r, c, *t, t.PreviousVersion, "rollback")
				if e != nil {
					t.LastError = t.LastError + "; rollback: " + e.Error()
					continue
				}
				t.RollbackDeploymentID = rollback.ID
				t.State = controlplane.UpgradeTargetRollingBack
			}
			rollback, e := s.store.GetBaselineDeployment(r.Context(), t.RollbackDeploymentID)
			if e != nil {
				t.LastError = t.LastError + "; rollback lookup: " + e.Error()
				continue
			}
			switch rollback.State {
			case controlplane.BaselineDeploymentAwaitingApproval:
				if _, e = s.store.ApproveBaselineDeployment(r.Context(), rollback.ID, rollback.Revision, "upgrade-campaign:"+c.ID); e != nil {
					t.LastError = strings.TrimSpace(t.LastError + "; rollback approval: " + e.Error())
					continue
				}
			case controlplane.BaselineDeploymentSucceeded:
				if !controlplane.BaselineCompletionEvidenceReady(rollback, time.Now().UTC()) {
					t.LastError = t.LastError + "; rollback completion evidence is missing, invalid or expired"
					continue
				}
				if t.RollbackVerificationID == "" {
					verify, e := s.campaignRuntimeVerification(r, c, rollback, "verify-rollback")
					if e == nil {
						t.RollbackVerificationID = verify.ID
					}
				}
				if t.RollbackVerificationID != "" {
					verify, e := s.store.GetRuntimeVerification(r.Context(), t.RollbackVerificationID)
					if e == nil && verify.State == controlplane.RuntimeVerificationSucceeded {
						t.State = controlplane.UpgradeTargetRolledBack
					} else if e == nil && verify.State == controlplane.RuntimeVerificationFailed {
						t.LastError = t.LastError + "; rollback verification failed: " + verify.LastError
					}
				}
			case controlplane.BaselineDeploymentFailed:
				t.LastError = t.LastError + "; rollback apply failed: " + rollback.LastError
			}
		}
	}
	failures = 0
	waveDone := true
	allSucceeded := true
	pendingLater := false
	for _, t := range c.Targets {
		if t.State == controlplane.UpgradeTargetFailed || t.State == controlplane.UpgradeTargetRollingBack || t.State == controlplane.UpgradeTargetRolledBack {
			failures++
		}
		if t.Wave == c.CurrentWave && t.State != controlplane.UpgradeTargetSucceeded && t.State != controlplane.UpgradeTargetRolledBack {
			waveDone = false
		}
		if t.State != controlplane.UpgradeTargetSucceeded {
			allSucceeded = false
		}
		if t.Wave > c.CurrentWave && t.State == controlplane.UpgradeTargetPending {
			pendingLater = true
		}
	}
	activeTargets := false
	for _, t := range c.Targets {
		if t.State == controlplane.UpgradeTargetPlanning || t.State == controlplane.UpgradeTargetApplying || t.State == controlplane.UpgradeTargetVerifying || t.State == controlplane.UpgradeTargetRollingBack {
			activeTargets = true
			break
		}
	}
	if allSucceeded {
		c.State = controlplane.UpgradeCampaignSucceeded
		c.Summary = "all fleet targets upgraded and runtime verified"
		c.FinishedAt = &now
	} else if c.State == controlplane.UpgradeCampaignCancelRequested && !activeTargets {
		c.State = controlplane.UpgradeCampaignCancelled
		c.CancelledBy = c.CancelRequestedBy
		c.CancelledAt = &now
		c.FinishedAt = &now
		c.Summary = fmt.Sprintf("campaign cancelled at safe point after wave %d; completed targets were preserved and pending targets were not started", c.CurrentWave)
	} else if c.State == controlplane.UpgradeCampaignPauseRequested && !activeTargets {
		c.State = controlplane.UpgradeCampaignPaused
		c.PausedAt = &now
		c.Summary = fmt.Sprintf("campaign paused at safe point after wave %d; no new target will start until resume", c.CurrentWave)
	} else if failures >= c.HaltAfterFailures && c.State != controlplane.UpgradeCampaignPauseRequested && c.State != controlplane.UpgradeCampaignCancelRequested {
		c.State = controlplane.UpgradeCampaignHalted
		c.Summary = fmt.Sprintf("campaign halted after %d failed target(s); affected targets are being rolled back", failures)
	} else if waveDone && pendingLater && c.State != controlplane.UpgradeCampaignPauseRequested && c.State != controlplane.UpgradeCampaignCancelRequested {
		c.CurrentWave++
		c.State = controlplane.UpgradeCampaignRunning
		c.Summary = "previous wave completed; next wave is ready"
	} else if c.State == controlplane.UpgradeCampaignPauseRequested {
		c.Summary = fmt.Sprintf("pause requested; wave %d active work is draining to a safe point", c.CurrentWave)
	} else if c.State == controlplane.UpgradeCampaignCancelRequested {
		c.Summary = fmt.Sprintf("cancel requested; wave %d active work is draining to a safe point", c.CurrentWave)
	} else {
		c.State = controlplane.UpgradeCampaignRunning
		c.Summary = fmt.Sprintf("wave %d is in progress", c.CurrentWave)
	}
	updated, err := s.store.UpdateUpgradeCampaign(r.Context(), c, expected, actor)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setRevisionETag(w, updated.Revision)
	writeJSON(w, 200, updated)
}
