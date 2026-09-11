package managedinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
)

const Authority = "BAREMETAL_MANAGED_INSTALL_AUTHORITY_V2"
const PayloadMediaType = "application/vnd.4so.managed-okd-install+json"

type Status string

const (
	StatusAwaitingApproval Status = "AWAITING_APPROVAL"
	StatusQueued           Status = "QUEUED"
	StatusRunning          Status = "RUNNING"
	StatusSucceeded        Status = "SUCCEEDED"
	StatusFailed           Status = "FAILED"
)

type Step string

const (
	StepValidateArtifacts   Step = "VALIDATE_ARTIFACTS"
	StepPrepareMirror       Step = "PREPARE_DISCONNECTED_MIRROR"
	StepAttachMedia         Step = "ATTACH_MEDIA"
	StepOneTimeBoot         Step = "SET_ONE_TIME_BOOT"
	StepPowerCycle          Step = "POWER_CYCLE"
	StepObserveBootstrap    Step = "OBSERVE_BOOTSTRAP"
	StepConnectedInstall    Step = "CONNECTED_INSTALL"
	StepDisconnectedInstall Step = "DISCONNECTED_INSTALL"
	StepRegisterCluster     Step = "REGISTER_CLUSTER"
	StepComplete            Step = "COMPLETE"
)

type Artifact struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

type DisconnectedConfig struct {
	MirrorRegistry              string `json:"mirrorRegistry"`
	ImageSetConfigurationSHA256 string `json:"imageSetConfigurationSha256"`
	MirrorInventorySHA256       string `json:"mirrorInventorySha256"`
}

type Machine struct {
	ID                   string `json:"id"`
	CredentialRef        string `json:"credentialRef"`
	Endpoint             string `json:"endpoint"`
	SystemResource       string `json:"systemResource"`
	VirtualMediaResource string `json:"virtualMediaResource"`
}

type Request struct {
	OrganizationID string              `json:"organizationId"`
	ProjectID      string              `json:"projectId"`
	TargetVersion  string              `json:"targetVersion"`
	ClusterName    string              `json:"clusterName"`
	BaseDomain     string              `json:"baseDomain"`
	APIVIP         string              `json:"apiVip"`
	IngressVIP     string              `json:"ingressVip"`
	Connectivity   string              `json:"connectivity,omitempty"`
	Disconnected   *DisconnectedConfig `json:"disconnected,omitempty"`
	Machines       []Machine           `json:"machines"`
	Artifacts      []Artifact          `json:"artifacts"`
}

type Operation struct {
	ID              string `json:"id"`
	RequesterActor  string `json:"requesterActor"`
	ApproverActor   string `json:"approverActor,omitempty"`
	RequestDigest   string `json:"requestDigest"`
	Connectivity    string `json:"connectivity"`
	Status          Status `json:"status"`
	Step            Step   `json:"step"`
	Revision        uint64 `json:"revision"`
	Fence           uint64 `json:"fence"`
	Sequence        uint64 `json:"sequence"`
	LastEvidenceKey string `json:"lastEvidenceKey,omitempty"`
}

func canonicalHTTPS(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || strings.TrimSpace(u.Host) == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("https URL without credentials or fragment is required")
	}
	return u.String(), nil
}

func CanonicalRequest(req Request) (Request, error) {
	req.OrganizationID = strings.TrimSpace(req.OrganizationID)
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.TargetVersion = strings.TrimSpace(req.TargetVersion)
	req.ClusterName = strings.ToLower(strings.TrimSpace(req.ClusterName))
	req.BaseDomain = strings.ToLower(strings.TrimSpace(req.BaseDomain))
	req.APIVIP = strings.TrimSpace(req.APIVIP)
	req.IngressVIP = strings.TrimSpace(req.IngressVIP)
	req.Connectivity = strings.ToLower(strings.TrimSpace(req.Connectivity))
	if req.Connectivity == "" {
		req.Connectivity = "connected"
	}
	if req.Disconnected != nil {
		req.Disconnected.MirrorRegistry = strings.ToLower(strings.Trim(strings.TrimSpace(req.Disconnected.MirrorRegistry), "/"))
		req.Disconnected.ImageSetConfigurationSHA256 = strings.ToLower(strings.TrimSpace(req.Disconnected.ImageSetConfigurationSHA256))
		req.Disconnected.MirrorInventorySHA256 = strings.ToLower(strings.TrimSpace(req.Disconnected.MirrorInventorySHA256))
	}
	for i := range req.Machines {
		m := &req.Machines[i]
		m.ID = strings.TrimSpace(m.ID)
		m.CredentialRef = strings.TrimSpace(m.CredentialRef)
		m.Endpoint = strings.TrimRight(strings.TrimSpace(m.Endpoint), "/")
		m.SystemResource = strings.TrimSpace(m.SystemResource)
		m.VirtualMediaResource = strings.TrimSpace(m.VirtualMediaResource)
	}
	for i := range req.Artifacts {
		a := &req.Artifacts[i]
		a.Name = strings.ToLower(strings.TrimSpace(a.Name))
		a.Version = strings.TrimSpace(a.Version)
		a.URL = strings.TrimSpace(a.URL)
		a.SHA256 = strings.ToLower(strings.TrimSpace(a.SHA256))
	}
	sort.Slice(req.Machines, func(i, j int) bool { return req.Machines[i].ID < req.Machines[j].ID })
	sort.Slice(req.Artifacts, func(i, j int) bool { return req.Artifacts[i].Name < req.Artifacts[j].Name })
	if err := ValidateRequest(req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func NewOperation(id, requester string, req Request) (Operation, error) {
	id = strings.TrimSpace(id)
	requester = strings.TrimSpace(requester)
	if id == "" || requester == "" {
		return Operation{}, errors.New("operation id and requester are required")
	}
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return Operation{}, err
	}
	digest, err := DigestRequest(canonical)
	if err != nil {
		return Operation{}, err
	}
	return Operation{ID: id, RequesterActor: requester, RequestDigest: digest, Connectivity: canonical.Connectivity, Status: StatusAwaitingApproval, Step: StepValidateArtifacts, Revision: 1}, nil
}

func Approve(op Operation, actor string) (Operation, error) {
	actor = strings.TrimSpace(actor)
	if op.Status != StatusAwaitingApproval {
		return op, fmt.Errorf("operation is not awaiting approval: %s", op.Status)
	}
	if actor == "" || actor == op.RequesterActor {
		return op, errors.New("independent approval actor is required")
	}
	op.ApproverActor = actor
	op.Status = StatusQueued
	op.Revision++
	return op, nil
}

func Claim(op Operation, fence uint64) (Operation, error) {
	if op.Status != StatusQueued && op.Status != StatusRunning {
		return op, fmt.Errorf("operation is not claimable: %s", op.Status)
	}
	if fence == 0 || fence <= op.Fence {
		return op, fmt.Errorf("stale fence %d; current fence %d", fence, op.Fence)
	}
	op.Fence = fence
	op.Status = StatusRunning
	op.Revision++
	return op, nil
}

func Advance(op Operation, fence uint64, evidenceKey string) (Operation, error) {
	if op.Status != StatusRunning {
		return op, fmt.Errorf("operation is not running: %s", op.Status)
	}
	if fence != op.Fence || fence == 0 {
		return op, fmt.Errorf("fence mismatch: got %d want %d", fence, op.Fence)
	}
	if strings.TrimSpace(evidenceKey) == "" {
		return op, errors.New("evidence key is required")
	}
	switch op.Step {
	case StepValidateArtifacts:
		if strings.EqualFold(op.Connectivity, "disconnected") {
			op.Step = StepPrepareMirror
		} else {
			op.Step = StepAttachMedia
		}
	case StepPrepareMirror:
		op.Step = StepAttachMedia
	case StepAttachMedia:
		op.Step = StepOneTimeBoot
	case StepOneTimeBoot:
		op.Step = StepPowerCycle
	case StepPowerCycle:
		op.Step = StepObserveBootstrap
	case StepObserveBootstrap:
		if strings.EqualFold(op.Connectivity, "disconnected") {
			op.Step = StepDisconnectedInstall
		} else {
			op.Step = StepConnectedInstall
		}
	case StepConnectedInstall, StepDisconnectedInstall:
		op.Step = StepRegisterCluster
	case StepRegisterCluster:
		op.Step = StepComplete
		op.Status = StatusSucceeded
	case StepComplete:
		return op, errors.New("operation is already complete")
	default:
		return op, fmt.Errorf("unknown managed-install step %q", op.Step)
	}
	op.Sequence++
	op.Revision++
	op.LastEvidenceKey = strings.TrimSpace(evidenceKey)
	return op, nil
}

func MarshalCanonicalRequest(req Request) ([]byte, string, error) {
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return nil, "", err
	}
	digest, err := DigestRequest(canonical)
	return raw, digest, err
}

func ParseCanonicalRequest(raw []byte, expectedDigest string) (Request, error) {
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return Request{}, err
	}
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return Request{}, err
	}
	digest, err := DigestRequest(canonical)
	if err != nil {
		return Request{}, err
	}
	if strings.TrimSpace(expectedDigest) != "" && digest != strings.TrimSpace(expectedDigest) {
		return Request{}, errors.New("managed-install request digest mismatch")
	}
	return canonical, nil
}

func DigestRequest(req Request) (string, error) {
	canonical, err := CanonicalRequest(req)
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal(struct {
		Authority string  `json:"authority"`
		Request   Request `json:"request"`
	}{Authority: Authority, Request: canonical})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateRequest(req Request) error {
	if strings.TrimSpace(req.OrganizationID) == "" || strings.TrimSpace(req.ProjectID) == "" {
		return errors.New("organization and project are required")
	}
	if strings.TrimSpace(req.TargetVersion) == "" || strings.TrimSpace(req.ClusterName) == "" || strings.TrimSpace(req.BaseDomain) == "" || strings.TrimSpace(req.APIVIP) == "" || strings.TrimSpace(req.IngressVIP) == "" {
		return errors.New("target version, cluster name, base domain and API/Ingress VIPs are required")
	}
	if len(req.ClusterName) > 54 || strings.ContainsAny(req.ClusterName, " /\\:@") || !strings.Contains(req.BaseDomain, ".") {
		return errors.New("cluster name or base domain is invalid")
	}
	if req.APIVIP == req.IngressVIP {
		return errors.New("API and Ingress VIPs must be distinct")
	}
	switch strings.ToLower(strings.TrimSpace(req.Connectivity)) {
	case "", "connected":
		if req.Disconnected != nil {
			return errors.New("disconnected configuration is forbidden for connected installs")
		}
	case "disconnected":
		if req.Disconnected == nil {
			return errors.New("disconnected installs require mirror configuration")
		}
		if err := validateDisconnectedConfig(*req.Disconnected); err != nil {
			return err
		}
	default:
		return errors.New("connectivity must be connected or disconnected")
	}
	if len(req.Machines) != 3 {
		return fmt.Errorf("Compact-3 requires exactly 3 machines; got %d", len(req.Machines))
	}
	seenMachines := map[string]struct{}{}
	for _, machine := range req.Machines {
		id := strings.TrimSpace(machine.ID)
		if id == "" || strings.TrimSpace(machine.Endpoint) == "" || strings.TrimSpace(machine.CredentialRef) == "" || strings.TrimSpace(machine.SystemResource) == "" || strings.TrimSpace(machine.VirtualMediaResource) == "" {
			return errors.New("machine id, endpoint, credential reference and Redfish resources are required")
		}
		if strings.ContainsAny(machine.CredentialRef, "=\r\n\t") || strings.Contains(machine.CredentialRef, "://") {
			return errors.New("credentialRef must be an opaque reference, not secret material")
		}
		if _, err := canonicalHTTPS(machine.Endpoint); err != nil {
			return fmt.Errorf("machine %q endpoint: %w", id, err)
		}
		for name, resource := range map[string]string{"systemResource": machine.SystemResource, "virtualMediaResource": machine.VirtualMediaResource} {
			if !strings.HasPrefix(resource, "/redfish/v1/") || strings.ContainsAny(resource, "?#%\r\n") || path.Clean(resource) != resource {
				return fmt.Errorf("machine %q %s must be an absolute canonical Redfish path", id, name)
			}
		}
		if _, exists := seenMachines[id]; exists {
			return fmt.Errorf("duplicate machine id %q", id)
		}
		seenMachines[id] = struct{}{}
	}
	if len(req.Artifacts) < 3 {
		return errors.New("release payload, FCOS and Agent ISO artifacts are required")
	}
	seenArtifacts := map[string]struct{}{}
	required := map[string]bool{"release-payload": false, "fcos": false, "agent-iso": false}
	for _, artifact := range req.Artifacts {
		name := strings.ToLower(strings.TrimSpace(artifact.Name))
		digest := strings.ToLower(strings.TrimSpace(artifact.SHA256))
		if name == "" || len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
			return fmt.Errorf("artifact %q requires canonical sha256 digest", name)
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
			return fmt.Errorf("artifact %q has invalid sha256 digest", name)
		}
		if _, err := canonicalHTTPS(artifact.URL); err != nil {
			return fmt.Errorf("artifact %q URL: %w", name, err)
		}
		if _, exists := seenArtifacts[name]; exists {
			return fmt.Errorf("duplicate artifact %q", name)
		}
		seenArtifacts[name] = struct{}{}
		if _, ok := required[name]; ok {
			required[name] = true
		}
		if (name == "release-payload" || name == "agent-iso") && strings.TrimSpace(artifact.Version) != strings.TrimSpace(req.TargetVersion) {
			return fmt.Errorf("artifact %q version must equal targetVersion", name)
		}
	}
	for name, ok := range required {
		if !ok {
			return fmt.Errorf("required artifact %q is missing", name)
		}
	}
	return nil
}

func validateDisconnectedConfig(cfg DisconnectedConfig) error {
	registry := strings.Trim(strings.ToLower(strings.TrimSpace(cfg.MirrorRegistry)), "/")
	if registry == "" || strings.Contains(registry, "://") || strings.ContainsAny(registry, "@?#\\ \t\r\n") {
		return errors.New("disconnected mirrorRegistry must be a credential-free registry host/path without scheme")
	}
	parsed, err := url.Parse("https://" + registry)
	if err != nil || strings.TrimSpace(parsed.Host) == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("disconnected mirrorRegistry is invalid")
	}
	if parsed.Path != "" && parsed.Path != "/" && path.Clean(parsed.Path) != parsed.Path {
		return errors.New("disconnected mirrorRegistry path must be canonical")
	}
	for label, digest := range map[string]string{
		"imageSetConfigurationSha256": cfg.ImageSetConfigurationSHA256,
		"mirrorInventorySha256":       cfg.MirrorInventorySHA256,
	} {
		digest = strings.ToLower(strings.TrimSpace(digest))
		if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
			return fmt.Errorf("%s must be sha256:<64 hex>", label)
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
			return fmt.Errorf("%s is not valid hexadecimal SHA-256", label)
		}
	}
	return nil
}

func IsDisconnected(req Request) bool {
	return strings.EqualFold(strings.TrimSpace(req.Connectivity), "disconnected")
}

func ArtifactByName(req Request, name string) (Artifact, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, artifact := range req.Artifacts {
		if artifact.Name == name {
			return artifact, true
		}
	}
	return Artifact{}, false
}

// OrderedSteps returns the canonical crash-resume sequence. Callers must treat
// this order as authority and persist evidence after each completed step.
func OrderedSteps() []Step {
	return []Step{StepValidateArtifacts, StepAttachMedia, StepOneTimeBoot, StepPowerCycle, StepObserveBootstrap, StepConnectedInstall, StepRegisterCluster, StepComplete}
}

// OrderedStepsFor returns the crash-resume sequence for the sealed request.
// Disconnected installs mirror only from the exact local archive before any
// machine is powered and use a distinct install evidence step so connected and
// air-gapped claims can never be conflated.
func OrderedStepsFor(req Request) []Step {
	if IsDisconnected(req) {
		return []Step{StepValidateArtifacts, StepPrepareMirror, StepAttachMedia, StepOneTimeBoot, StepPowerCycle, StepObserveBootstrap, StepDisconnectedInstall, StepRegisterCluster, StepComplete}
	}
	return OrderedSteps()
}
