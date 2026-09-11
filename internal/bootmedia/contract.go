package bootmedia

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

const Authority = "BOOT_MEDIA_PROVIDER_AUTHORITY_V1"

type Step string

const (
	StepAttach      Step = "ATTACH"
	StepOneTimeBoot Step = "SET_ONE_TIME_BOOT"
	StepPowerCycle  Step = "POWER_CYCLE"
	StepObserve     Step = "OBSERVE"
	StepComplete    Step = "COMPLETE"
)

type State string

const (
	StateRequested State = "REQUESTED"
	StateRunning   State = "RUNNING"
	StateSucceeded State = "SUCCEEDED"
	StateFailed    State = "FAILED"
)

type Request struct {
	OrganizationID       string `json:"organizationId"`
	ProjectID            string `json:"projectId"`
	MachineID            string `json:"machineId"`
	Provider             string `json:"provider"`
	Endpoint             string `json:"endpoint"`
	CredentialRef        string `json:"credentialRef"`
	MediaURL             string `json:"mediaUrl"`
	MediaSHA256          string `json:"mediaSha256"`
	SystemResource       string `json:"systemResource"`
	VirtualMediaResource string `json:"virtualMediaResource"`
	IdempotencyKey       string `json:"idempotencyKey"`
}

type Operation struct {
	ID             string `json:"id"`
	RequestDigest  string `json:"requestDigest"`
	State          State  `json:"state"`
	NextStep       Step   `json:"nextStep"`
	Revision       int64  `json:"revision"`
	Fence          int64  `json:"fence"`
	LastError      string `json:"lastError,omitempty"`
	EvidenceDigest string `json:"evidenceDigest,omitempty"`
}

type Observation struct {
	Attached       bool   `json:"attached"`
	OneTimeBootSet bool   `json:"oneTimeBootSet"`
	Powered        bool   `json:"powered"`
	BootState      string `json:"bootState"`
}

type Provider interface {
	Attach(Request) error
	SetOneTimeBoot(Request) error
	PowerCycle(Request) error
	Observe(Request) (Observation, error)
}

type ContextualProvider interface {
	Provider
	AttachContext(context.Context, Request) error
	SetOneTimeBootContext(context.Context, Request) error
	PowerCycleContext(context.Context, Request) error
	ObserveContext(context.Context, Request) (Observation, error)
}

func ValidateRequest(r Request) error {
	for name, value := range map[string]string{
		"organizationId":       r.OrganizationID,
		"projectId":            r.ProjectID,
		"machineId":            r.MachineID,
		"provider":             r.Provider,
		"endpoint":             r.Endpoint,
		"credentialRef":        r.CredentialRef,
		"mediaUrl":             r.MediaURL,
		"mediaSha256":          r.MediaSHA256,
		"systemResource":       r.SystemResource,
		"virtualMediaResource": r.VirtualMediaResource,
		"idempotencyKey":       r.IdempotencyKey,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if r.Provider != "redfish" {
		return fmt.Errorf("unsupported boot-media provider %q", r.Provider)
	}
	for name, resource := range map[string]string{"systemResource": r.SystemResource, "virtualMediaResource": r.VirtualMediaResource} {
		if !strings.HasPrefix(resource, "/redfish/v1/") || strings.Contains(resource, "://") || strings.ContainsAny(resource, "?#%\r\n") || path.Clean(resource) != resource {
			return fmt.Errorf("%s must be an absolute Redfish resource path under /redfish/v1/ without query or fragment", name)
		}
	}
	if strings.ContainsAny(r.CredentialRef, "\r\n\t") || strings.Contains(r.CredentialRef, "://") || strings.Contains(r.CredentialRef, "=") {
		return errors.New("credentialRef must be an opaque server-side reference, not inline credential material")
	}
	endpoint, err := url.Parse(r.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
		return errors.New("endpoint must be an https URL without inline credentials")
	}
	media, err := url.Parse(r.MediaURL)
	if err != nil || media.Scheme != "https" || media.Host == "" || media.User != nil {
		return errors.New("mediaUrl must be an https URL without inline credentials")
	}
	if len(r.MediaSHA256) != 64 {
		return errors.New("mediaSha256 must be an exact sha256 digest")
	}
	if _, err := hex.DecodeString(r.MediaSHA256); err != nil {
		return errors.New("mediaSha256 must be lowercase/uppercase hexadecimal")
	}
	return nil
}

func RequestDigest(r Request) (string, error) {
	if err := ValidateRequest(r); err != nil {
		return "", err
	}
	parts := []string{
		Authority, r.OrganizationID, r.ProjectID, r.MachineID, r.Provider,
		r.Endpoint, r.CredentialRef, r.MediaURL, strings.ToLower(r.MediaSHA256), r.SystemResource, r.VirtualMediaResource, r.IdempotencyKey,
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:]), nil
}

func EvidenceDigest(op Operation, obs Observation) string {
	parts := []string{
		Authority, op.ID, op.RequestDigest, string(op.State), string(op.NextStep),
		"attached=" + fmt.Sprintf("%t", obs.Attached),
		"oneTimeBootSet=" + fmt.Sprintf("%t", obs.OneTimeBootSet),
		"powered=" + fmt.Sprintf("%t", obs.Powered),
		"bootState=" + obs.BootState,
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

// Advance executes exactly one fenced, restart-safe transition. The caller owns
// durable persistence/lease acquisition and must persist the returned Operation
// before attempting the next transition.
func Advance(p Provider, req Request, op Operation, fence int64) (Operation, Observation, error) {
	if err := ValidateRequest(req); err != nil {
		return op, Observation{}, err
	}
	if fence <= 0 || (op.Fence != 0 && fence < op.Fence) {
		return op, Observation{}, errors.New("stale or invalid boot-media fence")
	}
	if op.State == StateSucceeded {
		return op, Observation{}, nil
	}
	if op.NextStep == "" {
		op.NextStep = StepAttach
	}
	op.Fence = fence
	op.State = StateRunning
	var obs Observation
	var err error
	switch op.NextStep {
	case StepAttach:
		err = p.Attach(req)
		if err == nil {
			op.NextStep = StepOneTimeBoot
		}
	case StepOneTimeBoot:
		err = p.SetOneTimeBoot(req)
		if err == nil {
			op.NextStep = StepPowerCycle
		}
	case StepPowerCycle:
		err = p.PowerCycle(req)
		if err == nil {
			op.NextStep = StepObserve
		}
	case StepObserve:
		obs, err = p.Observe(req)
		if err == nil {
			if !obs.Attached || !obs.OneTimeBootSet || !obs.Powered || strings.TrimSpace(obs.BootState) == "" {
				err = errors.New("provider observation does not prove attach/one-time-boot/power/boot state")
			} else {
				op.NextStep = StepComplete
				op.State = StateSucceeded
			}
		}
	case StepComplete:
		op.State = StateSucceeded
	default:
		err = fmt.Errorf("unknown boot-media step %q", op.NextStep)
	}
	op.Revision++
	if err != nil {
		op.State = StateFailed
		op.LastError = err.Error()
		return op, obs, err
	}
	op.LastError = ""
	if op.State == StateSucceeded {
		op.EvidenceDigest = EvidenceDigest(op, obs)
	}
	return op, obs, nil
}
