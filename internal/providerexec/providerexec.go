package providerexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const Authority = "PUBLIC_CLOUD_PROVIDER_EXECUTION_AUTHORITY_V1"

type Provider string

const (
	ProviderVMware Provider = "vmware"
	ProviderAWS    Provider = "aws"
	ProviderAzure  Provider = "azure"
	ProviderGCP    Provider = "gcp"
)

type Descriptor struct {
	Provider            Provider
	ClusterTemplateKind string
	MachineTemplateKind string
	AllowsCustomEndpoint bool
	Architectures       []string
}

func DescriptorFor(raw string) (Descriptor, bool) {
	switch Provider(strings.ToLower(strings.TrimSpace(raw))) {
	case ProviderVMware:
		return Descriptor{Provider: ProviderVMware, ClusterTemplateKind: "VSphereClusterTemplate", MachineTemplateKind: "VSphereMachineTemplate", AllowsCustomEndpoint: true, Architectures: []string{"amd64"}}, true
	case ProviderAWS:
		return Descriptor{Provider: ProviderAWS, ClusterTemplateKind: "AWSClusterTemplate", MachineTemplateKind: "AWSMachineTemplate", Architectures: []string{"amd64"}}, true
	case ProviderAzure:
		return Descriptor{Provider: ProviderAzure, ClusterTemplateKind: "AzureClusterTemplate", MachineTemplateKind: "AzureMachineTemplate", Architectures: []string{"amd64"}}, true
	case ProviderGCP:
		return Descriptor{Provider: ProviderGCP, ClusterTemplateKind: "GCPClusterTemplate", MachineTemplateKind: "GCPMachineTemplate", Architectures: []string{"amd64"}}, true
	default:
		return Descriptor{}, false
	}
}

type Action string

const (
	ActionCreate Action = "CREATE"
	ActionUpdate Action = "UPDATE"
	ActionDelete Action = "DELETE"
)

type Outcome string

const (
	OutcomeApplied Outcome = "APPLIED"
	OutcomeNoop    Outcome = "NOOP"
	OutcomeUnknown Outcome = "UNKNOWN"
	OutcomeFailed  Outcome = "FAILED"
)

type State string

const (
	StateSucceeded        State = "SUCCEEDED"
	StateReconciling      State = "RECONCILING"
	StateRecoveryRequired State = "RECOVERY_REQUIRED"
	StateFailed           State = "FAILED"
)

type Request struct {
	Provider      Provider
	OperationID   string
	FenceToken    int64
	Action        Action
	ResourceID    string
	DesiredDigest string
	CredentialRef string
	Desired       map[string]any
}

type Plan struct {
	RequestDigest    string
	MutationRequired bool
	ExternalID       string
	Summary          string
}

type MutationInput struct {
	Request        Request
	Plan           Plan
	IdempotencyKey string
}

type MutationResult struct {
	Outcome           Outcome
	ExternalID        string
	ProviderRequestID string
	Message           string
}

type Observation struct {
	Exists         bool
	Ready          bool
	ObservedDigest string
	ExternalID     string
	Phase          string
}

type Result struct {
	Authority         string
	State             State
	RequestDigest     string
	IdempotencyKey    string
	MutationAttempted bool
	Mutation          MutationResult
	Observation       Observation
	RecoveryRequired  bool
	Message           string
}

type Adapter interface {
	Provider() Provider
	Plan(context.Context, Request) (Plan, error)
	Apply(context.Context, MutationInput) (MutationResult, error)
	Readback(context.Context, Request) (Observation, error)
}

type Engine struct{}

var (
	shaPattern        = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
	secretNamePattern = regexp.MustCompile("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
)

func validProvider(p Provider) bool {
	switch p {
	case ProviderAWS, ProviderAzure, ProviderGCP:
		return true
	default:
		return false
	}
}

func ValidateCredentialReference(ref string) error {
	const prefix = "external-secret://4so-provider-system/"
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, prefix) {
		return fmt.Errorf("credentialRef must use %s<name>", prefix)
	}
	name := strings.TrimPrefix(ref, prefix)
	if name == "" || len(name) > 253 || strings.Contains(name, "..") || !secretNamePattern.MatchString(name) {
		return errors.New("credentialRef contains an invalid external secret name")
	}
	return nil
}

func containsRawCredential(v any) bool {
	switch typed := v.(type) {
	case map[string]any:
		for key, value := range typed {
			normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.TrimSpace(key)))
			switch normalized {
			case "password", "token", "accesstoken", "refreshtoken", "clientsecret", "secretaccesskey", "accesskey", "accesskeyid", "privatekey", "credentials", "credential":
				return true
			}
			if containsRawCredential(value) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if containsRawCredential(item) {
				return true
			}
		}
	}
	return false
}

func ValidateRequest(v Request) error {
	if !validProvider(v.Provider) {
		return fmt.Errorf("unsupported provider %q", v.Provider)
	}
	if strings.TrimSpace(v.OperationID) == "" {
		return errors.New("operationId is required")
	}
	if v.FenceToken <= 0 {
		return errors.New("fenceToken must be positive")
	}
	switch v.Action {
	case ActionCreate, ActionUpdate, ActionDelete:
	default:
		return fmt.Errorf("unsupported action %q", v.Action)
	}
	if v.Action != ActionCreate && strings.TrimSpace(v.ResourceID) == "" {
		return errors.New("resourceId is required for update/delete")
	}
	if v.Action != ActionDelete && !shaPattern.MatchString(strings.TrimSpace(v.DesiredDigest)) {
		return errors.New("desiredDigest must be an exact sha256 digest")
	}
	if err := ValidateCredentialReference(v.CredentialRef); err != nil {
		return err
	}
	if containsRawCredential(v.Desired) {
		return errors.New("desired payload contains raw credential material")
	}
	return nil
}

func RequestDigest(v Request) (string, error) {
	if err := ValidateRequest(v); err != nil {
		return "", err
	}
	raw, err := json.Marshal([]any{
		Authority,
		v.Provider,
		strings.TrimSpace(v.OperationID),
		v.FenceToken,
		v.Action,
		strings.TrimSpace(v.ResourceID),
		strings.TrimSpace(v.DesiredDigest),
		strings.TrimSpace(v.CredentialRef),
		v.Desired,
	})
	if err != nil {
		return "", fmt.Errorf("encode provider execution request: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func idempotencyKey(v Request, digest string) string {
	raw := fmt.Sprintf("%s|%s|%d|%s", v.Provider, strings.TrimSpace(v.OperationID), v.FenceToken, digest)
	sum := sha256.Sum256([]byte(raw))
	return "4so-provider-" + string(v.Provider) + "-" + hex.EncodeToString(sum[:16])
}

func converged(v Request, observed Observation) bool {
	if v.Action == ActionDelete {
		return !observed.Exists
	}
	return observed.Exists && observed.ObservedDigest == strings.TrimSpace(v.DesiredDigest)
}

func (Engine) Execute(ctx context.Context, adapter Adapter, request Request) Result {
	result := Result{Authority: Authority}
	digest, err := RequestDigest(request)
	if err != nil {
		result.State = StateFailed
		result.Message = err.Error()
		return result
	}
	result.RequestDigest = digest
	if adapter == nil {
		result.State = StateFailed
		result.Message = "provider adapter is required"
		return result
	}
	if adapter.Provider() != request.Provider {
		result.State = StateFailed
		result.Message = fmt.Sprintf("adapter provider %q does not match request provider %q", adapter.Provider(), request.Provider)
		return result
	}

	plan, err := adapter.Plan(ctx, request)
	if err != nil {
		result.State = StateFailed
		result.Message = "plan provider mutation: " + err.Error()
		return result
	}
	if plan.RequestDigest != digest {
		result.State = StateFailed
		result.Message = "provider plan request digest mismatch"
		return result
	}

	if !plan.MutationRequired {
		observation, readErr := adapter.Readback(ctx, request)
		result.Observation = observation
		if readErr != nil {
			result.State = StateFailed
			result.Message = "readback no-op plan: " + readErr.Error()
			return result
		}
		if !converged(request, observation) {
			result.State = StateFailed
			result.Message = "no-op plan did not match authoritative readback"
			return result
		}
		result.State = StateSucceeded
		result.Mutation = MutationResult{Outcome: OutcomeNoop, ExternalID: observation.ExternalID}
		return result
	}

	key := idempotencyKey(request, digest)
	result.IdempotencyKey = key
	result.MutationAttempted = true
	mutation, applyErr := adapter.Apply(ctx, MutationInput{Request: request, Plan: plan, IdempotencyKey: key})
	result.Mutation = mutation

	switch mutation.Outcome {
	case OutcomeFailed:
		result.State = StateFailed
		if applyErr != nil {
			result.Message = applyErr.Error()
		} else if mutation.Message != "" {
			result.Message = mutation.Message
		} else {
			result.Message = "provider mutation failed"
		}
		return result
	case OutcomeUnknown:
		observation, readErr := adapter.Readback(ctx, request)
		result.Observation = observation
		if readErr == nil && converged(request, observation) {
			result.State = StateSucceeded
			result.Message = "ambiguous mutation resolved by authoritative readback"
			return result
		}
		result.State = StateRecoveryRequired
		result.RecoveryRequired = true
		if readErr != nil {
			result.Message = "ambiguous mutation requires recovery; readback failed: " + readErr.Error()
		} else {
			result.Message = "ambiguous mutation requires recovery; readback did not prove convergence"
		}
		return result
	case OutcomeApplied:
		if applyErr != nil {
			result.State = StateRecoveryRequired
			result.RecoveryRequired = true
			result.Message = "adapter reported applied with an error; authoritative recovery is required"
			return result
		}
	default:
		result.State = StateFailed
		result.Message = fmt.Sprintf("provider adapter returned invalid mutation outcome %q", mutation.Outcome)
		return result
	}

	observation, readErr := adapter.Readback(ctx, request)
	result.Observation = observation
	if readErr != nil {
		result.State = StateRecoveryRequired
		result.RecoveryRequired = true
		result.Message = "provider mutation applied but authoritative readback failed: " + readErr.Error()
		return result
	}
	if converged(request, observation) {
		result.State = StateSucceeded
		return result
	}
	result.State = StateReconciling
	result.Message = "provider accepted mutation; authoritative readback has not converged"
	return result
}
