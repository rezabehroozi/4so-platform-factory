package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const WorkspaceAuthority = "WORKSPACE_AUTHORITY_V1"

type Workspace struct {
	ResourceMeta
	ProjectID   string `json:"projectId"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Digest      string `json:"digest"`
	CreatedBy   string `json:"createdBy"`
}

type WorkspaceBindingState string

const (
	WorkspaceBindingActive  WorkspaceBindingState = "ACTIVE"
	WorkspaceBindingRevoked WorkspaceBindingState = "REVOKED"
)

type WorkspaceBinding struct {
	ResourceMeta
	WorkspaceID string                `json:"workspaceId"`
	ProjectID   string                `json:"projectId"`
	ClusterID   string                `json:"clusterId"`
	Namespace   string                `json:"namespace"`
	State       WorkspaceBindingState `json:"state"`
	CreatedBy   string                `json:"createdBy"`
	RevokedBy   string                `json:"revokedBy,omitempty"`
	RevokedAt   *time.Time            `json:"revokedAt,omitempty"`
}

var workspaceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var workspaceNamespacePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func cloneWorkspace(in Workspace) Workspace { return in }
func cloneWorkspaceBinding(in WorkspaceBinding) WorkspaceBinding {
	out := in
	if in.RevokedAt != nil {
		v := *in.RevokedAt
		out.RevokedAt = &v
	}
	return out
}

func NormalizeWorkspace(in Workspace) (Workspace, error) {
	out := cloneWorkspace(in)
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.Name = normalizeName(out.Name)
	out.DisplayName = strings.TrimSpace(out.DisplayName)
	out.Description = strings.TrimSpace(out.Description)
	out.CreatedBy = strings.TrimSpace(out.CreatedBy)
	if out.ProjectID == "" || out.Name == "" || out.DisplayName == "" {
		return Workspace{}, fmt.Errorf("%w: projectId, name and displayName are required", ErrValidation)
	}
	if !workspaceNamePattern.MatchString(out.Name) {
		return Workspace{}, fmt.Errorf("%w: workspace name must be a DNS-style product identifier", ErrValidation)
	}
	if len(out.DisplayName) > 128 || len(out.Description) > 1024 {
		return Workspace{}, fmt.Errorf("%w: workspace displayName or description exceeds limit", ErrValidation)
	}
	material := struct {
		ProjectID   string `json:"projectId"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
		Description string `json:"description,omitempty"`
	}{out.ProjectID, out.Name, out.DisplayName, out.Description}
	raw, _ := json.Marshal(material)
	sum := sha256.Sum256(raw)
	out.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return out, nil
}

func NormalizeWorkspaceBinding(in WorkspaceBinding) (WorkspaceBinding, error) {
	out := cloneWorkspaceBinding(in)
	out.WorkspaceID = strings.TrimSpace(out.WorkspaceID)
	out.ProjectID = strings.TrimSpace(out.ProjectID)
	out.ClusterID = strings.TrimSpace(out.ClusterID)
	out.Namespace = strings.ToLower(strings.TrimSpace(out.Namespace))
	out.CreatedBy = strings.TrimSpace(out.CreatedBy)
	out.RevokedBy = strings.TrimSpace(out.RevokedBy)
	if out.WorkspaceID == "" || out.ProjectID == "" || out.ClusterID == "" || out.Namespace == "" {
		return WorkspaceBinding{}, fmt.Errorf("%w: workspaceId, projectId, clusterId and namespace are required", ErrValidation)
	}
	if len(out.Namespace) > 63 || !workspaceNamespacePattern.MatchString(out.Namespace) {
		return WorkspaceBinding{}, fmt.Errorf("%w: namespace must be a Kubernetes DNS-1123 label", ErrValidation)
	}
	if out.State == "" {
		out.State = WorkspaceBindingActive
	}
	switch out.State {
	case WorkspaceBindingActive:
		if out.RevokedAt != nil || out.RevokedBy != "" {
			return WorkspaceBinding{}, fmt.Errorf("%w: active workspace binding cannot contain revocation metadata", ErrValidation)
		}
	case WorkspaceBindingRevoked:
		if out.RevokedAt == nil || out.RevokedBy == "" {
			return WorkspaceBinding{}, fmt.Errorf("%w: revoked workspace binding requires revokedAt and revokedBy", ErrValidation)
		}
	default:
		return WorkspaceBinding{}, fmt.Errorf("%w: unsupported workspace binding state %q", ErrValidation, out.State)
	}
	return out, nil
}

func sortWorkspaces(out []Workspace) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
}

func sortWorkspaceBindings(out []WorkspaceBinding) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClusterID != out[j].ClusterID {
			return out[i].ClusterID < out[j].ClusterID
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].ID < out[j].ID
	})
}
