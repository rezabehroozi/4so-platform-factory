package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"platform.4so.io/factory/internal/controlplane"
	"platform.4so.io/factory/internal/managedinstall"
)

const managedOKDRegistrationAuthority = "MANAGED_OKD_CLUSTER_REGISTRATION_V1"

type managedOKDRegistrationManifestApplier interface {
	ApplyRegistrationManifest(context.Context, managedinstall.Request, string, string) (map[string]any, error)
}

type ManagedOKDRegistrar struct {
	server      *Server
	applier     managedOKDRegistrationManifestApplier
	signingKey  []byte
	WaitTimeout time.Duration
	Poll        time.Duration
}

func (s *Server) NewManagedOKDRegistrar(applier managedOKDRegistrationManifestApplier, signingKey []byte, waitTimeout time.Duration) (*ManagedOKDRegistrar, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("managed OKD registrar requires server store authority")
	}
	if applier == nil {
		return nil, errors.New("managed OKD registrar requires exact workspace manifest applier")
	}
	if len(signingKey) < 32 {
		return nil, errors.New("managed OKD registrar signing key must contain at least 32 bytes")
	}
	if strings.TrimSpace(s.fleetAgentImage) == "" || !strings.Contains(s.fleetAgentImage, "@sha256:") {
		return nil, errors.New("managed OKD registrar requires digest-pinned fleet agent image")
	}
	if strings.TrimSpace(s.runtimeProbeImage) == "" || !strings.Contains(s.runtimeProbeImage, "@sha256:") {
		return nil, errors.New("managed OKD registrar requires digest-pinned runtime probe image")
	}
	if !validFleetPublicURL(strings.TrimRight(strings.TrimSpace(s.fleetPublicURL), "/")) {
		return nil, errors.New("managed OKD registrar requires valid HTTPS fleet public URL")
	}
	if waitTimeout <= 0 {
		waitTimeout = 30 * time.Minute
	}
	return &ManagedOKDRegistrar{server: s, applier: applier, signingKey: append([]byte(nil), signingKey...), WaitTimeout: waitTimeout, Poll: 2 * time.Second}, nil
}

func managedInstallOperationID(operationToken string) (string, error) {
	token := strings.TrimSpace(operationToken)
	if token == "" {
		return "", errors.New("managed install operation token is required")
	}
	if at := strings.IndexByte(token, '@'); at > 0 {
		token = token[:at]
	}
	if token == "" || strings.ContainsAny(token, "\r\n\t /\\") {
		return "", errors.New("managed install operation token is invalid")
	}
	return token, nil
}

func managedOKDEnrollmentToken(signingKey []byte, operationID, requestDigest string) string {
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte(managedOKDRegistrationAuthority))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(operationID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(requestDigest))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (r *ManagedOKDRegistrar) findOrCreateImport(ctx context.Context, req managedinstall.Request, operationID, enrollment string) (controlplane.ClusterImport, error) {
	items, err := r.server.store.ListClusterImports(ctx, req.ProjectID)
	if err != nil {
		return controlplane.ClusterImport{}, err
	}
	wantDigest := credentialDigest(enrollment)
	actor := "managed-okd-install/" + operationID
	for _, item := range items {
		if item.Name != req.ClusterName {
			continue
		}
		switch item.State {
		case controlplane.ClusterImportPendingApproval, controlplane.ClusterImportApproved, controlplane.ClusterImportClaimed:
			if strings.TrimSpace(item.RequestedBy) != actor {
				return controlplane.ClusterImport{}, fmt.Errorf("%w: cluster import name %q is owned by a different managed-install operation", controlplane.ErrDuplicateName, req.ClusterName)
			}
			if item.TokenDigest != "" && item.TokenDigest != wantDigest {
				return controlplane.ClusterImport{}, fmt.Errorf("%w: cluster import name %q is already owned by a different enrollment", controlplane.ErrDuplicateName, req.ClusterName)
			}
			return item, nil
		case controlplane.ClusterImportExpired, controlplane.ClusterImportRevoked:
			continue
		}
	}
	return r.server.store.CreateClusterImport(ctx, controlplane.ClusterImport{
		ProjectID:   req.ProjectID,
		Name:        req.ClusterName,
		DisplayName: req.ClusterName,
		TokenDigest: wantDigest,
		ExpiresAt:   time.Now().UTC().Add(2 * time.Hour),
	}, actor)
}

func (r *ManagedOKDRegistrar) RegisterManagedCluster(ctx context.Context, req managedinstall.Request, operationToken string) (map[string]any, error) {
	canonical, err := managedinstall.CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	opID, err := managedInstallOperationID(operationToken)
	if err != nil {
		return nil, err
	}
	op, err := r.server.store.GetOperation(ctx, opID)
	if err != nil {
		return nil, fmt.Errorf("load managed install operation: %w", err)
	}
	if op.Kind != managedOKDInstallOperationKind || op.ProjectID != canonical.ProjectID || op.DesiredRevision == "" {
		return nil, fmt.Errorf("%w: managed cluster registration is not bound to the active install operation", controlplane.ErrValidation)
	}
	if op.State != controlplane.OperationRunning && op.State != controlplane.OperationVerifying {
		return nil, fmt.Errorf("%w: managed install operation must be running before cluster registration", controlplane.ErrInvalidTransition)
	}
	requestDigest, err := managedinstall.DigestRequest(canonical)
	if err != nil {
		return nil, err
	}
	if requestDigest != op.DesiredRevision {
		return nil, fmt.Errorf("%w: managed install operation/request digest mismatch", controlplane.ErrConflict)
	}
	enrollment := managedOKDEnrollmentToken(r.signingKey, opID, requestDigest)
	imp, err := r.findOrCreateImport(ctx, canonical, opID, enrollment)
	if err != nil {
		return nil, err
	}
	if imp.State == controlplane.ClusterImportClaimed && imp.ClusterID != "" {
		return map[string]any{"authority": managedOKDRegistrationAuthority, "importId": imp.ID, "clusterId": imp.ClusterID, "state": imp.State, "connected": true, "idempotentReplay": true}, nil
	}
	if imp.State == controlplane.ClusterImportPendingApproval {
		imp, err = r.server.store.ApproveClusterImport(ctx, imp.ID, imp.Revision, "managed-okd-install-approved/"+opID)
		if err != nil {
			return nil, fmt.Errorf("approve nested managed cluster enrollment: %w", err)
		}
	}
	if imp.State != controlplane.ClusterImportApproved {
		return nil, fmt.Errorf("%w: managed cluster import is not approved", controlplane.ErrInvalidTransition)
	}
	manifest := renderClusterImportManifest(strings.TrimRight(r.server.fleetPublicURL, "/"), imp.ID, imp.AgentServiceAccount, enrollment, r.server.fleetAgentImage, r.server.runtimeProbeImage, r.server.publicCAPEM)
	applyEvidence, err := r.applier.ApplyRegistrationManifest(ctx, canonical, operationToken, manifest)
	if err != nil {
		return nil, fmt.Errorf("apply managed cluster registration manifest: %w", err)
	}
	poll := r.Poll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, r.WaitTimeout)
	defer cancel()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		current, getErr := r.server.store.GetClusterImport(waitCtx, imp.ID)
		if getErr != nil {
			return nil, getErr
		}
		if current.State == controlplane.ClusterImportClaimed && current.ClusterID != "" {
			return map[string]any{"authority": managedOKDRegistrationAuthority, "importId": current.ID, "clusterId": current.ClusterID, "state": current.State, "connected": true, "manifest": applyEvidence}, nil
		}
		if current.State == controlplane.ClusterImportExpired || current.State == controlplane.ClusterImportRevoked {
			return nil, fmt.Errorf("managed cluster import became %s before agent connection", current.State)
		}
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("managed cluster registration did not reach CLAIMED/CONNECTED before timeout: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}
