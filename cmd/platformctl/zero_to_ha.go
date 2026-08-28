package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"platform.4so.io/factory/internal/bootstrap"
	"platform.4so.io/factory/internal/fieldcampaign"
	"platform.4so.io/factory/internal/installation"
	"platform.4so.io/factory/internal/releaseartifact"
	"platform.4so.io/factory/internal/remotebootstrap"
)

const zeroToHAConfirmation = "HANDOFF"

func zeroToHACommand(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return
	case "handoff":
		zeroToHAHandoffCommand(args[1:])
	case "status":
		zeroToHAStatusCommand(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func zeroToHAHandoffCommand(args []string) {
	fs := flag.NewFlagSet("zero-to-ha handoff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	remoteSpec := fs.String("remote-spec", "", "remote Installer bootstrap specification")
	installerURL := fs.String("installer-url", "", "HTTPS Bootstrap Installer base URL")
	installRequest := fs.String("install-request", "", "production-standard-ha installation request JSON")
	campaignState := fs.String("campaign-state", "", "new Field Campaign state path")
	releaseArtifact := fs.String("release-artifact", "", "exact 4SO Platform Factory release ZIP bound to the appliance bundle and physical campaign")
	tokenOutput := fs.String("out-token-file", "", "new private local Bootstrap Installer token file")
	identityFile := fs.String("ha-identity-file", "", "private SSH identity used by the Installer for HA peers")
	knownHostsFile := fs.String("ha-known-hosts-file", "", "pinned OpenSSH known_hosts file for HA peers")
	caFile := fs.String("ca-file", "", "PEM CA file for a private Installer endpoint")
	confirmation := fs.String("confirmation", "", "must be exactly HANDOFF")
	timeout := fs.Duration("timeout", 10*time.Minute, "maximum handoff duration")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	required := []*string{remoteSpec, installerURL, installRequest, campaignState, releaseArtifact, tokenOutput, identityFile, knownHostsFile}
	for _, value := range required {
		if strings.TrimSpace(*value) == "" {
			usage()
			os.Exit(2)
		}
	}
	if *confirmation != zeroToHAConfirmation || *timeout <= 0 || *timeout > 30*time.Minute || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	for _, path := range []string{*campaignState, *tokenOutput} {
		if _, err := os.Stat(path); err == nil {
			fatal(fmt.Errorf("output %s already exists; refusing to overwrite durable handoff state or credentials", path))
		} else if !errors.Is(err, os.ErrNotExist) {
			fatal(err)
		}
	}

	request, err := loadInstallationRequest(*installRequest)
	if err != nil {
		fatal(err)
	}
	if err = validateZeroToHARequest(request); err != nil {
		fatal(err)
	}
	release, err := releaseartifact.Inspect(*releaseArtifact, version)
	if err != nil {
		fatal(fmt.Errorf("inspect exact release artifact: %w", err))
	}
	installerBinaryDigest, err := release.FileDigest(releaseartifact.InstallerBinaryPath)
	if err != nil {
		fatal(fmt.Errorf("inspect release installer binary digest: %w", err))
	}
	privateKey, err := readPrivateInput(*identityFile, 1<<20, "HA SSH identity")
	if err != nil {
		fatal(err)
	}
	knownHosts, err := readPrivateInput(*knownHostsFile, 4<<20, "HA known_hosts")
	if err != nil {
		fatal(err)
	}
	entries, _, err := bootstrap.ParseSSHKnownHosts(knownHosts)
	if err != nil {
		fatal(fmt.Errorf("validate HA known_hosts: %w", err))
	}
	if err = requirePeerTrust(request.Infrastructure.NodeAddresses[1:], entries); err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	tokenRaw, remoteAccess, err := remotebootstrap.FetchBootstrapToken(ctx, *remoteSpec, remotebootstrap.Options{})
	if err != nil {
		fatal(err)
	}
	token := strings.TrimSpace(string(tokenRaw))
	base, err := validateAPIURL(*installerURL)
	if err != nil {
		fatal(err)
	}
	client, err := closureHTTPClient(*caFile)
	if err != nil {
		fatal(err)
	}
	connection := fieldCampaignConnection{base: base, client: client, token: token}
	accessStatus, err := fetchInstallerAccessStatus(client, base, token)
	if err != nil {
		fatal(fmt.Errorf("verify Installer access handoff: %w", err))
	}
	if (!accessStatus.Transport.TransportProtected && !accessStatus.Transport.LoopbackOnly) || accessStatus.Transport.InsecureOverride {
		fatal(errors.New("zero-to-ha handoff requires protected TLS or loopback-only Installer transport without insecure override"))
	}
	if accessStatus.Token.Fingerprint != remoteAccess.TokenFingerprint {
		fatal(errors.New("remote bootstrap token fingerprint does not match the live Installer access authority"))
	}

	trust, campaign, err := syncAndPrepareZeroToHA(connection, request, release.Digest, installerBinaryDigest, privateKey, knownHosts, time.Now().UTC())
	if err != nil {
		fatal(err)
	}
	pendingToken, absoluteToken, err := stagePrivateToken(*tokenOutput, tokenRaw)
	if err != nil {
		fatal(err)
	}
	if err = commitPrivateToken(pendingToken, absoluteToken); err != nil {
		fatal(err)
	}
	if err = fieldcampaign.Save(*campaignState, campaign); err != nil {
		fatal(fmt.Errorf("save Field Campaign after access handoff (token preserved at %s): %w", absoluteToken, err))
	}
	printJSON(map[string]any{
		"handoff":         true,
		"remoteAccess":    remoteAccess,
		"installerAccess": accessStatus,
		"haTrust":         trust,
		"tokenFile":       absoluteToken,
		"campaignState":   *campaignState,
		"campaign":        campaign,
		"nextAction":      "review the prepared campaign, then run field-campaign start with --confirmation INSTALL",
	})
}

func syncAndPrepareZeroToHA(connection fieldCampaignConnection, request installation.InstallRequest, releaseArtifactDigest, installerBinaryDigest string, privateKey, knownHosts []byte, now time.Time) (bootstrap.SSHTrustStatus, fieldcampaign.Campaign, error) {
	var storedKey struct {
		Stored        bool   `json:"stored"`
		CredentialRef string `json:"credentialRef"`
	}
	if err := installerRequestJSON(connection, "POST", "/api/v1/secrets/ssh-private-key", map[string]string{"privateKey": strings.TrimSpace(string(privateKey))}, &storedKey); err != nil {
		return bootstrap.SSHTrustStatus{}, fieldcampaign.Campaign{}, fmt.Errorf("store HA SSH identity: %w", err)
	}
	if !storedKey.Stored || storedKey.CredentialRef != "secret://installer/ssh-private-key" {
		return bootstrap.SSHTrustStatus{}, fieldcampaign.Campaign{}, errors.New("Installer did not confirm the HA SSH identity authority")
	}
	var trust bootstrap.SSHTrustStatus
	if err := installerRequestJSON(connection, "POST", "/api/v1/secrets/ssh-known-hosts", map[string]string{"knownHosts": strings.TrimSpace(string(knownHosts))}, &trust); err != nil {
		return bootstrap.SSHTrustStatus{}, fieldcampaign.Campaign{}, fmt.Errorf("store pinned HA host trust: %w", err)
	}
	if !trust.PrivateKeyStored || !trust.KnownHostsStored {
		return trust, fieldcampaign.Campaign{}, errors.New("Installer HA SSH trust authority is incomplete after handoff")
	}
	if err := requirePeerTrust(request.Infrastructure.NodeAddresses[1:], trust.Entries); err != nil {
		return trust, fieldcampaign.Campaign{}, fmt.Errorf("Installer HA trust status: %w", err)
	}
	campaign, err := prepareFieldCampaign(connection, request, releaseArtifactDigest, installerBinaryDigest, now)
	if err != nil {
		return trust, fieldcampaign.Campaign{}, fmt.Errorf("prepare zero-to-ha Field Campaign: %w", err)
	}
	return trust, campaign, nil
}

func zeroToHAStatusCommand(args []string) {
	fs := flag.NewFlagSet("zero-to-ha status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("campaign-state", "", "Field Campaign state path created by zero-to-ha handoff")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(*statePath) == "" || fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	campaign, err := fieldcampaign.Load(*statePath)
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"campaign": campaign, "nextAction": zeroToHANextAction(campaign)})
}

func validateZeroToHARequest(request installation.InstallRequest) error {
	if request.ProfileID != "production-standard-ha" {
		return errors.New("zero-to-ha handoff requires profile production-standard-ha")
	}
	if request.Infrastructure.ExistingCluster {
		return errors.New("zero-to-ha handoff is for raw Linux hosts, not an existing Kubernetes cluster")
	}
	if len(request.Infrastructure.NodeAddresses) != 3 {
		return fmt.Errorf("zero-to-ha handoff requires exactly three management nodes, got %d", len(request.Infrastructure.NodeAddresses))
	}
	if strings.TrimSpace(request.Infrastructure.CredentialRef) != "secret://installer/ssh-private-key" {
		return errors.New("zero-to-ha handoff requires credentialRef secret://installer/ssh-private-key")
	}
	return nil
}

func readPrivateInput(path string, limit int64, label string) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must be a regular non-symlink file", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s permissions must not grant group/world access", label)
	}
	if info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s size is outside the allowed range", label)
	}
	return os.ReadFile(absolute)
}

func requirePeerTrust(peers []string, entries []bootstrap.SSHHostTrustEntry) error {
	trusted := map[string]bool{}
	for _, entry := range entries {
		trusted[canonicalHost(entry.Host)] = true
	}
	for _, peer := range peers {
		if !trusted[canonicalHost(peer)] {
			return fmt.Errorf("HA peer %s has no pinned host key", peer)
		}
	}
	return nil
}

func canonicalHost(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	value = strings.Trim(value, "[]")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return strings.ToLower(value)
}

func zeroToHANextAction(campaign fieldcampaign.Campaign) string {
	switch campaign.State {
	case fieldcampaign.StatePrepared:
		return "run field-campaign start with --confirmation INSTALL"
	case fieldcampaign.StateStartRequested, fieldcampaign.StateRunning:
		return "run field-campaign watch"
	case fieldcampaign.StateFailed:
		return "run field-campaign diagnose, fix the owning cause, then resume with --confirmation RESUME"
	case fieldcampaign.StateSucceeded:
		return "collect independently verified field evidence"
	default:
		return "inspect campaign state"
	}
}
