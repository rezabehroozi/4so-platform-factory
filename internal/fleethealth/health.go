package fleethealth

import (
	"fmt"
	"platform.4so.io/factory/internal/controlplane"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	PolicySource     = "https://kubernetes.io/releases/"
	PolicyCapturedAt = "2026-08-07"
)

type KubernetesSupport struct {
	Minor              string    `json:"minor"`
	LatestPatch        string    `json:"latestPatch"`
	MaintenanceStarts  time.Time `json:"maintenanceStarts"`
	EndOfLife          time.Time `json:"endOfLife"`
	Status             string    `json:"status"`
	DaysUntilEndOfLife int       `json:"daysUntilEndOfLife"`
	Source             string    `json:"source"`
	PolicyCapturedAt   string    `json:"policyCapturedAt"`
}

type CertificateHealth struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"notAfter"`
	State       string    `json:"state"`
	DaysLeft    int       `json:"daysLeft"`
}

type ClusterHealth struct {
	ClusterID           string                         `json:"clusterId"`
	ProjectID           string                         `json:"projectId"`
	Name                string                         `json:"name"`
	DisplayName         string                         `json:"displayName"`
	Health              string                         `json:"health"`
	ConnectionState     string                         `json:"connectionState"`
	Online              bool                           `json:"online"`
	InventoryState      string                         `json:"inventoryState"`
	LastSeenAt          *time.Time                     `json:"lastSeenAt,omitempty"`
	InventoryObservedAt *time.Time                     `json:"inventoryObservedAt,omitempty"`
	Distribution        string                         `json:"distribution,omitempty"`
	KubernetesVersion   string                         `json:"kubernetesVersion,omitempty"`
	KubernetesSupport   KubernetesSupport              `json:"kubernetesSupport"`
	NodeCount           int                            `json:"nodeCount"`
	ReadyNodes          int                            `json:"readyNodes"`
	StorageClassCount   int                            `json:"storageClassCount"`
	DefaultStorageClass string                         `json:"defaultStorageClass,omitempty"`
	StorageProvisioners []string                       `json:"storageProvisioners,omitempty"`
	Capacity            controlplane.ClusterCapacity   `json:"capacity"`
	Networking          controlplane.ClusterNetworking `json:"networking"`
	Certificates        []CertificateHealth            `json:"certificates,omitempty"`
	CapabilityGaps      []string                       `json:"capabilityGaps,omitempty"`
	Warnings            []string                       `json:"warnings,omitempty"`
}

var minorRE = regexp.MustCompile(`(?:^|[^0-9])1\.([0-9]+)(?:\.|$|[^0-9])`)

type policyEntry struct {
	minor       string
	latestPatch string
	maintenance time.Time
	eol         time.Time
}

func date(value string) time.Time {
	v, _ := time.Parse("2006-01-02", value)
	return v.UTC()
}

// Snapshot intentionally lives in the artifact so disconnected installations
// do not need runtime Internet access. The release process updates it from the
// Kubernetes release support page.
var policy = []policyEntry{
	{minor: "1.36", latestPatch: "1.36.2", maintenance: date("2027-04-28"), eol: date("2027-06-28")},
	{minor: "1.35", latestPatch: "1.35.6", maintenance: date("2026-12-28"), eol: date("2027-02-28")},
	{minor: "1.34", latestPatch: "1.34.9", maintenance: date("2026-08-27"), eol: date("2026-10-27")},
	{minor: "1.33", latestPatch: "1.33.13", maintenance: date("2026-04-28"), eol: date("2026-06-28")},
	{minor: "1.32", latestPatch: "1.32.13", maintenance: date("2025-12-28"), eol: date("2026-02-28")},
}

func SupportFor(version string, now time.Time) KubernetesSupport {
	result := KubernetesSupport{Status: "UNKNOWN", Source: PolicySource, PolicyCapturedAt: PolicyCapturedAt}
	match := minorRE.FindStringSubmatch(strings.TrimSpace(version))
	if len(match) != 2 {
		return result
	}
	minor := "1." + match[1]
	result.Minor = minor
	for _, entry := range policy {
		if entry.minor != minor {
			continue
		}
		result.LatestPatch = entry.latestPatch
		result.MaintenanceStarts = entry.maintenance
		result.EndOfLife = entry.eol
		days := int(entry.eol.Sub(now.UTC()).Hours() / 24)
		result.DaysUntilEndOfLife = days
		switch {
		case !now.UTC().Before(entry.eol):
			result.Status = "EOL"
		case days <= 90:
			result.Status = "EOL_SOON"
		case !now.UTC().Before(entry.maintenance):
			result.Status = "MAINTENANCE"
		default:
			result.Status = "SUPPORTED"
		}
		return result
	}
	if n, err := strconv.Atoi(match[1]); err == nil && n < 32 {
		result.Status = "EOL"
	}
	return result
}

func Evaluate(cluster controlplane.ManagedCluster, inventory controlplane.ClusterInventory, agentCertificates []controlplane.AgentCertificate, now time.Time) ClusterHealth {
	now = now.UTC()
	out := ClusterHealth{ClusterID: cluster.ID, ProjectID: cluster.ProjectID, Name: cluster.Name, DisplayName: cluster.DisplayName, ConnectionState: cluster.ConnectionState, LastSeenAt: cluster.LastSeenAt, Distribution: cluster.Distribution, KubernetesVersion: cluster.KubernetesVersion, Capacity: inventory.Capacity, Networking: inventory.Networking}
	out.Online = cluster.ConnectionState != "REVOKED" && cluster.LastSeenAt != nil && now.Sub(cluster.LastSeenAt.UTC()) <= 3*time.Minute
	if inventory.ObservedAt.IsZero() {
		out.InventoryState = "MISSING"
	} else {
		observed := inventory.ObservedAt.UTC()
		out.InventoryObservedAt = &observed
		if now.Sub(observed) > 10*time.Minute {
			out.InventoryState = "STALE"
		} else {
			out.InventoryState = "FRESH"
		}
		if out.Distribution == "" {
			out.Distribution = inventory.Distribution
		}
		if out.KubernetesVersion == "" {
			out.KubernetesVersion = inventory.KubernetesVersion
		}
	}
	out.KubernetesSupport = SupportFor(out.KubernetesVersion, now)
	out.NodeCount = len(inventory.Nodes)
	for _, node := range inventory.Nodes {
		if node.Ready {
			out.ReadyNodes++
		}
	}
	out.StorageClassCount = len(inventory.StorageClasses)
	provisioners := map[string]bool{}
	for _, class := range inventory.StorageClasses {
		if class.Default && out.DefaultStorageClass == "" {
			out.DefaultStorageClass = class.Name
		}
		if class.Provisioner != "" {
			provisioners[class.Provisioner] = true
		}
	}
	for provisioner := range provisioners {
		out.StorageProvisioners = append(out.StorageProvisioners, provisioner)
	}
	sort.Strings(out.StorageProvisioners)

	for _, observed := range inventory.Certificates {
		out.Certificates = append(out.Certificates, certificateStatus(observed.Name, observed.Fingerprint, observed.NotAfter, now, "ACTIVE"))
	}
	for _, certificate := range agentCertificates {
		if certificate.State != controlplane.AgentCertificateActive {
			continue
		}
		out.Certificates = append(out.Certificates, certificateStatus("agent-mtls", certificate.Fingerprint, certificate.NotAfter, now, string(certificate.State)))
	}
	sort.Slice(out.Certificates, func(i, j int) bool {
		return out.Certificates[i].Name+out.Certificates[i].Fingerprint < out.Certificates[j].Name+out.Certificates[j].Fingerprint
	})

	gaps := map[string]bool{}
	if len(inventory.StorageClasses) == 0 {
		gaps["storage-class-inventory"] = true
	}
	if inventory.Networking.CNI == "" {
		gaps["cni-detection"] = true
	}
	if len(inventory.Networking.IngressControllers) == 0 {
		gaps["ingress-detection"] = true
	}
	if len(agentCertificates) == 0 {
		gaps["agent-mtls-certificate"] = true
	}
	for gap := range gaps {
		out.CapabilityGaps = append(out.CapabilityGaps, gap)
	}
	sort.Strings(out.CapabilityGaps)

	severity := 0
	addWarning := func(level int, message string) {
		if level > severity {
			severity = level
		}
		out.Warnings = append(out.Warnings, message)
	}
	if cluster.ConnectionState == "REVOKED" {
		addWarning(4, "managed-cluster access is revoked")
	}
	if !out.Online && cluster.ConnectionState != "REVOKED" {
		addWarning(2, "agent heartbeat is offline or older than three minutes")
	}
	if out.InventoryState == "STALE" {
		addWarning(3, "inventory is older than ten minutes")
	} else if out.InventoryState == "MISSING" {
		addWarning(3, "no inventory has been reported")
	}
	if out.NodeCount > 0 && out.ReadyNodes < out.NodeCount {
		addWarning(3, fmt.Sprintf("%d of %d nodes are Ready", out.ReadyNodes, out.NodeCount))
	}
	switch out.KubernetesSupport.Status {
	case "EOL":
		addWarning(4, "Kubernetes minor release is end-of-life in the bundled support policy")
	case "EOL_SOON":
		addWarning(2, fmt.Sprintf("Kubernetes minor release reaches end-of-life in %d days", out.KubernetesSupport.DaysUntilEndOfLife))
	case "UNKNOWN":
		addWarning(2, "Kubernetes minor release is not present in the bundled support policy")
	}
	for _, certificate := range out.Certificates {
		switch certificate.State {
		case "EXPIRED":
			addWarning(4, certificate.Name+" certificate is expired")
		case "EXPIRING":
			addWarning(2, fmt.Sprintf("%s certificate expires in %d days", certificate.Name, certificate.DaysLeft))
		}
	}
	if len(out.CapabilityGaps) > 0 {
		addWarning(1, "inventory has capability gaps: "+strings.Join(out.CapabilityGaps, ", "))
	}
	sort.Strings(out.Warnings)
	switch severity {
	case 4:
		out.Health = "CRITICAL"
	case 3:
		out.Health = "STALE"
	case 2, 1:
		out.Health = "WARNING"
	default:
		out.Health = "HEALTHY"
	}
	return out
}

func certificateStatus(name, fingerprint string, notAfter, now time.Time, baseState string) CertificateHealth {
	out := CertificateHealth{Name: name, Fingerprint: fingerprint, NotAfter: notAfter.UTC(), State: baseState}
	if notAfter.IsZero() {
		out.State = "UNKNOWN"
		return out
	}
	out.DaysLeft = int(notAfter.UTC().Sub(now.UTC()).Hours() / 24)
	if !now.UTC().Before(notAfter.UTC()) {
		out.State = "EXPIRED"
	} else if out.DaysLeft <= 30 {
		out.State = "EXPIRING"
	}
	return out
}

type PolicySnapshot struct {
	Source     string              `json:"source"`
	CapturedAt string              `json:"capturedAt"`
	Releases   []KubernetesSupport `json:"releases"`
}

func SnapshotPolicy(now time.Time) PolicySnapshot {
	out := PolicySnapshot{Source: PolicySource, CapturedAt: PolicyCapturedAt}
	for _, entry := range policy {
		out.Releases = append(out.Releases, SupportFor("v"+entry.minor+".0", now))
	}
	return out
}
