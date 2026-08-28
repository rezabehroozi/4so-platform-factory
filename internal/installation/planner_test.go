package installation

import (
	"strings"
	"testing"
)

func validRequest() InstallRequest {
	return InstallRequest{
		ProfileID: "production-standard-ha", Connectivity: ConnectivityConnected,
		Infrastructure: InfrastructureSpec{Provider: "existing-hosts", NodeAddresses: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, CredentialRef: "secret://infra/admin"},
		Network:        NetworkSpec{PublicEndpoint: "https://platform.example.test", DNSZone: "example.test", TLSMode: "managed-acme"},
		Services: ServicesSpec{
			Git: GitSpec{}, Registry: ServiceSpec{}, Database: ServiceSpec{},
			ObjectStorage: ServiceSpec{Mode: ServiceModeExternal, Provider: "s3-compatible", URL: "https://s3.example.test", CredentialRef: "secret://storage/backup"},
			Identity:      IdentitySpec{AdminEmail: "admin@example.test"},
		},
		AcceptRisk: true,
	}
}

func TestManagedServicesAreDefaultsAndRequireNoCustomerInstall(t *testing.T) {
	plan, err := CreatePlan(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if plan.EffectiveServices.Git.Mode != ServiceModeManaged || plan.EffectiveServices.Git.Provider != "forgejo" {
		t.Fatalf("git=%+v", plan.EffectiveServices.Git)
	}
	if plan.EffectiveServices.Registry.Provider != "zot" {
		t.Fatalf("registry=%+v", plan.EffectiveServices.Registry)
	}
	for _, d := range plan.Dependencies {
		if d.CustomerInstallRequired {
			t.Fatalf("dependency unexpectedly requires customer install: %+v", d)
		}
	}
	if plan.Executable || plan.Status != "planning-only" {
		t.Fatalf("unexpected status %+v", plan)
	}
	if plan.AuthorityGate != "blocked-pending-postgresql-runtime" {
		t.Fatalf("gate=%s", plan.AuthorityGate)
	}
}

func TestExternalGitRequiresSecretReference(t *testing.T) {
	r := validRequest()
	r.Services.Git = GitSpec{ServiceSpec: ServiceSpec{Mode: ServiceModeExternal, Provider: "gitlab", URL: "https://git.example.test"}, Organization: "platform", Repository: "desired-state"}
	plan, err := CreatePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "Git external mode requires a secret reference; plaintext credentials are forbidden")
}

func TestBootstrapPlanFailsClosedForExternalServicesWithoutRuntimeAdapters(t *testing.T) {
	r := validRequest()
	r.Infrastructure.StorageClass = "replicated"
	r.Services.ObjectStorage.Bucket = "backups"
	r.Services.Git = GitSpec{ServiceSpec: ServiceSpec{Mode: ServiceModeExternal, Provider: "gitlab", URL: "https://git.example.test", CredentialRef: "secret://git/admin"}, Organization: "platform", Repository: "desired-state"}
	r.Services.Registry = ServiceSpec{Mode: ServiceModeExternal, Provider: "harbor", URL: "https://registry.example.test", CredentialRef: "secret://registry/admin"}
	r.Services.Database = ServiceSpec{Mode: ServiceModeExternal, Provider: "postgresql", URL: "https://database.example.test", CredentialRef: "secret://database/admin"}
	r.Services.Identity = IdentitySpec{ServiceSpec: ServiceSpec{Mode: ServiceModeExternal, Provider: "oidc", URL: "https://identity.example.test", CredentialRef: "secret://identity/admin"}, IssuerURL: "https://identity.example.test", ClientID: "platform"}

	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable || plan.Status != "planning-only" {
		t.Fatalf("external adapter plan must not execute through managed bootstrap: status=%s blockers=%v", plan.Status, plan.Blockers)
	}
	for _, expected := range []string{
		"Git external mode is not executable by the appliance bootstrap runtime; use managed-internal mode",
		"registry external mode is not executable by the appliance bootstrap runtime; use managed-internal mode",
		"database external mode is not executable by the appliance bootstrap runtime; use managed-internal mode",
		"identity external mode is not executable by the appliance bootstrap runtime; use managed-internal mode",
	} {
		assertBlocker(t, plan, expected)
	}
}

func TestProductionBootstrapRequiresUniqueManagementNodes(t *testing.T) {
	r := validRequest()
	r.Infrastructure.NodeAddresses = []string{"10.0.0.1", "10.0.0.2", "10.0.0.2"}
	r.Infrastructure.CredentialRef = "secret://installer/ssh-private-key"
	r.Infrastructure.StorageClass = "replicated-rwx"
	r.Network.TLSMode = "managed-private-ca"
	r.Services.ObjectStorage.Bucket = "backups"
	r.Services.ObjectStorage.CredentialRef = "external-secret://platform-system/s3-credentials"
	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "management node addresses must be unique")
}

func TestProductionProfileRequiresThreeNodes(t *testing.T) {
	r := validRequest()
	r.Infrastructure.NodeAddresses = []string{"10.0.0.1"}
	plan, err := CreatePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "profile production-standard-ha requires at least 3 reachable nodes")
}

func TestProductionRejectsLocalEvidenceStorage(t *testing.T) {
	r := validRequest()
	r.Services.ObjectStorage = ServiceSpec{}
	plan, err := CreatePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "production profiles require a certified durable S3-compatible object storage target")
}

func TestExistingClusterStillHasManagementAdmissionStep(t *testing.T) {
	r := validRequest()
	r.ProfileID = "integrated-enterprise"
	r.Infrastructure = InfrastructureSpec{Provider: "existing-kubernetes", ExistingCluster: true, CredentialRef: "secret://cluster/enrollment"}
	plan, err := CreatePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, step := range plan.Steps {
		if step.Key == "management-kubernetes" && step.Title == "Validate and admit the existing management Kubernetes cluster" {
			found = true
		}
	}
	if !found {
		t.Fatal("existing cluster admission step missing")
	}
}

func assertBlocker(t *testing.T, plan InstallationPlan, expected string) {
	t.Helper()
	for _, blocker := range plan.Blockers {
		if blocker == expected {
			return
		}
	}
	t.Fatalf("missing blocker %q in %v", expected, plan.Blockers)
}

func TestEvaluationBootstrapPlanBecomesExecutableWithLocalJournal(t *testing.T) {
	request := validRequest()
	request.ProfileID = "evaluation-single-node"
	request.Network.TLSMode = "bootstrap-self-signed"
	request.Infrastructure.NodeAddresses = []string{"127.0.0.1"}
	request.Services.ObjectStorage = ServiceSpec{}
	plan, err := CreateBootstrapPlan(request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable || plan.Status != "execution-ready" {
		t.Fatalf("bootstrap plan is not executable: status=%s blockers=%v", plan.Status, plan.Blockers)
	}
	if plan.AuthorityGate != "bootstrap-local-journal" {
		t.Fatalf("authority gate=%s", plan.AuthorityGate)
	}
}

func TestBootstrapPlanExposesNormalizedEffectiveRequest(t *testing.T) {
	r := validRequest()
	r.ProfileID = "  production-standard-ha  "
	r.Infrastructure.Provider = "  existing-hosts  "
	r.Infrastructure.NodeAddresses = []string{" 10.0.0.1 ", "10.0.0.2 ", " 10.0.0.3"}
	r.Infrastructure.CredentialRef = " secret://installer/ssh-private-key "
	r.Infrastructure.StorageClass = " replicated-rwx "
	r.Network.PublicEndpoint = " https://platform.example.test "
	r.Network.DNSZone = " example.test. "
	r.Network.TLSMode = " managed-private-ca "
	r.Services.ObjectStorage.Mode = ServiceModeExternal
	r.Services.ObjectStorage.Provider = " s3-compatible "
	r.Services.ObjectStorage.URL = " https://s3.example.test "
	r.Services.ObjectStorage.Bucket = " platform-backups "
	r.Services.ObjectStorage.Prefix = " factory "
	r.Services.ObjectStorage.CredentialRef = " external-secret://platform-system/s3-credentials "
	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable {
		t.Fatalf("normalized plan blockers=%v", plan.Blockers)
	}
	effective := plan.EffectiveRequest
	if effective.ProfileID != "production-standard-ha" || effective.Infrastructure.Provider != "existing-hosts" || effective.Infrastructure.NodeAddresses[0] != "10.0.0.1" || effective.Infrastructure.CredentialRef != "secret://installer/ssh-private-key" || effective.Infrastructure.StorageClass != "replicated-rwx" || effective.Network.PublicEndpoint != "https://platform.example.test" || effective.Network.DNSZone != "example.test" || effective.Network.TLSMode != "managed-private-ca" {
		t.Fatalf("request was not normalized consistently: %+v", effective)
	}
}

func TestBootstrapPlannerRequiresValidDNSZone(t *testing.T) {
	for _, zone := range []string{"", "Example.TEST", "bad..example.test", "bad_zone.example.test", "-bad.example.test"} {
		r := validRequest()
		r.Network.TLSMode = "managed-private-ca"
		r.Network.DNSZone = zone
		r.Infrastructure.CredentialRef = "secret://installer/ssh-private-key"
		r.Infrastructure.StorageClass = "replicated-rwx"
		r.Services.ObjectStorage.CredentialRef = "external-secret://platform-system/s3-credentials"
		plan, err := CreateBootstrapPlan(r)
		if err != nil {
			t.Fatalf("dnsZone %q: %v", zone, err)
		}
		assertBlocker(t, plan, "appliance bootstrap requires a valid lowercase DNS zone")
	}
}

func TestProductionBootstrapRejectsInvalidStorageClassName(t *testing.T) {
	r := validRequest()
	r.Network.TLSMode = "managed-private-ca"
	r.Infrastructure.CredentialRef = "secret://installer/ssh-private-key"
	r.Infrastructure.StorageClass = "Bad_Storage"
	r.Services.ObjectStorage.CredentialRef = "external-secret://platform-system/s3-credentials"
	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "production-standard-ha storageClass must be a valid lowercase DNS subdomain")
}

func TestBootstrapPlannerRejectsKubernetesSecretNamesWithOversizedLabels(t *testing.T) {
	r := validRequest()
	r.Infrastructure.CredentialRef = "secret://installer/ssh-private-key"
	r.Infrastructure.StorageClass = "replicated-rwx"
	r.Network.TLSMode = "managed-private-ca"
	r.Services.ObjectStorage.Bucket = "backups"
	r.Services.ObjectStorage.CredentialRef = "external-secret://platform-system/" + strings.Repeat("a", 64)
	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "production-standard-ha appliance bootstrap requires object storage credentialRef external-secret://platform-system/<valid-kubernetes-secret>")
}

func TestPlannerRejectsUnknownTLSMode(t *testing.T) {
	r := validRequest()
	r.Network.TLSMode = "magic-tls"
	plan, err := CreatePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "TLS mode is not supported")
}

func TestBootstrapPlanBlocksTLSModesWithoutExecutors(t *testing.T) {
	for _, mode := range []string{"managed-acme", "external-certificate"} {
		t.Run(mode, func(t *testing.T) {
			r := validRequest()
			r.Infrastructure.StorageClass = "replicated"
			r.Services.ObjectStorage.Bucket = "backups"
			r.Network.TLSMode = mode
			if mode == "external-certificate" {
				r.Network.CertificateRef = "secret://tls/platform"
			}
			plan, err := CreateBootstrapPlan(r)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Executable {
				t.Fatalf("TLS mode %s must not be executable without a runtime adapter", mode)
			}
			assertBlocker(t, plan, mode+" TLS mode is not executable by the appliance bootstrap runtime; use managed-private-ca or bootstrap-self-signed as allowed by the selected profile")
		})
	}
}

func TestPlannerRejectsUnknownInfrastructureProvider(t *testing.T) {
	r := validRequest()
	r.Infrastructure.Provider = "decorative-cloud"
	plan, err := CreatePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "infrastructure provider is not supported")
}

func TestApplianceProfilesRequireExistingHosts(t *testing.T) {
	r := validRequest()
	r.Infrastructure.Provider = "existing-kubernetes"
	r.Infrastructure.ExistingCluster = true
	r.Infrastructure.CredentialRef = "secret://cluster/enrollment"
	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "production-standard-ha requires existing-hosts infrastructure")
}

func TestProductionBootstrapPlanMatchesSSHAndS3RuntimeCredentialContracts(t *testing.T) {
	r := validRequest()
	r.Infrastructure.StorageClass = "replicated"
	r.Network.TLSMode = "managed-private-ca"
	r.Services.ObjectStorage.Bucket = "backups"
	r.Infrastructure.CredentialRef = "secret://infra/admin"
	r.Services.ObjectStorage.CredentialRef = "secret://storage/backup"
	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "production-standard-ha appliance bootstrap requires credentialRef secret://installer/ssh-private-key")
	assertBlocker(t, plan, "production-standard-ha appliance bootstrap requires object storage credentialRef external-secret://platform-system/<valid-kubernetes-secret>")
}

func TestProductionBootstrapPlanAcceptsImplementedCredentialAndTLSContracts(t *testing.T) {
	r := validRequest()
	r.Infrastructure.StorageClass = "replicated"
	r.Infrastructure.CredentialRef = "secret://installer/ssh-private-key"
	r.Network.TLSMode = "managed-private-ca"
	r.Services.ObjectStorage.Bucket = "backups"
	r.Services.ObjectStorage.CredentialRef = "external-secret://platform-system/s3-credentials"
	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Executable {
		t.Fatalf("implemented production bootstrap contract unexpectedly blocked: %v", plan.Blockers)
	}
}

func TestPlannerRejectsManagedProviderRuntimeMismatch(t *testing.T) {
	r := validRequest()
	r.Services.Git.Provider = "gitlab"
	r.Services.Registry.Provider = "harbor"
	r.Services.Database.Provider = "postgresql"
	r.Services.Identity.Provider = "external-oidc"
	plan, err := CreatePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Git managed mode requires provider forgejo",
		"registry managed mode requires provider zot",
		"database managed mode requires provider cloudnative-pg",
		"identity managed mode requires provider keycloak",
	} {
		assertBlocker(t, plan, expected)
	}
}

func TestPlannerRejectsUnknownExternalProvider(t *testing.T) {
	r := validRequest()
	r.Services.ObjectStorage.Provider = "decorative-s3"
	plan, err := CreatePlan(r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocker(t, plan, "object storage external provider is not supported")
}

func TestBootstrapCapabilityCatalogContainsNoDeadEndProfilesOrAdapters(t *testing.T) {
	profiles := BootstrapProfiles()
	if len(profiles) != 2 {
		t.Fatalf("bootstrap profiles=%+v", profiles)
	}
	for _, profile := range profiles {
		if profile.ID == "integrated-enterprise" {
			t.Fatal("planning-only integrated-enterprise leaked into executable installer catalog")
		}
	}
	integrations := BootstrapIntegrations()
	for _, kind := range []string{"git", "registry", "database", "identity"} {
		for _, item := range integrations[kind] {
			if item["mode"] == ServiceModeExternal {
				t.Fatalf("planning-only external %s adapter leaked into executable installer catalog: %+v", kind, item)
			}
		}
	}
	foundExternalS3 := false
	for _, item := range integrations["objectStorage"] {
		if item["mode"] == ServiceModeExternal && item["id"] == "external-s3-compatible" {
			foundExternalS3 = true
		}
	}
	if !foundExternalS3 {
		t.Fatal("executable external S3 integration is missing from bootstrap catalog")
	}
}

func TestBootstrapPlanDoesNotClaimPostgreSQLRuntimeBeforeDatabaseExists(t *testing.T) {
	r := validRequest()
	r.ProfileID = "evaluation-single-node"
	r.Network.TLSMode = "bootstrap-self-signed"
	r.Infrastructure.NodeAddresses = []string{"127.0.0.1"}
	r.Services.ObjectStorage = ServiceSpec{}
	plan, err := CreateBootstrapPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	foundBootstrapAuthority := false
	for _, step := range plan.Steps {
		if step.Key == "authority-runtime-gate" {
			t.Fatalf("bootstrap plan falsely advertises pre-database PostgreSQL runtime certification: %+v", step)
		}
		if step.Key == "bootstrap-authority-gate" {
			foundBootstrapAuthority = true
			if step.Executor != "bootstrap-local-journal" || !strings.Contains(strings.ToLower(step.Title), "bootstrap journal") {
				t.Fatalf("bootstrap authority step does not describe the real execution authority: %+v", step)
			}
		}
		if step.Key == "management-kubernetes" {
			if len(step.DependsOn) != 1 || step.DependsOn[0] != "bootstrap-authority-gate" {
				t.Fatalf("management Kubernetes dependency does not use bootstrap authority: %+v", step.DependsOn)
			}
		}
	}
	if !foundBootstrapAuthority {
		t.Fatal("bootstrap authority gate missing from executable appliance plan")
	}
}
