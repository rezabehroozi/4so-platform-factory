package controlplane

import "testing"

func TestNotificationProviderContractsAreExplicitAndFailClosed(t *testing.T) {
	contracts := NotificationProviderContracts()
	if len(contracts) != 2 {
		t.Fatalf("contracts=%d want=2", len(contracts))
	}
	byKind := map[NotificationDestinationKind]NotificationProviderContract{}
	for _, contract := range contracts {
		byKind[contract.Kind] = contract
	}
	console, ok := byKind[NotificationDestinationConsole]
	if !ok || console.Transport != "in-product" || console.ExternalEgress || console.SupportsAuthorization || console.SupportsHMAC {
		t.Fatalf("console contract=%+v", console)
	}
	webhook, ok := byKind[NotificationDestinationWebhook]
	if !ok || webhook.Transport != "http-webhook" || !webhook.ExternalEgress || !webhook.SupportsAuthorization || !webhook.SupportsHMAC || webhook.RawSecretMaterialAllowed {
		t.Fatalf("webhook contract=%+v", webhook)
	}
}

func TestNotificationPreferenceDigestCanonicalizesRoutePolicy(t *testing.T) {
	a := NotificationRoute{OrganizationID: " org_1 ", ProjectID: " prj_1 ", Name: " Ops-Alerts ", Enabled: true, EventPatterns: []string{"upgrade.*", " operation.failed ", "upgrade.*"}, MinimumSeverity: NotificationWarning, DestinationIDs: []string{"ntd_b", "ntd_a", "ntd_b"}}
	b := NotificationRoute{OrganizationID: "org_1", ProjectID: "prj_1", Name: "ops-alerts", Enabled: true, EventPatterns: []string{"operation.failed", "upgrade.*"}, MinimumSeverity: NotificationWarning, DestinationIDs: []string{"ntd_a", "ntd_b"}}
	da, err := NotificationPreferenceDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := NotificationPreferenceDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da == "" || da != db {
		t.Fatalf("canonical digest mismatch a=%q b=%q", da, db)
	}
	b.MinimumSeverity = NotificationCritical
	dc, err := NotificationPreferenceDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if dc == da {
		t.Fatal("material policy change did not change digest")
	}
}
