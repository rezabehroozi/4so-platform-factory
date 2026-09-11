package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	NotificationProviderAdapterAuthority  = "NOTIFICATION_PROVIDER_ADAPTER_CONTRACT_V1"
	NotificationPreferenceDigestAuthority = "NOTIFICATION_PREFERENCE_DIGEST_POLICY_V1"
)

type NotificationProviderContract struct {
	Authority                 string                      `json:"authority"`
	Kind                      NotificationDestinationKind `json:"kind"`
	Transport                 string                      `json:"transport"`
	ExternalEgress            bool                        `json:"externalEgress"`
	SupportsAuthorization     bool                        `json:"supportsAuthorization"`
	SupportsHMAC              bool                        `json:"supportsHmac"`
	RawSecretMaterialAllowed  bool                        `json:"rawSecretMaterialAllowed"`
	OrganizationScopedSecrets bool                        `json:"organizationScopedSecrets"`
	DeliveryDurable           bool                        `json:"deliveryDurable"`
	RetryAndDeadLetter        bool                        `json:"retryAndDeadLetter"`
}

func NotificationProviderContracts() []NotificationProviderContract {
	return []NotificationProviderContract{
		{Authority: NotificationProviderAdapterAuthority, Kind: NotificationDestinationConsole, Transport: "in-product", ExternalEgress: false, SupportsAuthorization: false, SupportsHMAC: false, RawSecretMaterialAllowed: false, OrganizationScopedSecrets: false, DeliveryDurable: true, RetryAndDeadLetter: true},
		{Authority: NotificationProviderAdapterAuthority, Kind: NotificationDestinationWebhook, Transport: "http-webhook", ExternalEgress: true, SupportsAuthorization: true, SupportsHMAC: true, RawSecretMaterialAllowed: false, OrganizationScopedSecrets: true, DeliveryDurable: true, RetryAndDeadLetter: true},
	}
}

type notificationPreferenceDigestDocument struct {
	Authority       string               `json:"authority"`
	OrganizationID  string               `json:"organizationId"`
	ProjectID       string               `json:"projectId,omitempty"`
	Name            string               `json:"name"`
	Enabled         bool                 `json:"enabled"`
	EventPatterns   []string             `json:"eventPatterns"`
	MinimumSeverity NotificationSeverity `json:"minimumSeverity"`
	DestinationIDs  []string             `json:"destinationIds"`
}

func NotificationPreferenceDigest(route NotificationRoute) (string, error) {
	route = normalizeNotificationRoute(route)
	if err := ValidateNotificationRouteSyntax(route); err != nil {
		return "", err
	}
	doc := notificationPreferenceDigestDocument{
		Authority:       NotificationPreferenceDigestAuthority,
		OrganizationID:  route.OrganizationID,
		ProjectID:       route.ProjectID,
		Name:            route.Name,
		Enabled:         route.Enabled,
		EventPatterns:   append([]string(nil), route.EventPatterns...),
		MinimumSeverity: route.MinimumSeverity,
		DestinationIDs:  append([]string(nil), route.DestinationIDs...),
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
