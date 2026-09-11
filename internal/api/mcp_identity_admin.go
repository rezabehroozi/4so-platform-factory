package api

import (
	"math"
	"strings"

	"platform.4so.io/factory/internal/controlplane"
)

func mcpString(arguments map[string]any, key string, required bool, max int) (string, bool) {
	raw, exists := arguments[key]
	if !exists {
		return "", !required
	}
	value, ok := raw.(string)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	if required && value == "" {
		return "", false
	}
	if max > 0 && len(value) > max {
		return "", false
	}
	return value, true
}

func mcpPositiveRevision(arguments map[string]any, key string, required bool) (int64, bool) {
	raw, exists := arguments[key]
	if !exists {
		return 0, !required
	}
	value, ok := raw.(float64)
	if !ok || value < 1 || math.Trunc(value) != value || value > math.MaxInt64 {
		return 0, false
	}
	return int64(value), true
}

func mcpSAMLBrokerChangeArguments(arguments map[string]any) (controlplane.SAMLBroker, int64, string, bool) {
	allowed := map[string]bool{"brokerId": true, "expectedRevision": true, "organizationId": true, "alias": true, "displayName": true, "entityId": true, "singleSignOnServiceUrl": true, "singleLogoutServiceUrl": true, "signingCertificate": true, "nameIdPolicyFormat": true, "wantAuthnRequestsSigned": true, "enabled": true, "idempotencyKey": true}
	for key := range arguments {
		if !allowed[key] {
			return controlplane.SAMLBroker{}, 0, "", false
		}
	}
	organizationID, ok1 := mcpString(arguments, "organizationId", true, 200)
	alias, ok2 := mcpString(arguments, "alias", true, 120)
	displayName, ok3 := mcpString(arguments, "displayName", true, 200)
	entityID, ok4 := mcpString(arguments, "entityId", true, 1000)
	ssoURL, ok5 := mcpString(arguments, "singleSignOnServiceUrl", true, 2000)
	sloURL, ok6 := mcpString(arguments, "singleLogoutServiceUrl", false, 2000)
	certificate, ok7 := mcpString(arguments, "signingCertificate", true, 32768)
	nameID, ok8 := mcpString(arguments, "nameIdPolicyFormat", false, 500)
	idempotencyKey, ok9 := mcpString(arguments, "idempotencyKey", true, 200)
	brokerID, ok10 := mcpString(arguments, "brokerId", false, 200)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8 && ok9 && ok10) {
		return controlplane.SAMLBroker{}, 0, "", false
	}
	enabledRaw, exists := arguments["enabled"]
	enabled, enabledOK := enabledRaw.(bool)
	if !exists || !enabledOK {
		return controlplane.SAMLBroker{}, 0, "", false
	}
	wantSigned := false
	if raw, exists := arguments["wantAuthnRequestsSigned"]; exists {
		var ok bool
		wantSigned, ok = raw.(bool)
		if !ok {
			return controlplane.SAMLBroker{}, 0, "", false
		}
	}
	expected, revisionOK := mcpPositiveRevision(arguments, "expectedRevision", brokerID != "")
	if !revisionOK || (brokerID == "" && expected != 0) {
		return controlplane.SAMLBroker{}, 0, "", false
	}
	return controlplane.SAMLBroker{ResourceMeta: controlplane.ResourceMeta{ID: brokerID}, OrganizationID: organizationID, Alias: alias, DisplayName: displayName, EntityID: entityID, SingleSignOnServiceURL: ssoURL, SingleLogoutServiceURL: sloURL, SigningCertificate: certificate, NameIDPolicyFormat: nameID, WantAuthnRequestsSigned: wantSigned, Enabled: enabled}, expected, idempotencyKey, true
}

func mcpSAMLBrokerDeleteArguments(arguments map[string]any) (string, int64, string, bool) {
	if len(arguments) != 3 {
		return "", 0, "", false
	}
	id, idOK := mcpString(arguments, "id", true, 200)
	revision, revisionOK := mcpPositiveRevision(arguments, "expectedRevision", true)
	key, keyOK := mcpString(arguments, "idempotencyKey", true, 200)
	return id, revision, key, idOK && revisionOK && keyOK
}
