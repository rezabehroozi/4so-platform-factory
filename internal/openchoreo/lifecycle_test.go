package openchoreo

import (
	"strings"
	"testing"
)

func TestLifecycleRequestCanonicalDigestAndTransitionFences(t *testing.T) {
	source := "sha256:" + strings.Repeat("a", 64)
	previous := "sha256:" + strings.Repeat("b", 64)
	req := LifecycleRequest{
		ProjectID: " p1 ", ClusterID: " c1 ", Action: "install",
		RuntimeSourceDigest: source,
		OIDCIssuer: "https://auth.example.test/realms/platform",
		OIDCClientID: "platform-console",
		NativeCapabilitySuppressions: []string{"tenancy-native", "networking-and-ingress-native", "tenancy-native"},
	}
	raw, digest, err := MarshalLifecycleRequest(req)
	if err != nil { t.Fatal(err) }
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 { t.Fatalf("digest=%q", digest) }
	parsed, err := ParseLifecycleRequest(raw, digest)
	if err != nil { t.Fatal(err) }
	if parsed.Action != ActionInstall || parsed.ProjectID != "p1" || len(parsed.NativeCapabilitySuppressions) != 2 {
		t.Fatalf("parsed=%#v", parsed)
	}
	if err = ValidateLifecycleTransition(ActionInstall, nil, source); err != nil { t.Fatal(err) }
	installed := &ObservedState{Installed: true, RuntimeSourceDigest: previous}
	if err = ValidateLifecycleTransition(ActionInstall, installed, source); err == nil { t.Fatal("duplicate install admitted") }
	if err = ValidateLifecycleTransition(ActionUpgrade, installed, source); err != nil { t.Fatal(err) }
	if err = ValidateLifecycleTransition(ActionUpgrade, &ObservedState{Installed: true, RuntimeSourceDigest: source}, source); err == nil {
		t.Fatal("no-op upgrade admitted")
	}
	if err = ValidateLifecycleTransition(ActionRemove, installed, source); err != nil { t.Fatal(err) }
	if err = ValidateLifecycleTransition(ActionRemove, nil, source); err == nil { t.Fatal("remove without observed install admitted") }
}

func TestLifecycleRequestRejectsUnknownSuppressionAndDigestDrift(t *testing.T) {
	source := "sha256:" + strings.Repeat("a", 64)
	req := LifecycleRequest{ProjectID:"p", ClusterID:"c", Action:ActionInstall, RuntimeSourceDigest:source, OIDCIssuer:"https://auth.example.test/realms/platform", OIDCClientID:"platform-console", NativeCapabilitySuppressions:[]string{"fake-native"}}
	if _, _, err := MarshalLifecycleRequest(req); err == nil { t.Fatal("unknown suppression admitted") }
	req.NativeCapabilitySuppressions = nil
	raw, digest, err := MarshalLifecycleRequest(req)
	if err != nil { t.Fatal(err) }
	if _, err = ParseLifecycleRequest(raw, "sha256:"+strings.Repeat("f",64)); err == nil { t.Fatal("request digest drift admitted") }
	if _, err = ParseLifecycleRequest(raw, digest); err != nil { t.Fatal(err) }
}


func TestLifecycleDispatchFenceRejectsPostApprovalObservedDrift(t *testing.T) {
	source := "sha256:" + strings.Repeat("a", 64)
	previous := "sha256:" + strings.Repeat("b", 64)
	changed := "sha256:" + strings.Repeat("c", 64)

	approvedObserved := &ObservedState{Installed: true, RuntimeSourceDigest: previous}
	if err := ValidateLifecycleDispatchFence(ActionUpgrade, approvedObserved, source, previous); err != nil {
		t.Fatalf("stable approved fence rejected: %v", err)
	}

	driftedObserved := &ObservedState{Installed: true, RuntimeSourceDigest: changed}
	if err := ValidateLifecycleDispatchFence(ActionUpgrade, driftedObserved, source, previous); err == nil || !strings.Contains(err.Error(), "OPENCHOREO_OBSERVED_FENCE_CHANGED") {
		t.Fatalf("post-approval observed drift was not fenced: %v", err)
	}

	if err := ValidateLifecycleDispatchFence(ActionInstall, driftedObserved, source, ""); err == nil {
		t.Fatal("post-approval install race admitted an already installed runtime")
	}
}

func TestCanonicalExternalOIDCBinding(t *testing.T){
	issuer,client,err:=CanonicalExternalOIDCBinding(" https://auth.example.test/realms/platform/ ","platform-console")
	if err!=nil||issuer!="https://auth.example.test/realms/platform"||client!="platform-console"{t.Fatalf("canonical OIDC binding failed: %q %q %v",issuer,client,err)}
	for _,bad:=range [][2]string{{"http://auth.example.test/realms/platform","platform-console"},{"https://auth.example.test/realms/platform?x=1","platform-console"},{"https://auth.example.test/realms/platform","bad,client"}}{
		if _,_,err:=CanonicalExternalOIDCBinding(bad[0],bad[1]);err==nil{t.Fatalf("invalid OIDC binding admitted: %#v",bad)}
	}
}
