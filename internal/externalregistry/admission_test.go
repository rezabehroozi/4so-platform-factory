package externalregistry

import (
	"strings"
	"testing"
)

func TestAdmitRequiresHTTPSDigestPinnedReference(t *testing.T) {
	good := Request{RegistryURL: "https://registry.example.test", ImageReference: "registry.example.test/team/app@sha256:" + strings.Repeat("a", 64), Direction: "IMPORT", CredentialRef: "cred_registry_read"}
	result, err := Admit(good)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Admitted || result.Authority != Authority || result.RegistryHost != "registry.example.test" || result.Digest == "" || result.RawCredentialsAllowed {
		t.Fatalf("result=%+v", result)
	}
	for _, bad := range []Request{
		{RegistryURL: "http://registry.example.test", ImageReference: good.ImageReference, Direction: "IMPORT"},
		{RegistryURL: "https://user:pass@registry.example.test", ImageReference: good.ImageReference, Direction: "IMPORT"},
		{RegistryURL: "https://registry.example.test/path", ImageReference: good.ImageReference, Direction: "IMPORT"},
		{RegistryURL: "https://registry.example.test", ImageReference: "registry.example.test/team/app:latest", Direction: "IMPORT"},
		{RegistryURL: "https://registry.example.test", ImageReference: "other.example.test/team/app@sha256:" + strings.Repeat("a", 64), Direction: "IMPORT"},
		{RegistryURL: "https://registry.example.test", ImageReference: good.ImageReference, Direction: "IMPORT", CredentialRef: "user:password"},
		{RegistryURL: "https://registry.example.test", ImageReference: good.ImageReference, Direction: "IMPORT", CredentialRef: "token=secret"},
		{RegistryURL: "https://registry.example.test", ImageReference: good.ImageReference, Direction: "IMPORT", CredentialRef: "https://vault.example/secret"},
	} {
		if _, err := Admit(bad); err == nil {
			t.Fatalf("bad request admitted: %+v", bad)
		}
	}
}

func TestAdmitDirectionIsAllowListed(t *testing.T) {
	ref := "registry.example.test/team/app@sha256:" + strings.Repeat("b", 64)
	for _, direction := range []string{"IMPORT", "EXPORT", "MIRROR"} {
		if _, err := Admit(Request{RegistryURL: "https://registry.example.test", ImageReference: ref, Direction: direction}); err != nil {
			t.Fatalf("direction %s: %v", direction, err)
		}
	}
	if _, err := Admit(Request{RegistryURL: "https://registry.example.test", ImageReference: ref, Direction: "DELETE"}); err == nil {
		t.Fatal("unsupported direction admitted")
	}
}
