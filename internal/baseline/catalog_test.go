package baseline

import "testing"

func TestSecureNamespaceBaselineIsDeterministic(t *testing.T) {
	d1, err := DesiredDigest("prj_1", "clu_1", SecureNamespaceID)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := DesiredDigest("prj_1", "clu_1", SecureNamespaceID)
	if d1 != d2 || d1 == "" {
		t.Fatalf("digest not deterministic: %q %q", d1, d2)
	}
	r := Resources("dep_1", d1)
	if len(r) != 5 {
		t.Fatalf("resources=%d", len(r))
	}
	for _, x := range r {
		if x.Namespace != ManagedNamespace {
			t.Fatalf("resource escaped managed namespace: %#v", x)
		}
		if x.Object == nil {
			t.Fatalf("empty object: %#v", x)
		}
	}
}
