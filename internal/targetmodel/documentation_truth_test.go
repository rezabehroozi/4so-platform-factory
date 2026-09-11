package targetmodel

import (
	"os"
	"strings"
	"testing"
)

// The architecture docs are operator/developer input and must not lag the
// executable target model on admission semantics.
func TestDocumentationDoesNotRegressOKDImportAuthorityOrRoadmapVersion(t *testing.T) {
	for _, name := range []string{"../../README.md", "../../DESIGN.md", "../../docs/OPERATOR_CONSOLE_DESIGN_FOUNDATION.md"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		if !strings.Contains(body, ProgramAuthorityMethod) {
			t.Fatalf("%s does not reference canonical roadmap %s", name, ProgramAuthorityMethod)
		}
		stale := []string{
			"`PROGRAM_PHASE_MODEL_V18` is the canonical product-roadmap authority",
			"the current canonical roadmap authority is `PROGRAM_PHASE_MODEL_V16`",
			"The current roadmap phase is C7",
			"current work is G Day-2/governance",
			"OKD decisions remain preview-only",
			"including OKD in the current phase",
			"These source semantics do not admit OKD mutation",
			"OKD identity and read-only admission",
		}
		for _, phrase := range stale {
			if strings.Contains(body, phrase) {
				t.Fatalf("%s contains stale OKD authority statement %q", name, phrase)
			}
		}
	}
}
