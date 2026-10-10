package webconsole

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBoundedResourceExplorerConsoleEnhancementContract(t *testing.T) {
	jsBytes, err := fs.ReadFile(content, "static/resource-explorer.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(jsBytes)
	for _, contract := range []string{
		"BOUNDED_RESOURCE_EXPLORER_AUTHORITY_V1",
		"resourcePage",
		"nextCursor",
		"UNKNOWN",
		"resourceReadOnly",
		"rawKubernetesMutation",
		"OWNER_PRODUCT_API_ONLY",
		"personaJourneys",
		"taskLanguageFirst",
		"/workloads?",
	} {
		if !strings.Contains(js, contract) {
			t.Fatalf("bounded resource explorer console contract missing %q", contract)
		}
	}
	for _, forbidden := range []string{"kubectl", "method: 'DELETE'", "method:\"DELETE\"", "method: 'PATCH'", "method:\"PATCH\""} {
		if strings.Contains(js, forbidden) {
			t.Fatalf("resource explorer enhancement must remain read-only; found %q", forbidden)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("console index status=%d", w.Code)
	}
	body := w.Body.String()
	app := strings.Index(body, `<script src="/app.js"></script>`)
	enhancement := strings.Index(body, `<script src="/resource-explorer.js"></script>`)
	if app < 0 || enhancement < 0 || enhancement <= app {
		t.Fatal("resource explorer enhancement must load after the canonical app.js")
	}
}
