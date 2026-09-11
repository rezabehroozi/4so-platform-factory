package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"platform.4so.io/factory/internal/controlplane"
)

func TestDay2CampaignEngineContractIsMachineReadable(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/day2-campaign-engine", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got controlplane.Day2CampaignEngineDescriptor
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Authority != controlplane.GeneralizedDay2CampaignAuthorityMethod || len(got.StageOrder) != 10 || len(got.Adapters) != 2 {
		t.Fatalf("descriptor=%+v", got)
	}
}
