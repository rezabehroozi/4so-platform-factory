package airuntime

import (
	"encoding/json"
	"errors"
	"strings"
)

type Diagnosis struct {
	Classification    string   `json:"classification"`
	Summary           string   `json:"summary"`
	Owner             string   `json:"owner"`
	RecommendedChecks []string `json:"recommendedChecks"`
	RecommendedFix    string   `json:"recommendedFix"`
	Confidence        int      `json:"confidence"`
}

func ParseDiagnosis(raw json.RawMessage) (Diagnosis, error) {
	var out Diagnosis
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	switch out.Classification {
	case "product-defect", "test-defect", "environment", "supply-chain", "unknown":
	default:
		return out, errors.New("unsupported classification")
	}
	out.Summary = strings.TrimSpace(out.Summary)
	out.Owner = strings.TrimSpace(out.Owner)
	out.RecommendedFix = strings.TrimSpace(out.RecommendedFix)
	if out.Summary == "" || len(out.Summary) > 1000 || out.Owner == "" || len(out.Owner) > 200 || len(out.RecommendedFix) > 1500 || out.Confidence < 0 || out.Confidence > 100 || len(out.RecommendedChecks) > 5 {
		return out, errors.New("diagnosis fields exceed policy limits")
	}
	for i, value := range out.RecommendedChecks {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 500 {
			return out, errors.New("diagnosis check is invalid")
		}
		out.RecommendedChecks[i] = value
	}
	return out, nil
}
