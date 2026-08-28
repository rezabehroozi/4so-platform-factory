package labmodel

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed certification-matrix.json
var rawGuide []byte

type ServerTier struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"displayName"`
	PhysicalServers int      `json:"physicalServers"`
	Roles           []string `json:"roles"`
	Purpose         string   `json:"purpose"`
	Notes           []string `json:"notes,omitempty"`
	ResourceSummary []string `json:"resourceSummary,omitempty"`
}

type MatrixRow struct {
	ID               string   `json:"id"`
	Group            string   `json:"group"`
	Name             string   `json:"name"`
	ServerTier       string   `json:"serverTier"`
	Phase            string   `json:"phase"`
	Destructive      bool     `json:"destructive"`
	AIEligible       bool     `json:"aiEligible"`
	Actions          []string `json:"actions"`
	AutomationStatus string   `json:"automationStatus"`
	AutomationDetail string   `json:"automationDetail"`
}

type AIPolicy struct {
	DefaultMode                    string `json:"defaultMode"`
	DefaultFailurePacketBytes      int    `json:"defaultFailurePacketBytes"`
	MaxFailurePacketBytes          int    `json:"maxFailurePacketBytes"`
	DefaultOutputTokens            int    `json:"defaultOutputTokens"`
	MaxOutputTokens                int    `json:"maxOutputTokens"`
	MaxDiagnosisCallsPerFailureRun int    `json:"maxDiagnosisCallsPerFailurePerRun"`
	RuntimeAuthority               string `json:"runtimeAuthority"`
	EgressPolicy                   string `json:"egressPolicy"`
	DurableAudit                   string `json:"durableAudit"`
	ExecutionAuthority             string `json:"executionAuthority"`
	Providers                      []struct {
		ID     string `json:"id"`
		Use    string `json:"use"`
		Status string `json:"status"`
	} `json:"providers"`
}
type MCP struct {
	Protocol      string   `json:"protocol"`
	Transport     string   `json:"transport"`
	Path          string   `json:"path"`
	DefaultAccess string   `json:"defaultAccess"`
	Tools         []string `json:"tools"`
	MutatingTools []string `json:"mutatingTools"`
	Permission    string   `json:"permission"`
	Authorization string   `json:"authorization"`
}

type Runner struct {
	Command                       string   `json:"command"`
	Commands                      []string `json:"commands"`
	CurrentFullyAutomatedRows     []string `json:"currentFullyAutomatedRows"`
	CurrentPartiallyAutomatedRows []string `json:"currentPartiallyAutomatedRows"`
	CurrentDeferredRows           []string `json:"currentDeferredRows"`
	TargetHostSSHPolicy           string   `json:"targetHostSSHPolicy"`
	BundlePolicy                  string   `json:"bundlePolicy"`
	PhysicalPassPolicy            string   `json:"physicalPassPolicy"`
}

type Guide struct {
	APIVersion    string       `json:"apiVersion"`
	Kind          string       `json:"kind"`
	SchemaVersion int          `json:"schemaVersion"`
	Authority     string       `json:"authority"`
	Principles    []string     `json:"principles"`
	ServerTiers   []ServerTier `json:"serverTiers"`
	Matrix        []MatrixRow  `json:"matrix"`
	AIPolicy      AIPolicy     `json:"aiPolicy"`
	MCP           MCP          `json:"mcp"`
	Runner        Runner       `json:"runner"`
}

func Model() Guide {
	var guide Guide
	if err := json.Unmarshal(rawGuide, &guide); err != nil {
		panic(fmt.Errorf("decode embedded lab guide: %w", err))
	}
	return guide
}

func Raw() []byte { return append([]byte(nil), rawGuide...) }
