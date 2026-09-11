package api

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

const mcpProductActionRegistryAuthority = "MCP_PRODUCT_ACTION_REGISTRY_V1"

//go:embed mcp_action_registry.json
var rawMCPProductActionRegistry []byte

func mcpProductActionRegistryModel() map[string]any {
	var model map[string]any
	if err := json.Unmarshal(rawMCPProductActionRegistry, &model); err != nil {
		panic(fmt.Errorf("decode embedded MCP product action registry: %w", err))
	}
	return model
}
