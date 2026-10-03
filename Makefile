SHELL := /usr/bin/env bash
GO ?= go
PYTHON ?= python3
VERSION := $(shell cat VERSION)
GIT_SOURCE_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || true)
ifneq ($(strip $(GIT_SOURCE_COMMIT)),)
override SOURCE_COMMIT := $(GIT_SOURCE_COMMIT)
else
SOURCE_COMMIT ?= unknown
endif
PLATFORM_FACTORY_DEVELOPMENT_MODE ?= true
export PLATFORM_FACTORY_DEVELOPMENT_MODE
C7W_STATE_DIR ?= .state/c7w-external-interop
C7W_PLATFORM_ADMIN_TOKEN_ENV ?= C7W_PLATFORM_ADMIN_TOKEN
C7W_ALLOW_CAMPAIGN_SUPERSEDE ?= false
C9_ADMISSION_OUT ?= .state/final-exact-release-admission.json

BUILD_LDFLAGS := -s -w -buildid= -X platform.4so.io/factory/internal/buildinfo.Version=$(VERSION) -X platform.4so.io/factory/internal/buildinfo.SourceCommit=$(SOURCE_COMMIT)

.PHONY: runtime-status runtime-resume runtime-watchdog runtime-self-test autopilot-durable autopilot-agent autopilot-context autopilot-context-full c7w-prepare c7w-admit c7w-status c7w-seal c9-admission c9-seal validate test test-postgres-integration vet race build build-release run smoke smoke-ui agent-evidence browser-triage-profile persian-ui-lint release verify-release release-readiness upstream-admission-validate upstream-admission-plan upstream-acquisition-self-test upstream-acquisition-preflight autopilot-preflight autopilot-self-test autopilot-test autopilot-release-test autopilot-real-test autopilot clean

validate:
	$(PYTHON) scripts/validate_repository.py .
	$(PYTHON) scripts/release_tool_authority_gate.py --root .

test:
	@set -euo pipefail; packages="$$( $(GO) list ./... )"; while IFS= read -r pkg; do [[ -z "$$pkg" ]] || CGO_ENABLED=1 $(GO) test -count=1 "$$pkg"; done <<< "$$packages"
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v
	$(PYTHON) scripts/test_lab_runner.py
	$(PYTHON) scripts/lab_runner.py self-test
	$(PYTHON) scripts/catalog_upstream_admission.py
	$(PYTHON) scripts/upstream_acquisition_toolchain.py --self-test
	$(PYTHON) scripts/acquire_upstream_helm.py --self-test
	$(PYTHON) scripts/acquire_virtual_cluster_runtime.py --self-test
	$(PYTHON) scripts/prepare_virtual_cluster_executor.py --self-test
	$(PYTHON) scripts/acquire_openchoreo_runtime.py --self-test
	$(PYTHON) scripts/prepare_openchoreo_executor.py --self-test
	$(PYTHON) scripts/mirror_openchoreo_runtime.py --self-test
	$(PYTHON) scripts/build_openchoreo_executor_image.py --self-test
	$(PYTHON) scripts/seal_openchoreo_runtime.py --self-test
	$(PYTHON) scripts/acquire_upstream_tagged_source.py --self-test
	$(PYTHON) scripts/acquire_historical_upgrade_batch.py --self-test

test-postgres-integration:
	@test -n "$$PLATFORM_FACTORY_POSTGRES_TEST_DSN" || (echo "PLATFORM_FACTORY_POSTGRES_TEST_DSN is required" >&2; exit 2)
	go test -tags=integration ./internal/persistence -run '^TestPostgresIntegration' -count=1 -v

vet:
	@set -euo pipefail; packages="$$( $(GO) list ./... )"; while IFS= read -r pkg; do [[ -z "$$pkg" ]] || CGO_ENABLED=1 $(GO) vet "$$pkg"; done <<< "$$packages"

race:
	@set -euo pipefail; packages="$$( $(GO) list ./... )"; while IFS= read -r pkg; do [[ -z "$$pkg" ]] || CGO_ENABLED=1 $(GO) test -race -count=1 "$$pkg"; done <<< "$$packages"

build:
	mkdir -p bin
	CGO_ENABLED=1 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/platform-api ./cmd/platform-api
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/platformctl ./cmd/platformctl
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/platform-installer ./cmd/platform-installer
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/platform-agent ./cmd/platform-agent
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/platform-probe ./cmd/platform-probe
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/virtual-cluster-renderer ./cmd/virtual-cluster-renderer
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/openchoreo-runtime ./cmd/openchoreo-runtime
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/dapr-runtime ./cmd/dapr-runtime

build-release:
	GO="$(GO)" $(PYTHON) scripts/verify_release_build_toolchain.py --require-admitted
	$(PYTHON) scripts/build_release_binaries.py --root . --go "$(GO)" --source-commit "$(SOURCE_COMMIT)" --version "$(VERSION)"

run: build
	mkdir -p .state
	PLATFORM_FACTORY_STATE_FILE=.state/control-plane.json ./bin/platform-api

smoke: build
	$(PYTHON) scripts/smoke_api.py ./bin/platform-api
	$(PYTHON) scripts/smoke_ai_control_plane.py ./bin/platform-api
	$(PYTHON) scripts/smoke_blueprint_lifecycle.py ./bin/platform-api
	$(PYTHON) scripts/smoke_blueprint_overlay_ownership.py ./bin/platform-api
	$(PYTHON) scripts/smoke_blueprint_authoring_parity.py ./bin/platform-api
	$(PYTHON) scripts/smoke_compatibility_matrix.py ./bin/platform-api
	$(PYTHON) scripts/smoke_catalog_governance.py ./bin/platform-api
	$(PYTHON) scripts/smoke_plan_safety.py ./bin/platform-api
	$(PYTHON) scripts/smoke_planning_impact.py ./bin/platform-api
	$(PYTHON) scripts/smoke_evidence_collection_completion.py ./bin/platform-api
	$(PYTHON) scripts/smoke_rollback_feasibility.py
	$(PYTHON) scripts/smoke_operation_retry_recovery.py ./bin/platform-api
	$(PYTHON) scripts/smoke_operation_step_trace_authority.py ./bin/platform-api
	$(PYTHON) scripts/smoke_compensation_orchestration.py ./bin/platform-api
	$(PYTHON) scripts/smoke_owner_destructive_recovery.py ./bin/platform-api
	$(PYTHON) scripts/smoke_tenant_resize_protected_delete.py ./bin/platform-api
	$(PYTHON) scripts/smoke_cluster_maintenance.py ./bin/platform-api
	$(PYTHON) scripts/smoke_target_node_lifecycle.py ./bin/platform-api
	$(PYTHON) scripts/smoke_target_node_provider_add.py ./bin/platform-api
	$(PYTHON) scripts/smoke_oidc_group_authz_audit.py ./bin/platform-api
	$(PYTHON) scripts/smoke_git_credential_reference.py ./bin/platform-api
	$(PYTHON) scripts/smoke_git_pull_request_lkg.py ./bin/platform-api
	$(PYTHON) scripts/smoke_git_three_way_drift.py ./bin/platform-api
	$(PYTHON) scripts/smoke_upgrade_control.py ./bin/platform-api
	$(PYTHON) scripts/smoke_notification_routing.py ./bin/platform-api
	$(PYTHON) scripts/smoke_executable_catalog.py ./bin/platform-api
	$(PYTHON) scripts/smoke_external_catalog_bundle.py ./bin/platformctl
	$(PYTHON) scripts/smoke_canonical_gateway_api.py ./bin/platform-api
	$(PYTHON) scripts/smoke_canonical_snapshot_controller.py ./bin/platform-api
	$(PYTHON) scripts/smoke_image_mirror_runtime.py ./bin/platform-api ./bin/platformctl
	$(PYTHON) scripts/smoke_runtime_certification.py ./bin/platform-api
	$(PYTHON) scripts/smoke_service_account_token.py ./bin/platform-api
	$(PYTHON) scripts/smoke_agent_mtls.py ./bin/platform-api ./bin/platformctl
	$(PYTHON) scripts/smoke_fleet_support.py ./bin/platform-api ./bin/platformctl
	$(PYTHON) scripts/smoke_workload_logs.py ./bin/platform-api
	$(PYTHON) scripts/smoke_installer.py ./bin/platform-installer ./bin/platformctl
	$(PYTHON) scripts/smoke_installer_host.py ./bin/platformctl ./bin/platform-installer
	$(PYTHON) scripts/smoke_installer_remote.py ./bin/platformctl ./bin/platform-installer

smoke-ui:
	$(PYTHON) scripts/smoke_ui.py .
	$(PYTHON) scripts/smoke_ui_quality.py
	$(PYTHON) scripts/persian_ui_lint.py --root .
	$(PYTHON) scripts/persian_writing_gate.py --root . --write-report
	$(PYTHON) scripts/console_localization_coverage.py --root .
	$(PYTHON) scripts/smoke_ui_localization_runtime.py .
	$(PYTHON) scripts/smoke_ui_live.py ./bin/platform-api .

agent-evidence:
	mkdir -p .state
	$(PYTHON) scripts/generate_agent_knowledge.py --check --out .state/agent-knowledge.json

browser-triage-profile:
	$(PYTHON) scripts/browser_triage_profile.py

persian-ui-lint:
	$(PYTHON) scripts/persian_ui_lint.py --root .
	$(PYTHON) scripts/persian_writing_gate.py --root . --write-report

release: clean validate test vet race build-release smoke smoke-ui
	GO="$(GO)" $(PYTHON) scripts/package_release_exact.py --root .

verify-release:
	$(PYTHON) scripts/verify_release.py release/4so-platform-factory-$$(cat VERSION)-$$(cat RELEASE-NAME).zip --full

release-readiness:
	$(GO) run ./cmd/platformctl release-readiness -f blueprints/enterprise-private-cloud.json

upstream-admission-validate:
	$(PYTHON) scripts/catalog_upstream_admission.py

upstream-admission-plan:
	$(PYTHON) scripts/catalog_upstream_admission.py --commands

upstream-acquisition-self-test:
	$(PYTHON) scripts/catalog_upstream_admission.py
	$(PYTHON) scripts/upstream_acquisition_toolchain.py --self-test
	$(PYTHON) scripts/acquire_upstream_helm.py --self-test
	$(PYTHON) scripts/acquire_upstream_batch.py --self-test
	$(PYTHON) scripts/acquire_upstream_tagged_source.py --self-test
	$(PYTHON) scripts/acquire_historical_upgrade_batch.py --self-test
	$(PYTHON) scripts/supply_chain_handoff.py --check --status

upstream-acquisition-preflight:
	$(PYTHON) scripts/catalog_upstream_admission.py
	$(PYTHON) scripts/acquire_upstream_helm.py --preflight

c7w-prepare:
	@test -n "$(C7W_MCP_ENDPOINT)" || (echo "C7W_MCP_ENDPOINT is required" >&2; exit 2)
	$(PYTHON) scripts/run_mcp_external_interop.py --state-dir "$(C7W_STATE_DIR)" prepare --endpoint "$(C7W_MCP_ENDPOINT)" --token-env "$(C7W_PLATFORM_ADMIN_TOKEN_ENV)" $(if $(strip $(C7W_OAUTH_CLIENT_MAP)),--oauth-client-map "$(C7W_OAUTH_CLIENT_MAP)",)

c7w-admit:
	@test -n "$(C7W_CLIENT)" || (echo "C7W_CLIENT is required" >&2; exit 2)
	@test -n "$(C7W_CAPTURE)" || (echo "C7W_CAPTURE is required" >&2; exit 2)
	$(PYTHON) scripts/run_mcp_external_interop.py --state-dir "$(C7W_STATE_DIR)" admit --client "$(C7W_CLIENT)" --capture "$(C7W_CAPTURE)" --token-env "$(C7W_PLATFORM_ADMIN_TOKEN_ENV)" $(if $(filter true 1 yes,$(C7W_ALLOW_CAMPAIGN_SUPERSEDE)),--allow-campaign-supersede,)

c7w-status:
	$(PYTHON) scripts/run_mcp_external_interop.py --state-dir "$(C7W_STATE_DIR)" status

c7w-seal:
	$(PYTHON) scripts/run_mcp_external_interop.py --state-dir "$(C7W_STATE_DIR)" seal

c9-admission:
	@mkdir -p "$(dir $(C9_ADMISSION_OUT))"
	$(PYTHON) scripts/final_exact_release_admission.py --allow-pending --out "$(C9_ADMISSION_OUT)"

c9-seal:
	$(PYTHON) scripts/seal_final_exact_release.py --root . --out lab/final-exact-release-evidence.json
autopilot-preflight:
	$(PYTHON) scripts/codex_autopilot.py --preflight --repair

autopilot-self-test:
	$(PYTHON) scripts/codex_autopilot.py --self-test

autopilot-status:
	$(PYTHON) scripts/codex_autopilot.py --event-summary

autopilot-context:
	$(PYTHON) scripts/codex_autopilot.py --agent-context-compact

autopilot-context-full:
	$(PYTHON) scripts/codex_autopilot.py --agent-context

autopilot-agent:
	$(PYTHON) scripts/project_runtime.py start --phase C6-multi-agent-test-autopilot --task codex-autopilot-agent --heartbeat-seconds 30 --checkpoint-file .state/codex-autopilot-run.json --replay-safe --allow-owned-worktree-mutation -- $(PYTHON) scripts/codex_autopilot.py --agent-run

autopilot-test:
	$(PYTHON) scripts/codex_autopilot.py

autopilot-release-test:
	$(PYTHON) scripts/project_runtime.py start --phase C9-pre-certification-feature-freeze-exact-bundle --task autopilot-release-test --heartbeat-seconds 30 --checkpoint-file .state/codex-autopilot-run.json --replay-safe -- $(PYTHON) scripts/codex_autopilot.py --release-ready

autopilot-real-test:
	$(PYTHON) scripts/project_runtime.py start --phase D-exact-sha-physical-runtime --task autopilot-real-test --heartbeat-seconds 30 --checkpoint-file .state/codex-autopilot-run.json -- $(PYTHON) scripts/codex_autopilot.py --real-test

autopilot:
	$(PYTHON) scripts/project_runtime.py start --phase C6-multi-agent-test-autopilot --task codex-autopilot --heartbeat-seconds 30 --checkpoint-file .state/codex-autopilot-run.json --replay-safe --allow-owned-worktree-mutation -- $(PYTHON) scripts/codex_autopilot.py --repair

clean:
	rm -rf bin dist release .state
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

runtime-status:
	$(PYTHON) scripts/project_runtime.py status

runtime-resume:
	$(PYTHON) scripts/project_runtime.py resume

runtime-watchdog:
	$(PYTHON) scripts/project_runtime.py watchdog

runtime-self-test:
	$(PYTHON) scripts/project_runtime.py self-test

autopilot-durable:
	$(PYTHON) scripts/project_runtime.py start --phase C6-multi-agent-test-autopilot --task codex-autopilot --heartbeat-seconds 30 --checkpoint-file .state/codex-autopilot-run.json --replay-safe --allow-owned-worktree-mutation -- $(PYTHON) scripts/codex_autopilot.py --repair
