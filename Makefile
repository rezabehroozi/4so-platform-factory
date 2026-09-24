SHELL := /usr/bin/env bash
GO ?= go
PYTHON ?= python3
VERSION := $(shell cat VERSION)
PLATFORM_FACTORY_DEVELOPMENT_MODE ?= true
export PLATFORM_FACTORY_DEVELOPMENT_MODE

BUILD_LDFLAGS := -s -w -buildid= -X platform.4so.io/factory/internal/buildinfo.Version=$(VERSION)

.PHONY: validate test test-postgres-integration vet race build build-release run smoke smoke-ui agent-evidence browser-triage-profile persian-ui-lint release verify-release release-readiness upstream-admission-validate upstream-admission-plan upstream-acquisition-self-test upstream-acquisition-preflight autopilot-preflight autopilot-self-test autopilot-test autopilot-release-test autopilot-real-test autopilot clean

validate:
	$(PYTHON) scripts/validate_repository.py .

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

build-release:
	$(PYTHON) scripts/verify_release_build_toolchain.py --require-admitted
	mkdir -p bin/linux-amd64
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/linux-amd64/platform-api ./cmd/platform-api
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/linux-amd64/platformctl ./cmd/platformctl
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/linux-amd64/platform-installer ./cmd/platform-installer
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/linux-amd64/platform-agent ./cmd/platform-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/linux-amd64/platform-probe ./cmd/platform-probe
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/linux-amd64/virtual-cluster-renderer ./cmd/virtual-cluster-renderer
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags '$(BUILD_LDFLAGS)' -o bin/linux-amd64/openchoreo-runtime ./cmd/openchoreo-runtime

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
	$(PYTHON) scripts/build_release.py .

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

autopilot-preflight:
	$(PYTHON) scripts/codex_autopilot.py --preflight --repair

autopilot-self-test:
	$(PYTHON) scripts/codex_autopilot.py --self-test

autopilot-test:
	$(PYTHON) scripts/codex_autopilot.py

autopilot-release-test:
	$(PYTHON) scripts/codex_autopilot.py --release-ready

autopilot-real-test:
	$(PYTHON) scripts/codex_autopilot.py --real-test

autopilot:
	$(PYTHON) scripts/codex_autopilot.py --repair

clean:
	rm -rf bin dist release .state
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
