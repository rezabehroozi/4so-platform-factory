# Third-party components

This source release contains 4SO product code/contracts plus explicitly embedded third-party source/runtime material recorded in the catalog and SBOM. Appliance bundles may redistribute additional exact digest-locked artifacts.

Current appliance/runtime dependencies can include RKE2, PostgreSQL, Forgejo, zot, Keycloak, Argo CD, Open Cluster Management, CloudNativePG, Longhorn and the selected maintenance/probe images. Their exact presence is profile/bundle dependent; every redistributed artifact must keep its upstream license/notices and be represented by digest in the bundle SBOM/provenance.

Delivered Linux `platform-api` binaries link to PostgreSQL `libpq` under the PostgreSQL License. Go standard-library licensing is BSD-3-Clause.

The repository currently embeds canonical source/runtime evidence for Gateway API and Kubernetes CSI Snapshot Controller where present under `catalog/runtime/`. Snapshot Controller upstream material is Apache-2.0 and the exact image/source digests are recorded in its catalog runtime bundle and image inventory.

Do not treat this prose as an inventory authority: `SBOM.spdx.json`, catalog source locks, image inventories and per-bundle license manifests are the machine-readable redistribution records for a built artifact.

## Management Plane replicated storage source authority

Longhorn `v1.12.1` is the canonical replicated-storage provider for the three-node RKE2 Management Plane production-HA appliance. The release does not vendor Longhorn source in ordinary source history; `lab/appliance-bundle-acquisition-lock.json` pins the official `longhorn.yaml` asset by URL, exact byte size and SHA-256 for later appliance-bundle acquisition. Longhorn is Apache-2.0 licensed. This authority is internal to the Management Plane and is not a default storage choice for OKD or other managed/imported targets.

## UI design reference

The Operator Console does not vendor UI source or assets from Spectro Cloud Palette, Rafay, SUSE Rancher, TailAdmin, CoreUI or other benchmark products. Operator Horizon V3 uses Palette/Rafay/Rancher only as product-UX research references and implements its own information architecture, tokens, HTML/CSS/JavaScript, workflows and authority semantics. Historical TailAdmin/CoreUI evaluation remains design research, not a runtime dependency. If third-party source is ever copied in a future change, its license and provenance must be admitted through the normal supply-chain process before release.

## Persian product-writing quality gate

`persian-writing` version 1.3.5 is pinned at commit `118c2167f30cafe18df13c0ba85f98f50dad1894` and integrated as a curated offline source snapshot under `third_party/persian-writing/`. Its source is MIT licensed. 4SO consumes its register, orthography and Persian AI-tell guidance through `PERSIAN_WRITING_GATE_V1`; product runtime never fetches this dependency from the network. The upstream binary font assets and optional large Persian word-list are intentionally not redistributed in this release. Machine-readable admission metadata is in `dependencies/persian-writing-admission.json`.
