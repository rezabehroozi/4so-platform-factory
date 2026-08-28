# Third-party components

This source release contains 4SO product code/contracts plus explicitly embedded third-party source/runtime material recorded in the catalog and SBOM. Appliance bundles may redistribute additional exact digest-locked artifacts.

Current appliance/runtime dependencies can include RKE2, PostgreSQL, Forgejo, zot, Keycloak, Argo CD, Open Cluster Management, CloudNativePG and the selected maintenance/probe images. Their exact presence is profile/bundle dependent; every redistributed artifact must keep its upstream license/notices and be represented by digest in the bundle SBOM/provenance.

Delivered Linux `platform-api` binaries link to PostgreSQL `libpq` under the PostgreSQL License. Go standard-library licensing is BSD-3-Clause.

The repository currently embeds canonical source/runtime evidence for Gateway API and Kubernetes CSI Snapshot Controller where present under `catalog/runtime/`. Snapshot Controller upstream material is Apache-2.0 and the exact image/source digests are recorded in its catalog runtime bundle and image inventory.

Do not treat this prose as an inventory authority: `SBOM.spdx.json`, catalog source locks, image inventories and per-bundle license manifests are the machine-readable redistribution records for a built artifact.

## UI design reference

The Operator Console uses TailAdmin Community Edition as an external visual/layout reference. TailAdmin Community is MIT licensed. The current implementation does not vendor the TailAdmin runtime stack or PRO assets; 4SO reimplements the selected shell/interaction patterns in its existing embedded console. If upstream source is copied in a future change, its MIT copyright/license notice must be retained and represented in release notices/SBOM as applicable. CoreUI and AdminMart were evaluated but are not current runtime dependencies.
