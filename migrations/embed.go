package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.sql
var files embed.FS

type Compatibility string

const (
	CompatibilityRollingSafe      Compatibility = "ROLLING_SAFE"
	CompatibilityQuiescedRequired Compatibility = "QUIESCED_REQUIRED"
)

type Migration struct {
	Version             int64
	Name                string
	SQL                 string
	Checksum            string
	Compatibility       Compatibility
	CompatibilityReason string
}

func compatibilityForVersion(version int64) (Compatibility, string, error) {
	switch {
	case version >= 1 && version <= 20:
		return CompatibilityRollingSafe, "historical migration reviewed for compatibility gate; direct upgrades crossing v21 are blocked before any pending mutation", nil
	case version == 21:
		return CompatibilityQuiescedRequired, "v21 makes blueprint revision columns NOT NULL without defaults; old writers do not populate those columns", nil
	case version >= 22 && version <= 26:
		return CompatibilityRollingSafe, "reviewed additive/expanding schema migration", nil
	case version == 27:
		return CompatibilityQuiescedRequired, "v27 adds destructive-operation CHECK constraints that are enforced for new writes; old writers do not populate destructive_operation_id before entering destructive states", nil
	case version >= 28 && version <= 44:
		return CompatibilityRollingSafe, "reviewed additive/expanding schema migration", nil
	case version == 45:
		return CompatibilityRollingSafe, "v45 canonicalizes mutable provider distribution aliases and changes only the default; old writers keep supplying explicit compatible values", nil
	case version == 46:
		return CompatibilityRollingSafe, "v46 adds nullable/defaulted inventory authority evidence and an inventory epoch timestamp; old writers remain valid and new binaries fail closed until a fresh inventory report", nil
	case version == 47:
		return CompatibilityQuiescedRequired, "v47 enables post-revocation re-enrollment and replaces a global UNIQUE constraint with a partial unique index; old writers use the legacy fixed agent ServiceAccount and must be stopped before this semantic boundary is crossed", nil
	case version == 48:
		return CompatibilityRollingSafe, "v48 adds a defaulted cluster-import agent principal authority; existing imports remain on the legacy fixed ServiceAccount while newly created imports persist an isolated principal", nil
	case version == 49:
		return CompatibilityRollingSafe, "v49 adds defaulted mutation-RBAC inventory-basis authority digests; old writers remain schema-compatible while new binaries fail closed until a fresh inventory and explicit activation issuance establish the new authority", nil
	case version == 50:
		return CompatibilityQuiescedRequired, "v50 introduces digest-bound target-RBAC revocation acknowledgement and repairs legacy same-UID successors; old writers do not enforce the predecessor fence ordering and must be stopped before this semantic boundary is crossed", nil
	case version == 51:
		return CompatibilityRollingSafe, "v51 is a data-only parity repair that adds the explicit read-only capability marker to already-inventoried legacy successors whose mutation authority was removed by v50; no schema or write contract changes", nil
	case version == 52:
		return CompatibilityRollingSafe, "v52 adds a nullable inventory observation-epoch timestamp; old writers remain schema-compatible while new binaries fail closed until a fresh observed inventory establishes authority", nil
	case version == 53:
		return CompatibilityRollingSafe, "v53 adds an independent AI advisory-run table; existing writers and authorities are unchanged and new binaries may begin recording redacted AI metadata", nil
	case version == 54:
		return CompatibilityRollingSafe, "v54 adds an independent durable AI dispatch-claim table; old writers remain schema-compatible while new writers acquire at-most-once provider dispatch authority before model egress", nil
	case version == 55:
		return CompatibilityRollingSafe, "v55 adds defaulted immutable runtime-closure exact-release identity columns; old writers remain schema-compatible as legacy schema 0 while new writers persist exact release and producer binary digests", nil
	case version == 56:
		return CompatibilityRollingSafe, "v56 adds an independent immutable project-scoped variable-schema authority; existing writers and runtime tables are unchanged", nil
	case version == 57:
		return CompatibilityRollingSafe, "v57 adds immutable project-scoped platform policy-set/template authorities and insert-time reference guards; existing writers and runtime tables are unchanged", nil
	case version == 58:
		return CompatibilityRollingSafe, "v58 adds independent project-scoped workspace and namespace-binding authorities with insert/update reference guards; existing writers and runtime tables are unchanged", nil
	case version == 59:
		return CompatibilityRollingSafe, "v59 adds a defaulted workload-explorer JSON projection to cluster inventory snapshots; old writers remain valid and new readers treat missing observations as incomplete rather than authoritative", nil
	case version == 60:
		return CompatibilityQuiescedRequired, "v60 introduces an executable OS_PATCH maintenance action; old agents interpret legacy maintenance tasks as drain-only and must be stopped before OS patch runs can be created", nil
	case version == 61:
		return CompatibilityQuiescedRequired, "v61 introduces exact CAPI Machine remove/replace mutation envelopes; old agents do not honor node/inventory/window identity fencing and must be stopped before destructive provider-node mutations are admitted", nil
	case version == 62:
		return CompatibilityRollingSafe, "v62 adds independent trusted MCP client and human delegation grant authorities; existing writers and resource tables remain schema-compatible while new binaries enforce delegation on human MCP requests", nil
	case version == 63:
		return CompatibilityRollingSafe, "v63 adds defaulted component identity columns and expands runtime-certification profile admission; old writers remain schema-compatible while new binaries bind component certification to exact component/release identity", nil
	case version == 64:
		return CompatibilityQuiescedRequired, "v64 introduces component-only FAILURE_RECOVERY and REMOVE task phases; old agents reject these phase values and must be stopped before new binaries can advance a component certification beyond VERIFY", nil
	case version == 65:
		return CompatibilityRollingSafe, "v65 adds independent backup-policy and target data-protection run authorities; old agents ignore the new task endpoint while existing writers remain schema-compatible", nil
	case version == 66:
		return CompatibilityRollingSafe, "v66 adds independent compliance profile/scan/finding/waiver authorities; old agents ignore the new scan task lane while existing writers remain schema-compatible", nil
	case version == 67:
		return CompatibilityRollingSafe, "v67 adds product-owned SAML broker desired state and durable identity-admin jobs; existing writers remain schema-compatible and Keycloak reconciliation is performed only by new API workers using server-held credentials", nil
	case version == 68:
		return CompatibilityRollingSafe, "v68 adds immutable bounded request payloads for durable operations; existing operation writers remain schema-compatible while new critical workflows can atomically bind sealed non-secret input", nil
	case version == 69:
		return CompatibilityRollingSafe, "v69 adds an independent durable MCP control-job authority; existing API writers remain schema-compatible while new MCP mutation bridges record idempotent fail-closed execution envelopes", nil
	case version == 70:
		return CompatibilityRollingSafe, "v70 adds independent immutable FinOps rate-card, usage-measurement and capacity-observation authorities; existing writers and runtime tables remain unchanged", nil
	case version == 71:
		return CompatibilityRollingSafe, "v71 adds defaulted VMware infrastructure identity, endpoint and external-secret reference columns to provider profiles; old writers continue producing the unchanged unspecified-provider shape while new writers opt into the stricter VMware contract", nil
	case version == 72:
		return CompatibilityRollingSafe, "v72 adds defaulted MCP recovery-resolution metadata; old writers keep the empty legacy shape while new operators may terminally reconcile only RECOVERY_REQUIRED jobs from authoritative readback and evidence", nil
	case version == 73:
		return CompatibilityRollingSafe, "v73 adds an independent immutable FinOps budget-policy authority; existing writers and measured FinOps evidence remain unchanged while new readers derive forecast, anomaly and rightsizing views", nil
	case version == 74:
		return CompatibilityRollingSafe, "v74 adds independent product reliability observation, incident and immutable SLO authorities; existing telemetry/runtime writers remain unchanged", nil
	case version == 75:
		return CompatibilityRollingSafe, "v75 adds a defaulted immutable SLO cluster target and rekeys SLO revision identity by project/cluster/name; old writers remain schema-compatible while new binaries fail closed on untargeted legacy policies", nil
	default:
		return "", "", fmt.Errorf("migration %d is missing an explicit mixed-version compatibility classification", version)
	}
}

func All() ([]Migration, error) {
	names, err := fs.Glob(files, "*.sql")
	if err != nil {
		return nil, err
	}
	out := make([]Migration, 0, len(names))
	for _, name := range names {
		part := strings.SplitN(name, "_", 2)[0]
		version, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid migration filename %s: %w", name, err)
		}
		raw, err := files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		compatibility, reason, err := compatibilityForVersion(version)
		if err != nil {
			return nil, fmt.Errorf("classify migration %s: %w", name, err)
		}
		out = append(out, Migration{Version: version, Name: name, SQL: string(raw), Checksum: "sha256:" + hex.EncodeToString(sum[:]), Compatibility: compatibility, CompatibilityReason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}
