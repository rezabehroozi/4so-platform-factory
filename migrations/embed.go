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
