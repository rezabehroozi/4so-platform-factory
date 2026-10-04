#!/usr/bin/env python3
"""Non-secret credential/delegation requirements for real C7W external execution."""
from __future__ import annotations

import hashlib
import json

AUTHORITY="MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1"


def contract()->dict:
    return {
        "authority":AUTHORITY,
        "profiles":{
            "none":{
                "authentication":"none",
                "delegation":{"required":False},
                "purpose":"OAuth Protected Resource Metadata discovery",
            },
            "valid-user-token-wrong-resource-audience":{
                "authentication":"oidc-user-token",
                "audience":{"mcpResourceAudienceRequired":False,"mcpResourceAudienceMustBeAbsent":True},
                "delegation":{"required":False},
                "purpose":"prove dedicated MCP audience rejection before delegation authorization",
            },
            "campaign-delegated-user":{
                "authentication":"oidc-user-token",
                "trustedNamedClientRequired":True,
                "delegation":{"required":True,"state":"ACTIVE","accessProfile":"OPERATE","scope":"campaign-project"},
                "purpose":"positive tools/list authorization with delegation-filtered capability visibility",
            },
            "project-scoped-delegation":{
                "authentication":"oidc-user-token",
                "trustedNamedClientRequired":True,
                "delegation":{"required":True,"state":"ACTIVE","accessProfile":"VIEW","scope":"one-project"},
                "requestConstraint":"replace <foreign-project-id> with a different project than the active grant scope",
                "purpose":"prove foreign-project access is denied while the grant itself remains valid",
            },
            "revoked-campaign-delegation":{
                "authentication":"oidc-user-token",
                "trustedNamedClientRequired":True,
                "delegation":{"required":True,"state":"REVOKED","previousAccessProfile":"OPERATE","scope":"campaign-project"},
                "purpose":"prove an authenticated/trusted client cannot use a revoked human delegation",
            },
            "view-delegation":{
                "authentication":"oidc-user-token",
                "trustedNamedClientRequired":True,
                "delegation":{"required":True,"state":"ACTIVE","accessProfile":"VIEW","scope":"same-project-operation"},
                "requestConstraint":"replace <same-project-operation-id> with a real cancellable-operation ID in the grant project",
                "purpose":"prove VIEW delegation cannot mutate operation lifecycle",
            },
            "administration-delegation-requester":{
                "authentication":"oidc-user-token",
                "trustedNamedClientRequired":True,
                "delegation":{"required":True,"state":"ACTIVE","accessProfile":"ADMINISTRATION","scope":"platform-or-owning-scope"},
                "rbac":"authenticated subject must still satisfy current platform-admin/owning-scope administration RBAC",
                "requestConstraint":"replace <request-created-by-same-subject> with a pending approval request created by the same authenticated subject",
                "purpose":"prove separation-of-duties blocks self approval",
            },
        },
        "materializationAuthority":"external OAuth/OIDC plus Product MCP delegation APIs",
        "tokenValuesEmbedded":False,
        "clientSecretsEmbedded":False,
        "secretsIncluded":False,
        "runtimeCertified":False,
        "physicalCertified":False,
    }


def contract_digest()->str:
    raw=json.dumps(contract(),sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return "sha256:"+hashlib.sha256(raw).hexdigest()


def main()->int:
    print(json.dumps(contract(),sort_keys=True))
    return 0


if __name__=="__main__": raise SystemExit(main())
