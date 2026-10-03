import importlib.util
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("c7w_credential_profiles",ROOT/"scripts"/"c7w_credential_profiles.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WCredentialProfileContractTests(unittest.TestCase):
    def test_contract_covers_every_packet_profile_without_secret_material(self):
        contract=mod.contract()
        self.assertEqual("MCP_EXTERNAL_CREDENTIAL_PROFILE_CONTRACT_V1",contract["authority"])
        expected={
            "none","valid-user-token-wrong-resource-audience","campaign-delegated-user",
            "project-scoped-delegation","revoked-campaign-delegation","view-delegation",
            "administration-delegation-requester",
        }
        self.assertEqual(expected,set(contract["profiles"]))
        self.assertEqual("OPERATE",contract["profiles"]["campaign-delegated-user"]["delegation"]["accessProfile"])
        self.assertEqual("VIEW",contract["profiles"]["view-delegation"]["delegation"]["accessProfile"])
        self.assertEqual("REVOKED",contract["profiles"]["revoked-campaign-delegation"]["delegation"]["state"])
        self.assertEqual("ADMINISTRATION",contract["profiles"]["administration-delegation-requester"]["delegation"]["accessProfile"])
        text=str(contract).lower()
        for forbidden in ("clientsecret","access_token","refresh_token","bearer "):
            self.assertNotIn(forbidden,text)
        self.assertFalse(contract["secretsIncluded"])


if __name__=="__main__": unittest.main()
