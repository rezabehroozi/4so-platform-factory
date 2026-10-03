import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class C7WRequestIdentityFinalizerContractTests(unittest.TestCase):
    def test_finalizer_revalidates_shared_request_identity_authority(self):
        source=(ROOT/"scripts"/"finalize_mcp_external_client_receipt.py").read_text(encoding="utf-8")
        self.assertIn("import c7w_request_identity as request_identity",source)
        self.assertIn("request_identity.validate_packet_ids(packet)",source)
        self.assertIn('"requestIdentityAuthority":request_identity.AUTHORITY',source)
        self.assertNotIn("<unique-jsonrpc-id>",source)


if __name__=="__main__":
    unittest.main()
