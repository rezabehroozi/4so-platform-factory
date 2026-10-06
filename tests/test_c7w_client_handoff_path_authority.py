import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/"scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0,str(SCRIPTS))
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_handoff_paths",SCRIPTS/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class C7WClientHandoffPathAuthorityTests(unittest.TestCase):
    def symlink(self,link:Path,target:Path,*,directory:bool=False):
        try:
            os.symlink(target,link,target_is_directory=directory)
        except (OSError,NotImplementedError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")

    def prepared_state(self,root:Path,client:str):
        state=mod.secure_state_dir(root/"state")
        p=mod.paths(state)
        (p["packets"]/f"{client}.json").write_text("{}",encoding="utf-8")
        (p["templates"]/f"{client}.json").write_text("{}",encoding="utf-8")
        return state,p

    def test_rejects_symlinked_packet_parent(self):
        client=mod.core.CLIENTS[0]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            state,p=self.prepared_state(root,client)
            external=root/"external-packets"; external.mkdir()
            (external/f"{client}.json").write_text("{}",encoding="utf-8")
            shutil.rmtree(p["packets"])
            self.symlink(p["packets"],external,directory=True)
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_CLIENT_HANDOFF_PATH_INVALID"):
                mod.client_execution_handoff(state,client)

    def test_rejects_symlinked_packet_file(self):
        client=mod.core.CLIENTS[0]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            state,p=self.prepared_state(root,client)
            external=root/"external-packet.json"; external.write_text("{}",encoding="utf-8")
            packet=p["packets"]/f"{client}.json"
            packet.unlink()
            self.symlink(packet,external)
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_CLIENT_HANDOFF_PATH_INVALID"):
                mod.client_execution_handoff(state,client)

    def test_capture_admission_path_is_bound_to_client_state(self):
        client=mod.core.CLIENTS[0]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            state,p=self.prepared_state(root,client)
            expected=p["captures"]/f"{client}.capture.json"
            expected.write_text("{}",encoding="utf-8")
            self.assertEqual(expected,mod.require_client_capture_path(state,client,expected))
            external=root/"external.capture.json"; external.write_text("{}",encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_CAPTURE_PATH_INVALID"):
                mod.require_client_capture_path(state,client,external)

    def test_capture_admission_path_rejects_symlink(self):
        client=mod.core.CLIENTS[0]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            state,p=self.prepared_state(root,client)
            external=root/"external.capture.json"; external.write_text("{}",encoding="utf-8")
            expected=p["captures"]/f"{client}.capture.json"
            self.symlink(expected,external)
            with self.assertRaisesRegex(RuntimeError,"MCP_EXTERNAL_LOCAL_CAPTURE_PATH_INVALID"):
                mod.require_client_capture_path(state,client,expected)


if __name__=="__main__":
    unittest.main()
