import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_mcp_external_interop_cli_context",ROOT/"scripts"/"run_mcp_external_interop.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class MCPExternalLocalRunnerCLIContextTests(unittest.TestCase):
    def test_main_emits_canonical_working_directory_for_followup_commands(self):
        args=SimpleNamespace(
            command="status",
            progress_out=Path("lab/mcp-external-client-interop-progress.json"),
            evidence_out=Path("lab/mcp-external-client-interoperability-evidence.json"),
            matrix=Path("lab/mcp-external-client-interop-matrix.json"),
            state_dir=Path(".state/c7w-external-interop"),
        )
        parser=SimpleNamespace(parse_args=lambda:args)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            previous=Path.cwd()
            os.chdir(root)
            try:
                with (
                    mock.patch.object(mod,"parser",return_value=parser),
                    mock.patch.object(mod,"require_canonical_artifact_path",side_effect=lambda current,_candidate,rel,_label:current/rel),
                    mock.patch.object(mod,"status",return_value={
                        "authority":mod.AUTHORITY,
                        "action":"STATUS",
                        "nextActionCode":"RUN_EXTERNAL_CLIENT",
                        "nextCommand":[],
                        "postExternalExecutionCommand":["python","scripts/run_mcp_external_interop.py","admit"],
                    }),
                ):
                    buf=io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        rc=mod.main()
            finally:
                os.chdir(previous)
        self.assertEqual(0,rc)
        out=json.loads(buf.getvalue())
        self.assertEqual(str(root),out["workingDirectory"])
        self.assertEqual("RUN_EXTERNAL_CLIENT",out["nextActionCode"])


if __name__=="__main__":
    unittest.main()
