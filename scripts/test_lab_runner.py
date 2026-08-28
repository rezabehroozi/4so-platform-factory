#!/usr/bin/env python3
import importlib.util, json, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("lab_runner",ROOT/"scripts/lab_runner.py")
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

def main():
    assert mod.self_test()==0
    g=mod.guide(); assert g["authority"]=="LAB_CERTIFICATION_MATRIX_V1"
    assert g["aiPolicy"]["defaultMode"]=="failure-only"
    assert g["aiPolicy"]["defaultFailurePacketBytes"]==8192 and g["aiPolicy"]["defaultOutputTokens"]==800
    assert {p["id"] for p in g["aiPolicy"]["providers"]} >= {"codex-cli","claude-code","openai-responses","antigravity-command"}
    assert g["runner"]["currentFullyAutomatedRows"]==["M00","M01"]
    fake={"stage":"boom","command":["x","--password=hunter2"],"returnCode":1,"durationSeconds":0,"outputTail":"Authorization: Bearer very-secret-token\npassword=another-secret\n"+"a"*50000,"fingerprint":"f","status":"FAIL"}
    packet=mod.failure_packet(fake,artifact_sha="a"*64)
    assert len(json.dumps(packet,separators=(",",":")).encode()) <= 8192
    encoded=json.dumps(packet)
    assert "hunter2" not in encoded and "very-secret-token" not in encoded and "another-secret" not in encoded
    assert packet["redactionCount"] >= 3
    print("LAB_RUNNER_TEST_PASS")
if __name__=="__main__": main()
