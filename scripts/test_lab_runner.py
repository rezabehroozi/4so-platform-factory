#!/usr/bin/env python3
import base64, hashlib, http.server, importlib.util, json, os, socket, tempfile, threading, urllib.error, urllib.request
from unittest import mock
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("lab_runner",ROOT/"scripts/lab_runner.py")
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

def main():
    assert mod.self_test()==0
    g=mod.guide(); assert g["authority"]=="LAB_CERTIFICATION_MATRIX_V2"
    assert g["aiPolicy"]["defaultMode"]=="failure-only"
    assert g["aiPolicy"]["defaultFailurePacketBytes"]==8192 and g["aiPolicy"]["defaultOutputTokens"]==800
    assert {p["id"] for p in g["aiPolicy"]["providers"]} >= {"codex-cli","claude-code","openai-responses","antigravity-command"}
    assert g["runner"]["currentFullyAutomatedRows"]==["M00","M01","M02","M03"]
    m03=next(row for row in g["matrix"] if row["id"]=="M03")
    assert m03["serverTier"]=="production-ha" and m03["automationStatus"]=="IMPLEMENTED"
    assert "PostgreSQL primary restart/failover" in m03["actions"]
    fake={"stage":"boom","command":["x","--password=hunter2"],"returnCode":1,"durationSeconds":0,"outputTail":"Authorization: Bearer very-secret-token\npassword=another-secret\n"+"a"*50000,"fingerprint":"f","status":"FAIL"}
    packet=mod.failure_packet(fake,artifact_sha="a"*64)
    assert len(json.dumps(packet,separators=(",",":")).encode()) <= 8192
    encoded=json.dumps(packet)
    assert "hunter2" not in encoded and "very-secret-token" not in encoded and "another-secret" not in encoded
    assert packet["redactionCount"] >= 3

    fake_ca=b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
    password="a"*48
    ca_b64=base64.b64encode(fake_ca).decode()
    private_output=(
        "M03_ROLE=pf_cert_0123456789abcdef\n"
        "M03_DATABASE=pf_cert_0123456789abcdef\n"
        f"M03_PASSWORD={password}\n"
        "M03_SERVICE_IP=10.43.0.10\n"
        f"M03_CA_B64={ca_b64}\n"
    )
    private=mod._parse_m03_bootstrap_output(private_output)
    assert private["M03_ROLE"]=="pf_cert_0123456789abcdef" and private["M03_SERVICE_IP"]=="10.43.0.10"
    safe=mod._sanitize_private_stage_output(private_output)
    assert password not in safe and ca_b64 not in safe and "M03_CA_B64=[OMITTED]" in safe

    with tempfile.TemporaryDirectory() as td:
        evidence_path=Path(td)/"m03.json"
        artifact_sha="a"*64
        evidence={
            "schemaVersion":2,
            "releaseEvidenceAuthority":mod.M03_EXACT_RELEASE_EVIDENCE_AUTHORITY,
            "releaseArtifactDigest":"sha256:"+artifact_sha,
            "mode":"runtime",
            "status":"PASS",
            "runtimeCertified":True,
            "aiRunPostgresDurabilityAuthority":mod.AI_RUN_POSTGRES_DURABILITY_AUTHORITY,
            "aiRunPostgresDurabilityCertified":True,
            "target":"postgresql://pf_cert_0123456789abcdef:***@platform-postgresql-rw.platform-system.svc.cluster.local:5432/pf_cert_0123456789abcdef",
            "checks":[
                {"name":"migration","status":"PASS","detail":"ok","durationMs":1},
                {"name":"ai-run-atomic-result-commit","status":"PASS","detail":"ok","durationMs":1},
                {"name":"ai-run-post-restart-durability","status":"PASS","detail":"ok","durationMs":1},
                {"name":"ai-run-post-restore-durability","status":"PASS","detail":"ok","durationMs":1},
            ],
        }
        canonical=json.dumps(evidence,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        evidence["evidenceDigest"]="sha256:"+hashlib.sha256(canonical).hexdigest()
        evidence_path.write_text(json.dumps(evidence))
        assert mod._validate_m03_evidence(evidence_path,artifact_sha)[0]
        evidence["evidenceDigest"]="sha256:"+"0"*64
        evidence_path.write_text(json.dumps(evidence))
        assert not mod._validate_m03_evidence(evidence_path,artifact_sha)[0]

    assert mod.LAB_CONTROL_PLANE_TRANSPORT_AUTHORITY=="LAB_CONTROL_PLANE_TRANSPORT_AUTHORITY_V1"
    opener=mod._build_control_plane_opener()
    proxies=[h.proxies for h in opener.handlers if isinstance(h,urllib.request.ProxyHandler)]
    assert all(not item for item in proxies)
    for address in ("169.254.169.254","0.0.0.0","224.0.0.1"):
        parsed=mod._parse_control_plane_url(f"https://{address}/healthz",label="negative-control")
        try:
            mod._resolve_control_plane_addresses(parsed,label="negative-control")
            raise AssertionError(f"unsafe Lab control-plane address accepted: {address}")
        except RuntimeError as exc:
            assert "unsafe address" in str(exc)
    private_http=mod._parse_control_plane_url("http://10.23.45.67:9443/healthz",label="negative-control")
    try:
        mod._resolve_control_plane_addresses(private_http,label="negative-control")
        raise AssertionError("plaintext non-loopback Lab control-plane endpoint accepted")
    except RuntimeError as exc:
        assert "plaintext HTTP only on loopback" in str(exc)
    request=urllib.request.Request("https://installer.example/healthz",headers={"Authorization":"Bearer synthetic-token"})
    with mock.patch.object(socket,"getaddrinfo",return_value=[(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,"",("169.254.169.254",443))]):
        with mock.patch.object(socket,"socket",side_effect=AssertionError("unsafe address reached socket dial")):
            try:
                mod._control_plane_open(request,timeout=1)
                raise AssertionError("unsafe DNS resolution was accepted")
            except RuntimeError as exc:
                assert "unsafe address" in str(exc)

    class HealthHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.headers.get("Authorization")=="Bearer loopback-token"
            if self.path=="/redirect":
                self.send_response(302); self.send_header("Location","/healthz"); self.end_headers(); return
            raw=b'{"status":"ok"}'
            self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
        def log_message(self,*args):
            pass
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),HealthHandler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        with mock.patch.dict(os.environ,{"HTTP_PROXY":"http://127.0.0.1:1","HTTPS_PROXY":"http://127.0.0.1:1"},clear=False):
            base=f"http://127.0.0.1:{server.server_port}"
            value=mod._get_json(base,"loopback-token","/healthz")
            assert value=={"status":"ok"}
            try:
                mod._get_json(base,"loopback-token","/redirect")
                raise AssertionError("Lab control-plane redirect was followed")
            except urllib.error.HTTPError as exc:
                assert exc.code==302 and "redirects are denied" in str(exc)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)

    print("LAB_RUNNER_TEST_PASS")
if __name__=="__main__": main()
