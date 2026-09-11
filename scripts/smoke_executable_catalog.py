#!/usr/bin/env python3
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


def req(url, method="GET", body=None, headers=None):
    data=None if body is None else json.dumps(body).encode(); h=dict(headers or {})
    if data is not None: h["Content-Type"]="application/json"
    request=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(request,timeout=5) as response:
            raw=response.read(); return response.status,json.loads(raw or b"null"),dict(response.headers)
    except urllib.error.HTTPError as error:
        raw=error.read()
        try: parsed=json.loads(raw or b"null")
        except Exception: parsed={"raw":raw.decode(errors="replace")}
        return error.code,parsed,dict(error.headers)


def start(binary: Path, root: Path, state: Path):
    port=free_port(); env=os.environ.copy(); env['PLATFORM_FACTORY_DEVELOPMENT_MODE']='true'; env["PLATFORM_FACTORY_LISTEN"]=f"127.0.0.1:{port}"; env["PLATFORM_FACTORY_STATE_FILE"]=str(state)
    process=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    base=f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if req(base+"/readyz")[0]==200: return process,base
        except Exception: pass
        time.sleep(.1)
    process.terminate(); raise RuntimeError("api not ready")


def stop(process):
    process.terminate()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); process.wait()


def lifecycle(base, release):
    st,review,_=req(base+f"/api/v1/catalog-releases/{release['id']}/review","POST",{}, {"If-Match":f'"{release["revision"]}"'}); assert st==200,(st,review)
    st,published,_=req(base+f"/api/v1/catalog-releases/{release['id']}/publish","POST",{}, {"If-Match":f'"{review["revision"]}"'}); assert st==200,(st,published)
    return published


def main():
    if len(sys.argv)!=2: raise SystemExit("usage: smoke_executable_catalog.py platform-api")
    binary=Path(sys.argv[1]).resolve(); root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as temp:
        state=Path(temp)/"control-plane.json"; process,base=start(binary,root,state)
        try:
            st,org,_=req(base+"/api/v1/organizations","POST",{"name":"executable-catalog-smoke","displayName":"Executable Catalog Smoke"}); assert st==201,(st,org)
            st,signer,_=req(base+"/api/v1/catalog-governance/signing-identity"); assert st==200 and signer.get("available") is True,(st,signer)
            st,key,_=req(base+"/api/v1/catalog-trust-keys","POST",{"organizationId":org["id"],"name":"embedded-render-signer","publicKey":signer["publicKey"]}); assert st==201,(st,key)
            st,components,_=req(base+"/api/v1/catalog/components"); assert st==200,(st,components)
            selected=[c for c in components if c.get("metadata",{}).get("name")=="secure-namespace-foundation"]
            assert len(selected)==1 and selected[0]["spec"]["source"]["resolved"] is True, selected
            source=selected[0]["spec"]["source"]
            for field in ("artifactDigest","sourceLockDigest","imageInventoryDigest","licenseManifestDigest","sbom","provenance"):
                assert source[field].startswith("sha256:") and len(source[field])==71,(field,source[field])
            st,created,_=req(base+"/api/v1/catalog-releases","POST",{"organizationId":org["id"],"catalogName":"embedded-platform-foundation","catalogVersion":"1.0.0","visibility":"PRIVATE","channel":"CANDIDATE","components":selected}); assert st==201,(st,created)
            candidate=lifecycle(base,created["release"])
            st,promoted,_=req(base+f"/api/v1/catalog-releases/{candidate['id']}/promote","POST",{"channel":"RENDER"}); assert st==201,(st,promoted)
            render_published=lifecycle(base,promoted["release"])
            assert render_published["channel"]=="RENDER" and render_published["state"]=="PUBLISHED"
            st,rendered,_=req(base+f"/api/v1/catalog-releases/{render_published['id']}/render","POST",{"namespace":"catalog-smoke"}); assert st==200,(st,rendered)
            assert rendered["resourceCount"]==6 and rendered["renderedDigest"].startswith("sha256:"),rendered
            raw=json.dumps(rendered["resources"],sort_keys=True)
            assert "${" not in raw and "example.invalid" not in raw and "catalog-smoke" in raw and render_published["id"] in raw,raw
            first_digest=rendered["renderedDigest"]
            release_id=render_published["id"]
        finally: stop(process)
        process,base=start(binary,root,state)
        try:
            st,rendered2,_=req(base+f"/api/v1/catalog-releases/{release_id}/render","POST",{"namespace":"catalog-smoke"}); assert st==200,(st,rendered2)
            assert rendered2["renderedDigest"]==first_digest,(first_digest,rendered2["renderedDigest"])
            print("EXECUTABLE_CATALOG_SMOKE_PASS",release_id,first_digest,rendered2["resourceCount"])
        finally: stop(process)
    return 0


if __name__=="__main__": raise SystemExit(main())
