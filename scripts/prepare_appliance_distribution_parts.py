#!/usr/bin/env python3
"""Split one exact appliance distribution object into immutable transport parts."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import distribution_transport as transport

AUTHORITY="APPLIANCE_MULTIPART_DISTRIBUTION_MANIFEST_V1"


def prepare(path: Path, out_dir: Path, *, max_part_bytes: int, name: str) -> dict:
    row=transport.split_file(path,out_dir,max_part_bytes=max_part_bytes,name=name)
    return {
        "authority":AUTHORITY,
        "objectName":name,
        "sha256":row["sha256"],
        "sizeBytes":row["sizeBytes"],
        "partCount":row["partCount"],
        "maxPartBytes":row["maxPartBytes"],
        "parts":row["parts"],
    }


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path,required=True)
    p.add_argument("--out-dir",type=Path,required=True)
    p.add_argument("--name",required=True)
    p.add_argument("--max-part-bytes",type=int,default=1536*1024*1024)
    p.add_argument("--manifest",type=Path,required=True)
    a=p.parse_args()
    doc=prepare(a.input.resolve(),a.out_dir.resolve(),max_part_bytes=a.max_part_bytes,name=a.name)
    a.manifest.parent.mkdir(parents=True,exist_ok=True)
    a.manifest.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"authority":AUTHORITY,"objectName":doc["objectName"],"sha256":"sha256:"+doc["sha256"],"sizeBytes":doc["sizeBytes"],"partCount":doc["partCount"]},sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
