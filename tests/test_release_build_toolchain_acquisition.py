import hashlib
import importlib.util
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('acquire_toolchain',ROOT/'scripts'/'acquire_release_build_toolchain.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

def candidate(raw:bytes):
    return {'archiveSize':len(raw),'archiveSha256':hashlib.sha256(raw).hexdigest()}

def test_verify_archive_accepts_exact_bytes(tmp_path):
    raw=b'exact-go-toolchain-archive-fixture'
    p=tmp_path/'go.tar.gz'; p.write_bytes(raw)
    mod.verify_archive(p,candidate(raw))

def test_verify_archive_rejects_size_or_digest_drift(tmp_path):
    raw=b'exact-go-toolchain-archive-fixture'
    p=tmp_path/'go.tar.gz'; p.write_bytes(raw+b'x')
    try: mod.verify_archive(p,candidate(raw))
    except ValueError as e: assert 'size mismatch' in str(e)
    else: raise AssertionError('size drift accepted')
    p.write_bytes(raw)
    bad=candidate(raw); bad['archiveSha256']='0'*64
    try: mod.verify_archive(p,bad)
    except ValueError as e: assert 'sha256 mismatch' in str(e)
    else: raise AssertionError('digest drift accepted')
