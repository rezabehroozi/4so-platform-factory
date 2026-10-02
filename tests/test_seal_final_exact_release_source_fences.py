import hashlib, importlib.util, json, os, subprocess, tempfile, unittest, zipfile
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class FinalExactReleaseSourceFenceTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_git_source_rejects_non_main_branch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"tracked.txt").write_text("tracked\n")
            self.git(root,"add","tracked.txt")
            self.git(root,"commit","-m","initial")
            self.git(root,"checkout","-b","feature")
            with self.assertRaisesRegex(RuntimeError,"BRANCH_NOT_MAIN"):
                mod.git_source(root.resolve())

    def test_git_source_rejects_untracked_bytes_not_bound_to_head(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            (root/"tracked.txt").write_text("tracked\n")
            self.git(root,"add","tracked.txt"); self.git(root,"commit","-m","initial")
            head=self.git(root,"rev-parse","HEAD")
            self.assertEqual(head,mod.git_source(root.resolve()))
            (root/"untracked.txt").write_text("not in HEAD\n")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_NOT_EXACT_HEAD"):
                mod.git_source(root.resolve())

    def test_git_source_rejects_assume_unchanged_index_masking(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            tracked=root/"tracked.txt"; tracked.write_text("tracked\n")
            self.git(root,"add","tracked.txt"); self.git(root,"commit","-m","initial")
            self.git(root,"update-index","--assume-unchanged","tracked.txt")
            tracked.write_text("hidden-drift\n")
            with self.assertRaisesRegex(RuntimeError,"GIT_INDEX_FLAGS_FORBIDDEN"):
                mod.git_source(root.resolve())

    def test_detached_worktree_is_pinned_to_exact_head_and_isolated_from_root_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            tracked=root/"tracked.txt"; tracked.write_text("v1\n")
            self.git(root,"add","tracked.txt"); self.git(root,"commit","-m","initial")
            head=self.git(root,"rev-parse","HEAD")
            workspace=Path(td)/"workspace"; workspace.mkdir()
            worktree=mod.prepare_exact_worktree(root.resolve(),head,workspace)
            try:
                self.assertEqual("v1\n",(worktree/"tracked.txt").read_text())
                tracked.write_text("root-drift\n")
                self.assertEqual("v1\n",(worktree/"tracked.txt").read_text())
                mod.verify_worktree_source_unchanged(worktree,head)
                self.git(worktree,"update-index","--assume-unchanged","tracked.txt")
                with self.assertRaisesRegex(RuntimeError,"WORKTREE_SOURCE_CHANGED"):
                    mod.verify_worktree_source_unchanged(worktree,head)
            finally:
                mod.remove_exact_worktree(root.resolve(),worktree)

    def test_exact_release_environment_strips_build_semantic_overrides(self):
        injected={
            "PATH":"/usr/bin:/bin",
            "GOFLAGS":"-overlay=/tmp/evil.json",
            "GOWORK":"/tmp/evil.work",
            "GOENV":"/tmp/evil.goenv",
            "GOROOT":"/tmp/fake-go",
            "CGO_CFLAGS":"-include /tmp/evil.h",
            "CGO_LDFLAGS":"-Wl,--dynamic-linker=/tmp/evil",
            "CC":"/tmp/fake-gcc",
            "PYTHONPATH":"/tmp/evil-python",
            "LD_PRELOAD":"/tmp/evil.so",
            "GIT_DIR":"/tmp/other.git",
            "GIT_WORK_TREE":"/tmp/other-tree",
            "MAKEFILES":"/tmp/evil.mk",
            "SOURCE_COMMIT":"f"*40,
        }
        with mock.patch.dict(os.environ,injected,clear=True):
            env=mod.exact_release_environment(Path("/opt/exact-go/bin/go"))
        self.assertEqual("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",env["PATH"])
        self.assertEqual("C",env["LANG"])
        self.assertEqual("C",env["LC_ALL"])
        self.assertEqual("UTC",env["TZ"])
        self.assertEqual("/opt/exact-go/bin/go",env["GO"])
        self.assertEqual("local",env["GOTOOLCHAIN"])
        self.assertEqual("off",env["GOENV"])
        self.assertEqual("off",env["GOWORK"])
        self.assertEqual("",env["GOFLAGS"])
        self.assertEqual("off",env["GOPROXY"])
        self.assertEqual("1",env["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual("1",env["PYTHONNOUSERSITE"])
        for key in ("GOROOT","CGO_CFLAGS","CGO_LDFLAGS","CC","PYTHONPATH","LD_PRELOAD","GIT_DIR","GIT_WORK_TREE","MAKEFILES","SOURCE_COMMIT"):
            self.assertNotIn(key,env)

    def test_exact_worktree_rejects_untracked_source_but_allows_exact_staged_toolchain(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo"; root.mkdir()
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            tracked=root/"tracked.txt"; tracked.write_text("v1\n")
            self.git(root,"add","tracked.txt"); self.git(root,"commit","-m","initial")
            head=self.git(root,"rev-parse","HEAD")
            workspace=Path(td)/"workspace"; workspace.mkdir()
            worktree=mod.prepare_exact_worktree(root.resolve(),head,workspace)
            try:
                rogue=worktree/"cmd"/"rogue.go"; rogue.parent.mkdir(); rogue.write_text("package cmd\n")
                with self.assertRaisesRegex(RuntimeError,"WORKTREE_SOURCE_CHANGED"):
                    mod.verify_worktree_source_unchanged(worktree,head)
                rogue.unlink()
                staged=worktree/"vendor"/"toolchains"/"go.tgz"; staged.parent.mkdir(parents=True); staged.write_bytes(b"toolchain")
                mod.verify_worktree_source_unchanged(worktree,head,{"vendor/toolchains/go.tgz"})
                with self.assertRaisesRegex(RuntimeError,"WORKTREE_SOURCE_CHANGED"):
                    mod.verify_worktree_source_unchanged(worktree,head,{"vendor/toolchains/other.tgz"})
            finally:
                mod.remove_exact_worktree(root.resolve(),worktree)

    def test_toolchain_extraction_rejects_member_count_bomb_before_extracting(self):
        fake=mock.MagicMock()
        fake.__enter__.return_value=fake
        fake.__exit__.return_value=False
        fake.getmembers.return_value=[object()]*65537
        with tempfile.TemporaryDirectory() as td, mock.patch.object(mod.tarfile,"open",return_value=fake):
            with self.assertRaisesRegex(RuntimeError,"MEMBER_COUNT_INVALID"):
                mod.extract_toolchain(Path(td)/"archive.tgz",{"archiveSize":1024},Path(td)/"out")

    def test_toolchain_extraction_rejects_oversized_regular_member(self):
        member=SimpleNamespace(
            name="go/oversized.bin",
            size=256*1024*1024+1,
            mode=0o644,
            isdir=lambda:False,
            isreg=lambda:True,
        )
        fake=mock.MagicMock()
        fake.__enter__.return_value=fake
        fake.__exit__.return_value=False
        fake.getmembers.return_value=[member]
        with tempfile.TemporaryDirectory() as td, mock.patch.object(mod.tarfile,"open",return_value=fake):
            with self.assertRaisesRegex(RuntimeError,"MEMBER_SIZE_INVALID"):
                mod.extract_toolchain(Path(td)/"archive.tgz",{"archiveSize":1024},Path(td)/"out")

    def test_staged_toolchain_archive_is_bound_to_locked_digest_not_current_source_equality(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/"go.tgz"; source.write_bytes(b"trusted-toolchain-bytes")
            exact={
                "localArchivePath":"vendor/toolchains/go.tgz",
                "archiveSize":source.stat().st_size,
                "archiveSha256":hashlib.sha256(source.read_bytes()).hexdigest(),
            }
            worktree=root/"worktree"; worktree.mkdir()
            staged=mod.stage_toolchain_archive(source,exact,worktree)
            self.assertEqual(source.read_bytes(),staged.read_bytes())

            source.write_bytes(b"mutated-toolchain-byte")
            other=root/"other"; other.mkdir()
            with self.assertRaisesRegex(RuntimeError,"WORKTREE_TOOLCHAIN_MISMATCH"):
                mod.stage_toolchain_archive(source,exact,other)

    def test_verified_publication_is_independent_snapshot_not_source_hardlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/"verified.zip"; source.write_bytes(b"verified-release-bytes")
            target=root/"release"/"exact.zip"
            published=mod.publish_verified_file(source,target)
            self.assertEqual(b"verified-release-bytes",published.read_bytes())
            self.assertNotEqual(source.stat().st_ino,published.stat().st_ino)
            source.chmod(0o644); source.write_bytes(b"mutated-after-publication")
            self.assertEqual(b"verified-release-bytes",published.read_bytes())
            self.assertEqual(0o444,published.stat().st_mode & 0o777)

    def test_verified_publication_rejects_same_bytes_when_existing_target_is_writable(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/"verified.zip"; source.write_bytes(b"verified-release-bytes")
            target=root/"release"/"exact.zip"; target.parent.mkdir(); target.write_bytes(source.read_bytes())
            target.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError,"ARTIFACT_WRITABLE"):
                mod.publish_verified_file(source,target)

    def test_resume_rejects_writable_exact_publication_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
            out,release,evidence,admitted=self.final_evidence_fixture(root)
            release.parent.chmod(0o755)
            with mock.patch.object(mod.admission,"verify",return_value=admitted):
                with self.assertRaisesRegex(RuntimeError,"EXISTING_PUBLICATION_DIRECTORY_WRITABLE"):
                    mod.execute(root,out)

    def test_resume_rejects_writable_exact_archive_or_checksum(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
            out,release,evidence,admitted=self.final_evidence_fixture(root)
            release.chmod(0o644)
            with mock.patch.object(mod.admission,"verify",return_value=admitted):
                with self.assertRaisesRegex(RuntimeError,"EXISTING_ARCHIVE_WRITABLE"):
                    mod.execute(root,out)
            release.chmod(0o444)
            checksum=release.with_name(release.name+".sha256"); checksum.chmod(0o644)
            with mock.patch.object(mod.admission,"verify",return_value=admitted):
                with self.assertRaisesRegex(RuntimeError,"EXISTING_CHECKSUM_WRITABLE"):
                    mod.execute(root,out)

    def test_verified_publication_rejects_existing_conflicting_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/"verified.zip"; source.write_bytes(b"verified-release-bytes")
            target=root/"release"/"exact.zip"; target.parent.mkdir(); target.write_bytes(b"other")
            with self.assertRaisesRegex(RuntimeError,"ARTIFACT_CONFLICT"):
                mod.publish_verified_file(source,target)

    def test_published_checksum_must_match_exact_snapshot_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); release=root/"release.zip"; release.write_bytes(b"exact-release")
            checksum=root/"release.zip.sha256"
            checksum.write_text(f"{mod.sha256(release).removeprefix('sha256:')}  {release.name}\n",encoding="utf-8")
            mod.verify_release_checksum(release,checksum,"TEST_RELEASE")
            checksum.write_text("0"*64+f"  {release.name}\n",encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"CHECKSUM_INVALID"):
                mod.verify_release_checksum(release,checksum,"TEST_RELEASE")

    def test_exact_release_publication_is_source_sha_scoped(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            name="4so-platform-factory-0.0.363-test.zip"
            first=mod.exact_release_publication_path(root,"a"*40,name)
            second=mod.exact_release_publication_path(root,"b"*40,name)
            self.assertEqual(root/"release"/"exact-sha"/("a"*40)/name,first)
            self.assertEqual(root/"release"/"exact-sha"/("b"*40)/name,second)
            self.assertNotEqual(first,second)
            with self.assertRaisesRegex(RuntimeError,"SOURCE_SHA_INVALID"):
                mod.exact_release_publication_path(root,"bad",name)

    def final_evidence_fixture(self,root):
        (root/".gitignore").write_text("/release/\n/.state/\n",encoding="utf-8")
        (root/"VERSION").write_text("0.0.363\n",encoding="utf-8")
        (root/"RELEASE-NAME").write_text("resume-test\n",encoding="utf-8")
        self.git(root,"add",".gitignore","VERSION","RELEASE-NAME")
        self.git(root,"commit","-m","initial")
        head=self.git(root,"rev-parse","HEAD")
        name="4so-platform-factory-0.0.363-resume-test"
        release=root/"release"/"exact-sha"/head/(name+".zip")
        release.parent.mkdir(parents=True)
        embedded={
            "ARTIFACT-MANIFEST.json":b"{\"schemaVersion\":2}\n",
            "BUILD-PROVENANCE.json":b"{\"schemaVersion\":1}\n",
            "SBOM.spdx.json":b"{\"spdxVersion\":\"SPDX-2.3\"}\n",
        }
        with zipfile.ZipFile(release,"w",zipfile.ZIP_STORED) as archive:
            for filename,data in embedded.items():
                archive.writestr(name+"/"+filename,data)
        digest=mod.sha256(release)
        checksum=release.with_name(release.name+".sha256")
        checksum.write_text(f"{digest.removeprefix('sha256:')}  {release.name}\n",encoding="utf-8")
        release.chmod(0o444); checksum.chmod(0o444); release.parent.chmod(0o555)
        evidence={
            "apiVersion":"platform.4so.io/v1alpha1","kind":"FinalExactReleaseEvidence",
            "authority":mod.AUTHORITY,"sourceExecutionAuthority":mod.EXECUTION_AUTHORITY,
            "sourceWorkspaceAuthority":mod.SOURCE_WORKSPACE_AUTHORITY,"sourceCommitSHA":head,
            "version":"0.0.363","releaseName":"resume-test","releaseArchive":release.name,
            "releaseArchivePath":release.relative_to(root).as_posix(),
            "releaseArchiveSha256":digest,"releaseArchiveBytes":release.stat().st_size,
            "artifactManifestSha256":"sha256:"+hashlib.sha256(embedded["ARTIFACT-MANIFEST.json"]).hexdigest(),
            "buildProvenanceSha256":"sha256:"+hashlib.sha256(embedded["BUILD-PROVENANCE.json"]).hexdigest(),
            "sbomSha256":"sha256:"+hashlib.sha256(embedded["SBOM.spdx.json"]).hexdigest(),
            "admissionAuthority":mod.admission.AUTHORITY,
            "applianceDistributionSha256":"sha256:"+"a"*64,
            "mcpExternalInteropSha256":"sha256:"+"b"*64,
            "fullVerifierAuthority":mod.FULL_VERIFIER_AUTHORITY,"fullVerifierPass":True,
            "physicalCertified":False,
        }
        out=root/"lab"/"final-exact-release-evidence.json"
        out.parent.mkdir(); out.write_text(json.dumps(evidence),encoding="utf-8")
        admitted={"authority":mod.admission.AUTHORITY,"admitted":True,
            "applianceDistributionSha256":evidence["applianceDistributionSha256"],
            "mcpExternalInteropSha256":evidence["mcpExternalInteropSha256"],"physicalCertified":False}
        return out,release,evidence,admitted

    def test_exact_source_admission_reads_from_detached_commit_not_mutable_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
            (root/".gitignore").write_text("/.state/\n",encoding="utf-8")
            tracked=root/"authority.json"; tracked.write_text('{"value":"exact"}\n',encoding="utf-8")
            self.git(root,"add",".gitignore","authority.json"); self.git(root,"commit","-m","initial")
            head=self.git(root,"rev-parse","HEAD")
            observed={}
            def verify(worktree):
                observed["path"]=worktree
                observed["value"]=(worktree/"authority.json").read_text(encoding="utf-8")
                return {"authority":mod.admission.AUTHORITY,"admitted":True,"physicalCertified":False}
            tracked.write_text('{"value":"mutable-root"}\n',encoding="utf-8")
            with mock.patch.object(mod.admission,"verify",side_effect=verify):
                out=mod.exact_source_admission(root.resolve(),head)
            self.assertTrue(out["admitted"])
            self.assertEqual('{"value":"exact"}\n',observed["value"])
            self.assertNotEqual(root.resolve(),Path(observed["path"]).resolve())
            self.assertEqual("mutable-root",json.loads(tracked.read_text())["value"])

    def test_completed_c9_seal_resumes_without_rebuild_and_rejects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
            out,release,evidence,admitted=self.final_evidence_fixture(root)
            with mock.patch.object(mod.admission,"verify",return_value=admitted), mock.patch.object(mod,"verify_existing_release_full") as full_verify:
                self.assertEqual(evidence,mod.execute(root,out))
                full_verify.assert_called_once_with(root.resolve(),evidence["sourceCommitSHA"],release)
                release.chmod(0o644)
                with release.open("ab") as fh: fh.write(b"tamper")
                with self.assertRaisesRegex(RuntimeError,"EXISTING_ARCHIVE_WRITABLE|EXISTING_ARCHIVE_DRIFT"):
                    mod.execute(root,out)

    def test_completed_c9_resume_cannot_trust_self_declared_full_verifier_flag(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
            out,_,_,admitted=self.final_evidence_fixture(root)
            with mock.patch.object(mod.admission,"verify",return_value=admitted), mock.patch.object(mod,"verify_existing_release_full",side_effect=RuntimeError("FULL_REVERIFY_REQUIRED")):
                with self.assertRaisesRegex(RuntimeError,"FULL_REVERIFY_REQUIRED"):
                    mod.execute(root,out)

    def test_completed_c9_seal_resume_rejects_extra_fields_and_missing_checksum(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
            out,release,evidence,admitted=self.final_evidence_fixture(root)
            extra=dict(evidence); extra["runtimeCertified"]=True
            out.write_text(json.dumps(extra),encoding="utf-8")
            with mock.patch.object(mod.admission,"verify",return_value=admitted):
                with self.assertRaisesRegex(RuntimeError,"EVIDENCE_FIELDS_INVALID"):
                    mod.execute(root,out)
            out.write_text(json.dumps(evidence),encoding="utf-8")
            release.with_name(release.name+".sha256").unlink()
            with mock.patch.object(mod.admission,"verify",return_value=admitted):
                with self.assertRaisesRegex(RuntimeError,"CHECKSUM_DRIFT"):
                    mod.execute(root,out)

    def test_c9_resume_accepts_staged_final_evidence_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            out,release,evidence,admitted=self.final_evidence_fixture(root)
            self.git(root,"add",out.relative_to(root).as_posix())
            head=self.git(root,"rev-parse","HEAD")
            self.assertEqual(head,mod.git_source_for_resume(root.resolve(),out))
            with mock.patch.object(mod.admission,"verify",return_value=admitted), mock.patch.object(mod,"verify_existing_release_full") as full_verify:
                resumed=mod.execute(root,out)
            self.assertEqual(evidence,resumed)
            full_verify.assert_called_once_with(root.resolve(),evidence["sourceCommitSHA"],release)

    def test_c9_resume_rejects_staged_unrelated_source_change(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            out,_,_,_=self.final_evidence_fixture(root)
            self.git(root,"add",out.relative_to(root).as_posix())
            extra=root/"extra.txt"; extra.write_text("unexpected\n")
            self.git(root,"add","extra.txt")
            with self.assertRaisesRegex(RuntimeError,"SOURCE_NOT_EXACT_HEAD"):
                mod.git_source_for_resume(root.resolve(),out)

    def test_completed_c9_resume_accepts_committed_evidence_only_descendant(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            out,release,evidence,admitted=self.final_evidence_fixture(root)
            sealed_sha=evidence["sourceCommitSHA"]
            self.git(root,"add",out.relative_to(root).as_posix())
            self.git(root,"commit","-m","evidence only")
            evidence_commit=self.git(root,"rev-parse","HEAD")
            self.assertNotEqual(sealed_sha,evidence_commit)
            with mock.patch.object(mod.admission,"verify",return_value=admitted), mock.patch.object(mod,"verify_existing_release_full") as full_verify:
                resumed=mod.execute(root,out)
            self.assertEqual(evidence,resumed)
            full_verify.assert_called_once_with(root.resolve(),sealed_sha,release)
            handoff=mod.final_git_handoff(root.resolve(),out,evidence)
            self.assertEqual("C9_SEALED",handoff["nextActionCode"])
            self.assertEqual(sealed_sha,handoff["releaseSourceCommitSHA"])
            self.assertEqual(evidence_commit,handoff["evidenceCommitSHA"])

    def test_completed_c9_resume_rejects_evidence_commit_plus_source_delta(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init","-b","main")
            self.git(root,"config","user.email","test@example.invalid")
            self.git(root,"config","user.name","Test")
            out,_,evidence,admitted=self.final_evidence_fixture(root)
            self.git(root,"add",out.relative_to(root).as_posix())
            self.git(root,"commit","-m","evidence only")
            extra=root/"extra.txt"; extra.write_text("source drift\n")
            self.git(root,"add","extra.txt")
            self.git(root,"commit","-m","source drift")
            with mock.patch.object(mod.admission,"verify",return_value=admitted):
                with self.assertRaisesRegex(RuntimeError,"DELTA_NOT_EVIDENCE_ONLY"):
                    mod.execute(root,out)

    def test_completed_c9_seal_resume_rejects_unrelated_source_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init","-b","main"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
            out,_,_,admitted=self.final_evidence_fixture(root)
            (root/"unrelated.txt").write_text("drift\n")
            with mock.patch.object(mod.admission,"verify",return_value=admitted):
                with self.assertRaisesRegex(RuntimeError,"SOURCE_NOT_EXACT_HEAD"):
                    mod.execute(root,out)

    def test_output_path_preserves_and_rejects_symlink_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            target=root/"target.json"; target.write_text("{}\n")
            alias=root/"seal.json"; alias.symlink_to(target.name)
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_SYMLINK_FORBIDDEN"):
                mod.admit_output_path(root,alias)
            real=root/"real"; real.mkdir()
            parent_alias=root/"alias"; parent_alias.symlink_to(real.name,target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,"OUTPUT_PARENT_SYMLINK_FORBIDDEN"):
                mod.admit_output_path(root,parent_alias/"seal.json")

    def test_atomic_seal_publication_never_replaces_existing_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); path=root/"seal.json"
            mod.atomic_write_json(path,{"authority":"test","value":1})
            first=path.read_bytes()
            with self.assertRaisesRegex(RuntimeError,"ALREADY_SEALED"):
                mod.atomic_write_json(path,{"authority":"test","value":2})
            self.assertEqual(first,path.read_bytes())

if __name__=="__main__":
    unittest.main()
