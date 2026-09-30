import hashlib, importlib.util, json, os, subprocess, tempfile, unittest, zipfile
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("seal_final_exact_release",ROOT/"scripts"/"seal_final_exact_release.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class FinalExactReleaseSourceFenceTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.run(["git",*args],cwd=root,text=True,capture_output=True,check=True).stdout.strip()

    def test_git_source_rejects_untracked_bytes_not_bound_to_head(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            self.git(root,"init")
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
            self.git(root,"init")
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
            self.git(root,"init")
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
        (root/".gitignore").write_text("/release/\n",encoding="utf-8")
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

    def test_completed_c9_seal_resumes_without_rebuild_and_rejects_artifact_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
            out,release,evidence,admitted=self.final_evidence_fixture(root)
            with mock.patch.object(mod.admission,"verify",return_value=admitted):
                self.assertEqual(evidence,mod.execute(root,out))
                with release.open("ab") as fh: fh.write(b"tamper")
                with self.assertRaisesRegex(RuntimeError,"EXISTING_ARCHIVE_DRIFT"):
                    mod.execute(root,out)

    def test_completed_c9_seal_resume_rejects_unrelated_source_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.git(root,"init"); self.git(root,"config","user.email","test@example.invalid"); self.git(root,"config","user.name","Test")
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
