import importlib.util, json, tempfile, unittest, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('tagged',ROOT/'scripts/acquire_upstream_tagged_source.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

class TaggedSourceAcquisitionTests(unittest.TestCase):
    def test_committed_historical_recipes_bind_admission_and_full_commit(self):
        expected={
            ('gateway-api','1.5.0'):'3797b631d20f9ff4e2b4571f62d91d84a1fbdf5a',
            ('snapshot-controller','8.4.0'):'f21cb02763e7cd6a7fc84846f106b83119b5371d',
        }
        for (component,version),commit in expected.items():
            recipe,row=mod.load_recipe(component,version,historical=True,root=ROOT)
            self.assertEqual(version,row['previousVersion'])
            self.assertEqual(commit,recipe['spec']['commitSHA'])
            self.assertEqual(row['source'],recipe['spec']['releaseURL'])
            self.assertTrue(any(f['render'] for f in recipe['spec']['files']))

    def test_tag_ref_resolution_is_commit_pinned_and_annotated_tag_safe(self):
        commit='a'*40
        direct=lambda url,**kwargs: json.dumps({'object':{'sha':commit,'type':'commit'}}).encode()
        self.assertEqual(commit,mod._resolve_tag_commit('o/r','v1.2.3',timeout=1,fetch=direct))
        tagsha='b'*40
        def annotated(url,**kwargs):
            if '/git/ref/' in url: return json.dumps({'object':{'sha':tagsha,'type':'tag'}}).encode()
            return json.dumps({'object':{'sha':commit,'type':'commit'}}).encode()
        self.assertEqual(commit,mod._resolve_tag_commit('o/r','v1.2.3',timeout=1,fetch=annotated))

    def test_deterministic_zip_and_traversal_negative_control(self):
        raw={'install.yaml':b'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n'}
        idx={'apiVersion':'platform.4so.io/v1alpha1','kind':'UpstreamSourceSet','component':'x','version':'1.0.0','upstream':{'revision':'v1.0.0'},'assembly':{'method':'deterministic-zip-from-official-tag-files','networkFetchRequired':False},'files':[]}
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            a=Path(td)/'a.zip'; b=Path(td)/'b.zip'
            mod.deterministic_zip(raw,idx,a); mod.deterministic_zip(raw,idx,b)
            self.assertEqual(a.read_bytes(),b.read_bytes())
            with zipfile.ZipFile(a) as z: self.assertEqual({'install.yaml','source-index.json'},set(z.namelist()))
        with self.assertRaises(RuntimeError): mod._safe_source_path('../escape')
        with self.assertRaises(RuntimeError): mod._https('http://raw.githubusercontent.com/x')
        with self.assertRaises(RuntimeError): mod._https('https://evil.example/x',hosts={'raw.githubusercontent.com'})

if __name__=='__main__': unittest.main()
