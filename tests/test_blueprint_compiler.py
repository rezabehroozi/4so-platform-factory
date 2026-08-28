import json,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BLUEPRINT=ROOT/'blueprints/enterprise-private-cloud.json'
class CompilerTests(unittest.TestCase):
 def test_compile_produces_ordered_non_executable_preview(self):
  with tempfile.TemporaryDirectory() as d:
   r=subprocess.run(['python3',str(ROOT/'scripts/compile_blueprint.py'),str(BLUEPRINT),'--root',str(ROOT),'--output',d],text=True,capture_output=True)
   self.assertEqual(r.returncode,0,r.stdout+r.stderr)
   p=json.loads((Path(d)/'plan.json').read_text());waves=[x['wave'] for x in p['steps']]
   self.assertEqual(waves,sorted(waves));self.assertTrue(p['evidenceRequired'])
   self.assertFalse(p['executable']);self.assertGreater(len(p['blockers']),0)
   previews=list((Path(d)/'previews/applications').glob('*.json'));self.assertEqual(len(previews),len(p['steps']))
   first=json.loads(previews[0].read_text());self.assertEqual(first['metadata']['annotations']['platform.4so.io/executable'],'false')
   self.assertNotIn('automated',first['spec']['syncPolicy'])
   metallb=next(json.loads(x.read_text()) for x in previews if x.name.endswith('-metallb.json'))
   self.assertEqual(metallb['spec']['source']['helm']['valuesObject']['addressPool'],'192.0.2.100-192.0.2.120')
 def test_missing_dependency_fails(self):
  b=json.loads(BLUEPRINT.read_text());b['spec']['components']=[x for x in b['spec']['components'] if x['name']!='gateway-api']
  with tempfile.TemporaryDirectory() as d:
   bp=Path(d)/'bad.json';bp.write_text(json.dumps(b));r=subprocess.run(['python3',str(ROOT/'scripts/compile_blueprint.py'),str(bp),'--root',str(ROOT),'--output',str(Path(d)/'out')],text=True,capture_output=True)
   self.assertNotEqual(r.returncode,0)
if __name__=='__main__':unittest.main()
