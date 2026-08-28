#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,subprocess,sys
from pathlib import Path

def load(path:Path): return json.loads(path.read_text())

def main():
 p=argparse.ArgumentParser(description='Compile a blueprint into a deterministic, non-syncing planning preview')
 p.add_argument('blueprint');p.add_argument('--root',default=str(Path(__file__).resolve().parents[1]));p.add_argument('--output',required=True);a=p.parse_args()
 root=Path(a.root).resolve();bp=Path(a.blueprint).resolve();out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
 result=subprocess.run(['go','run','./cmd/platformctl','plan','-f',str(bp)],cwd=root,text=True,capture_output=True)
 if result.returncode:
  sys.stderr.write(result.stdout+result.stderr);return result.returncode
 plan=json.loads(result.stdout);(out/'plan.json').write_text(json.dumps(plan,indent=2,sort_keys=True)+'\n')
 blueprint=load(bp);components={x['metadata']['name']:x for x in (load(p) for p in sorted((root/'catalog/components').glob('*.json')))}
 previews=out/'previews/applications';previews.mkdir(parents=True,exist_ok=True)
 registry=blueprint['spec']['delivery']['ociRegistry']
 selections={x['name']:x for x in blueprint['spec']['components']}
 for step in plan['steps']:
  c=components[step['component']]
  source={'repoURL':registry,'chart':c['spec']['delivery']['chart'],'targetRevision':c['spec']['release']}
  settings=selections.get(step['component'],{}).get('settings') or {}
  if settings: source['helm']={'valuesObject':settings}
  app={'apiVersion':'argoproj.io/v1alpha1','kind':'Application','metadata':{'name':'platform-'+step['component'],'namespace':'argocd','annotations':{'argocd.argoproj.io/sync-wave':str(step['wave']),'platform.4so.io/executable':'false','platform.4so.io/preview-only':'true','platform.4so.io/plan-id':plan['id']}},'spec':{'project':'platform','source':source,'destination':{'server':'https://kubernetes.default.svc','namespace':c['spec']['namespace']},'syncPolicy':{'syncOptions':['CreateNamespace=true']}}}
  (previews/f"{step['wave']:03d}-{step['component']}.json").write_text(json.dumps(app,indent=2,sort_keys=True)+'\n')
 print('COMPILE_PASS',plan['id'],'EXECUTABLE',str(plan['executable']).lower(),'BLOCKERS',len(plan['blockers']))
 return 0
if __name__=='__main__':raise SystemExit(main())
