#!/usr/bin/env python3
"""Build a pinned native-format compatibility backend; executes no repairs."""
import argparse,hashlib,json,shutil,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BUILDER='sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
WORKER=r'''
import hashlib,json,pathlib,shutil,subprocess
root=pathlib.Path.cwd();out=pathlib.Path('/output')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
inventory=json.loads(pathlib.Path('/inputs/inventory.json').read_text())
for name,expected in inventory.items():
 path=root/name
 if not path.exists() or sha(path)!=expected:
  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)
 if sha(path)!=expected:raise RuntimeError('native source differs: '+name)
program=root/'vpn_legacy_repair_backend';program.mkdir()
for name in ['backend.ml','cases.ml','legacy_repair_storage.ml','legacy_repair_version.ml','dune']:
 shutil.copyfile(pathlib.Path('/inputs')/name,program/name)
commands=[]
def run(name,argv):
 commands.append({'name':name,'argv':argv});(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 result=subprocess.run(argv,capture_output=True,text=True)
 (out/(name+'.stdout')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
 result.check_returncode();return result.stdout
version=run('compiler',['opam','exec','--','ocamlopt','-version']).strip()
if version!='4.14.2':raise RuntimeError('compiler differs')
run('packages',['opam','list','--installed','--columns=name,version','--short'])
run('build',['opam','exec','--','dune','build','./vpn_legacy_repair_backend/backend.exe','./vpn_legacy_repair_backend/cases.exe'])
for name in ['backend','cases']:
 shutil.copyfile(root/'_build/default/vpn_legacy_repair_backend'/(name+'.exe'),out/name)
 (out/name).chmod(0o555)
(out/'worker-manifest.json').write_text(json.dumps({'compiler':version,'verified_source_count':len(inventory),'source_sha256':inventory,'backend_sha256':sha(out/'backend'),'cases_sha256':sha(out/'cases'),'worker_sha256':sha(pathlib.Path('/inputs/worker.py'))},indent=2)+'\n')
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--builder-image',default=BUILDER);a=p.parse_args()
 script_digest=sha(Path(__file__));source_map=ROOT/'docs/rust-node/source-map.json';mapping=json.loads(source_map.read_text());upstream=a.upstream.resolve()
 pin=subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip()
 if pin!=mapping['upstream_commit']:raise RuntimeError('native pin differs')
 inventory=dict(mapping['files'])
 for name in ['test/recovery_case/recovery_case.ml','test/recovery_case/dune']:
  original=subprocess.check_output(['git','-C',str(upstream),'show',f'{pin}:{name}'])
  if original!=(upstream/name).read_bytes():raise RuntimeError('native test helper differs: '+name)
  inventory[name]=hashlib.sha256(original).hexdigest()
 for name,expected in inventory.items():
  if sha(upstream/name)!=expected:raise RuntimeError('native source differs: '+name)
 if not a.builder_image.startswith('sha256:') or len(a.builder_image)!=71:raise RuntimeError('require immutable builder identity')
 out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
 inspected=subprocess.run(['docker','image','inspect',a.builder_image],capture_output=True,text=True)
 (out/'builder-inspect.json').write_text(inspected.stdout);(out/'builder-inspect.stderr').write_text(inspected.stderr);inspected.check_returncode()
 image=json.loads(inspected.stdout)[0]
 if image['Id']!=a.builder_image:raise RuntimeError('builder identity differs')
 with tempfile.TemporaryDirectory(prefix='octra-legacy-build-')as temporary:
  inputs=Path(temporary)
  for source,target in [('legacy-repair-backend.ml','backend.ml'),('legacy-repair-cases.ml','cases.ml'),('legacy-repair-storage.ml','legacy_repair_storage.ml')]:shutil.copyfile(ROOT/'scripts/node-port'/source,inputs/target)
  helper_digests={name:sha(ROOT/'scripts/node-port'/name)for name in ['legacy-repair-backend.ml','legacy-repair-cases.ml','legacy-repair-storage.ml']}
  assert helper_digests=={name:sha(inputs/target)for name,target in [('legacy-repair-backend.ml','backend.ml'),('legacy-repair-cases.ml','cases.ml'),('legacy-repair-storage.ml','legacy_repair_storage.ml')]}
  (inputs/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
  (inputs/'legacy_repair_version.ml').write_text(f'let upstream = "{pin}"\n')
  (inputs/'dune').write_text('(library (name legacy_repair_storage) (wrapped false) (modules legacy_repair_storage) (libraries octra_core octra_node_runtime))\n(executable (name backend) (modules backend legacy_repair_version) (libraries legacy_repair_storage octra_core octra_node_runtime octra_consensus base64 lwt.unix unix yojson))\n(executable (name cases) (modules cases) (libraries legacy_repair_storage octra_core octra_node_runtime octra_consensus octra_recovery_case mirage-crypto-ec lwt.unix unix yojson))\n')
  (inputs/'worker.py').write_text(WORKER)
  argv=['docker','run','--rm','--network','none','--mount',f'type=bind,source={inputs},target=/inputs,readonly','--mount',f'type=bind,source={upstream},target=/native,readonly','--mount',f'type=bind,source={out},target=/output',a.builder_image,'bash','-lc','python3 /inputs/worker.py']
  (out/'host-command.json').write_text(json.dumps(argv,indent=2)+'\n')
  result=subprocess.run(argv,capture_output=True,text=True)
  (out/'builder.stdout').write_text(result.stdout);(out/'builder.stderr').write_text(result.stderr);result.check_returncode()
 assert script_digest==sha(Path(__file__)), 'builder source changed'
 if helper_digests!={name:sha(ROOT/'scripts/node-port'/name)for name in helper_digests}:raise RuntimeError('helper source changed during build')
 worker=json.loads((out/'worker-manifest.json').read_text())
 manifest=dict(schema='octra_legacy_backend_v1',upstream_commit=pin,builder_image=a.builder_image,platform=dict(os=image['Os'],architecture=image['Architecture']),source_map_sha256=sha(source_map),helper_source_sha256=helper_digests,builder_script_sha256=script_digest,**worker)
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(json.dumps({k:v for k,v in manifest.items()if k in ['upstream_commit','builder_image','backend_sha256','cases_sha256','verified_source_count']}))
if __name__=='__main__':main()
