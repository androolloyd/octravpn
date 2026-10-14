#!/usr/bin/env python3
"""Exercise the Rust swarm against the pinned OCaml swarm over localhost TCP."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
def run(*args,**kwargs):return subprocess.check_output(list(args),text=True,**kwargs)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh evidence output')
 inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=run('git','-C',str(a.upstream),'rev-parse','HEAD').strip()
 if pin!=inventory['upstream_commit']:raise RuntimeError('pin differs')
 for name,expected in inventory['files'].items():
  if digest(a.upstream/name)!=expected:raise RuntimeError(f'modified upstream source: {name}')
 source_paths=sorted((ROOT/'crates/octra-node-protocol/src/network').rglob('*.rs'))+[ROOT/'crates/octra-node-protocol/src/oce1.rs',ROOT/'crates/octra-node-protocol/tests/native_peer_interop.rs',ROOT/'scripts/node-port/native-peer-server.ml',pathlib.Path(__file__).resolve(),ROOT/'Cargo.lock']
 source_hashes={str(p.relative_to(ROOT)):digest(p) for p in source_paths}
 print('Building Rust interoperability test',flush=True)
 build=run('cargo','test','--offline','--locked','-p','octra-node-protocol','--test','native_peer_interop','--no-run','--message-format=json',cwd=ROOT)
 executable=next(row['executable'] for line in build.splitlines() if (row:=json.loads(line)).get('reason')=='compiler-artifact' and row.get('executable'))
 with tempfile.TemporaryDirectory(prefix='octra-native-peer-') as folder:
  folder=pathlib.Path(folder);shutil.copyfile(ROOT/'scripts/node-port/native-peer-server.ml',folder/'main.ml')
  (folder/'dune').write_text('(executable (name main) (libraries octra_net lwt.unix mirage-crypto-ec mirage-crypto-rng.unix))\n')
  (folder/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
  (folder/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/harness/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);p=pathlib.Path(name)\n if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:\n  p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,p)\n")
  print('Starting unmodified OCaml swarm on a localhost-published Docker port',flush=True)
  cid=run('docker','run','-d','--publish','127.0.0.1::19091','--mount',f'type=bind,source={folder},target=/harness,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /harness/restore.py && sha256sum --check --quiet /harness/runtime.sha256 && mkdir native_peer_harness && cp /harness/main.ml /harness/dune native_peer_harness/ && opam exec -- dune exec ./native_peer_harness/main.exe').strip()
  try:
   until=time.monotonic()+120
   while True:
    logs=run('docker','logs',cid,stderr=subprocess.STDOUT)
    if 'NATIVE_PEER_READY' in logs:break
    if time.monotonic()>until or run('docker','inspect','-f','{{.State.Running}}',cid).strip()!='true':raise RuntimeError(logs)
    time.sleep(1)
   address=run('docker','port',cid,'19091/tcp').strip()
   if not address.startswith('127.0.0.1:'):raise RuntimeError('peer port is not localhost-only')
   print('Running Rust/OCaml HELLO, signed discovery, profile and inventory exchange',flush=True)
   env=dict(os.environ,OCTRA_NATIVE_PEER=address)
   command=[executable,'rust_swarm_interoperates_with_pinned_ocaml_swarm','--ignored','--exact','--nocapture']
   test=subprocess.run(command,cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
   print(test.stdout,flush=True)
   if test.returncode:raise RuntimeError(f'interoperability test failed ({test.returncode})')
   if source_hashes!={str(p.relative_to(ROOT)):digest(p) for p in source_paths}:raise RuntimeError('sources changed during interoperability test')
   evidence=dict(status='PASS',upstream_commit=pin,source_sha256=inventory['files'],builder_image=a.builder_image,builder_image_id=run('docker','image','inspect','-f','{{.Id}}',a.builder_image).strip(),rust_sha256=source_hashes,test_output=test.stdout,native_output=run('docker','logs',cid,stderr=subprocess.STDOUT),scope='Rust outbound HELLO/ACK/FINISH against native inbound swarm; bidirectional native framing, signed PEX records, signed profile offers, inventory/request exchange and clean shutdown. Public deterministic development keys. No consensus execution or funded VPN claim.')
   a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(evidence,indent=2)+'\n');print(f'PASS: {a.out}',flush=True)
  finally:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
if __name__=='__main__':main()
