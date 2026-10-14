#!/usr/bin/env python3
"""Generate roots/preimages with the adopted native Irmin implementation."""
import argparse, base64, hashlib, json, pathlib, random, shutil, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
def encoded(value): return base64.b64encode(value).decode()
def fixtures():
    rng = random.Random(0x1A11)
    cases = []
    for value in [b'', b'abc', b'\0\xff\x7f', bytes(range(256)), b'x'*127, b'x'*128, b'x'*16384]:
        for op in ['contents', 'step']: cases.append(dict(op=op,value=encoded(value)))
    for count in [0,1,2,31,32,33,127,128,255,256,257]:
        entries = [dict(name=encoded(rng.randbytes(rng.randrange(0,40))), hash=encoded(rng.randbytes(64)),
                        kind='node' if i%3==0 else 'contents') for i in range(count)]
        cases.append(dict(op='node',entries=entries))
        if entries: cases.append(dict(op='node',entries=entries+entries[:1]))
    for date in [0,1,-1,2**63-1,-2**63]:
        for count in [0,1,2,127,128]:
            cases.append(dict(op='commit',node=encoded(rng.randbytes(64)),
                parents=[encoded(rng.randbytes(64)) for _ in range(count)],date=str(date),
                author=encoded(b'octra\xff'),message=encoded(rng.randbytes(137))))
    for count in [0,1,2,31,32,33,255,256,257,512,1025]:
        operations=[dict(op='set',path=[encoded(f'key-{i:06}'.encode())],value=encoded(rng.randbytes(i%97))) for i in range(count)]
        cases.append(dict(op='tree',operations=operations))
    # Force a two-level hash-bits inode to exercise nested unstable value nodes.
    keys=[]; index=0
    while len(keys)<260:
        key=f'collision-{index}'.encode(); index+=1
        digest=hashlib.blake2b(key).digest()
        if digest[0]==0 and digest[1]>>6==0: keys.append(key)
    cases.append(dict(op='tree',operations=[dict(op='set',path=[encoded(key)],value=encoded(b'v')) for key in keys]))
    for _ in range(80):
        operations=[]
        for _ in range(60):
            path=[encoded(rng.choice([b'',b'a',b'b',b'\xff',b'\0',b'state',b'accounts'])) for _ in range(rng.randrange(0,6))]
            operations.append(dict(op='set',path=path,value=encoded(rng.randbytes(rng.randrange(0,65)))) if rng.randrange(4) else dict(op='remove',path=path))
        cases.append(dict(op='tree',operations=operations))
    return cases

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',type=pathlib.Path,required=True)
    parser.add_argument('--builder-image',required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
    pin=subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()
    if pin != inventory['upstream_commit'] or args.out.exists(): raise SystemExit('require current pin and a fresh output')
    for name,digest in inventory['files'].items():
        if hashlib.sha256((args.upstream/name).read_bytes()).hexdigest()!=digest: raise SystemExit(f'modified upstream: {name}')
    inputs=fixtures()
    with tempfile.TemporaryDirectory(prefix='octra-storage-') as temporary:
        work=pathlib.Path(temporary)
        shutil.copyfile(ROOT/'scripts/node-port/storage-oracle.ml',work/'main.ml')
        (work/'dune').write_text('(executable (name main) (libraries octra_core lwt.unix yojson base64 irmin))\n')
        (work/'input.json').write_text(json.dumps(inputs))
        (work/'runtime.sha256').write_text(''.join(f'{digest}  {name}\n' for name,digest in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1); path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        (work/'dependencies.py').write_text("import pathlib,hashlib,json,subprocess\nroot=pathlib.Path('/home/opam/.opam/4.14.2/lib')\nfiles={}\nfor package in ['irmin','irmin-pack','repr','digestif','irmin-containers','ppx_irmin']:\n for path in sorted((root/package).rglob('*')):\n  if path.is_file() and path.suffix in ['.ml','.mli']:\n   files[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()\nprint(json.dumps(dict(source_sha256=files,packages=subprocess.check_output(['opam','list','--installed','--columns=name,version','--color=never'],text=True))))\n")
        command=['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly',
            '--mount',f'type=bind,source={args.upstream.resolve()},target=/native,readonly',args.builder_image,'bash','-lc',
            'python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && python3 /oracle/dependencies.py && mkdir vpn_storage_oracle && cp /oracle/main.ml /oracle/dune vpn_storage_oracle/ && opam exec -- dune exec ./vpn_storage_oracle/main.exe < /oracle/input.json']
        output=subprocess.check_output(command,text=True)
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256((ROOT/'scripts/node-port/storage-oracle.ml').read_bytes()).hexdigest(),dependencies=json.loads(output.splitlines()[-2]),cases=json.loads(output.splitlines()[-1]))
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(inputs)} native storage cases: {args.out}')
if __name__=='__main__': main()
