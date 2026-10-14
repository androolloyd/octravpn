#!/usr/bin/env python3
"""Qualify Circle storage costs and speculative stable-state persistence."""
import argparse, base64, hashlib, importlib.util, json, pathlib, random, shutil, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('state',ROOT/'scripts/node-port/circle-state-fixtures.py')
state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
b64=state.b64

def fixtures():
    cases=[];circle=state.CIRCLE;path=(b'circles',circle,b'stable',b'by_hash')
    initial=state.state()
    values=[b'{',b'null',b'{}',state.entry('counter','4'),state.raw(dict(raw_key='x',key_hash='h',value={'value_kind':'blob_ref','value_blob_hash':'h','value_size':'4'})),state.raw(dict(raw_key='x',key_hash='h',value={'value_kind':'blob_ref','value_blob_hash':'h','value_size':'bad'}))]
    entries=[initial,initial|{path:b'contents'},initial|{path+(b'nested',b'key'):b'ignored'}]
    entries += [initial|{path+(b'0',):v} for v in values]
    entries += [initial|{path+(b'0',):a,path+(b'1',):b} for a in values for b in values]
    for count in [1,2,16,32,33,128,255,256,257,300]:
        es=dict(initial)
        for i in range(count):
            key=f'key{i}';es[path+(state.assets.digest(b'octra:stable_key:v1',key.encode()).encode(),)]=state.entry(key,'value'+str(i))
        entries.append(es)
        dup=dict(es);dup[path+(b'zzz',)]=state.entry('key0','duplicate');entries.append(dup)
    for es in entries:
        for budget in [None,-1,0,15,16,17,100,1000000]:
            cases.append(dict(op='load',circle=b64(circle),entries=state.encoded(es),budget=None if budget is None else str(budget)))
    rng=random.Random(7221)
    for count in [0,1,2,16,32,33,128,256,257,300]:
        pairs=[(f'key{i}'.encode(),bytes([i%256])*min(i,3)) for i in range(count)];rng.shuffle(pairs)
        for capacity in [0,100,count]:
            table=dict(capacity=capacity,pairs=[[b64(k),b64(v)] for k,v in pairs])
            for max_stable,max_inline in [(1000000,1000000),(-1,10),(0,0),(100,1),(4,1000000)]:
                for keep in [False,True]:
                    es=initial|{path+(b'old',):state.entry('old','delete')}
                    if keep:es=es|{(b'circles',circle,b'stable',b'other'):b'preserve'}
                    cases.append(dict(op='save',circle=b64(circle),entries=state.encoded(es),table=table,max_stable=str(max_stable),max_inline=str(max_inline)))
    for key,value in [(b'',b''),(b'\x00\xff',b'\\\"\n\t\x7f'),(b'x',b'\x0b\x0c')]:
        cases.append(dict(op='save',circle=b64(circle),entries=state.encoded(initial),table=dict(capacity=0,pairs=[[b64(key),b64(value)]]),max_stable='1000',max_inline='1000'))
    return cases
def write_fixture(report,path):
    """Intern repeated input trees without altering native expected outcomes."""
    report=json.loads(json.dumps(report));states=[];index={}
    for case in report['cases']:
        entries=case['input'].pop('entries');key=json.dumps(entries,separators=(',',':'))
        if key not in index:index[key]=len(states);states.append(entries)
        case['input']['state']=index[key]
    report['states']=states
    path.write_text(json.dumps(report,separators=(',',':'))+'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--fixture',type=pathlib.Path);a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if a.out.exists() or pin!=inventory['upstream_commit']:raise SystemExit('require adopted pin and fresh output')
    for name,h in inventory['files'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=h:raise SystemExit(f'modified upstream: {name}')
    oracle=ROOT/'scripts/node-port/circle-stable-oracle.ml';inputs=fixtures()
    with tempfile.TemporaryDirectory(prefix='octra-circle-stable-') as directory:
        work=pathlib.Path(directory);shutil.copyfile(oracle,work/'main.ml')
        (work/'dune').write_text('(executable (name main) (libraries octra_core octra_circle_runtime octra_vm lwt.unix yojson base64 irmin))\n')
        (work/'input.json').write_text(json.dumps(inputs));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && mkdir vpn_circle_stable_oracle && cp /oracle/main.ml /oracle/dune vpn_circle_stable_oracle/ && opam exec -- dune exec ./vpn_circle_stable_oracle/main.exe < /oracle/input.json'],text=True)
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,scope='Native Circle charged reads, storage costs, limits and stable-root writes',cases=json.loads(output.splitlines()[-1]))
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(inputs)} native Circle stable-state cases: {a.out}')
    if a.fixture:write_fixture(report,a.fixture)
if __name__=='__main__':main()
