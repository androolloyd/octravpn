#!/usr/bin/env python3
"""Native c49 VM-root encoding and narrowly scoped historical receipt projection.

Only the tree_hash JSON literal and its native byte-work emission cost change.
Full historical Circle execution is not rerun: state roots, fees, transactions,
and all unrelated receipt bytes remain original adopted native observations.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

PIN = 'c49de45cf49ebbc2e5c0697eb956cbcada5845e7'
ROOT = Path(__file__).resolve().parents[2]
HISTORICAL = ['circle-octb-execution.json', 'circle-octb-journal.json']
SOURCES = ['node_runtime/consensus_vm_transition.ml', 'node_runtime/consensus_epoch_vm_shell.ml',
           'lib/vm/runtime/contract_vm.ml', 'lib/vm/rpc/contract_rpc.ml',
           'lib/vm/runtime/byte_work.ml']
def b64(raw): return base64.b64encode(raw).decode()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--fixture',type=Path,required=True)
    parser.add_argument('--ocaml-bin',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    originals={path:subprocess.check_output(['git','-C',str(args.upstream),'show',f'{PIN}:{path}']) for path in SOURCES}
    source=originals[SOURCES[0]].decode()
    spans=[('exception Policy_unavailable of string','let float_mode '),('let tree_hash root =','let context ')]
    extracted='\n'.join(source[source.index(start):source.index(end,source.index(start))] for start,end in spans)
    # Assert the original production routing alongside executing the pure encoder.
    assert 'tree_hash = tree_hash env.prev_state_root;' in source
    assert 'tree_hash = deps.tree_hash;' in originals[SOURCES[1]].decode()
    assert '| TREEHASH rd -> setr st rd (VString st.ctx.tree_hash); true' in originals[SOURCES[2]].decode()
    assert '~some:(fun snapshot -> snapshot.Store_irmin.state_root) snapshot;' in originals[SOURCES[3]].decode()
    (args.out/'vm_root.ml').write_text(extracted)
    (args.out/'byte_work.ml').write_bytes(originals[SOURCES[4]])
    oracle=Path(__file__).with_suffix('.ml').read_bytes();(args.out/'oracle.ml').write_bytes(oracle)
    env=os.environ.copy();env['PATH']=str(args.ocaml_bin)+os.pathsep+env['PATH']
    command=[str(args.ocaml_bin/'ocamlfind'),'ocamlopt','-package','digestif.c,yojson,base64,zarith','-linkpkg','byte_work.ml','vm_root.ml','oracle.ml','-o','oracle']
    built=subprocess.run(command,cwd=args.out,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    (args.out/'build.log').write_text(built.stdout)
    if built.returncode:raise SystemExit('native root build failed; see build.log')
    raw=bytes((i*19)%256 for i in range(32)); hexed=raw.hex().encode()
    roots=[raw,hexed,hexed.upper(),hexed+b'00'*32,b'0'*31,b'0'*33,b'0'*63,b'g'*64,hexed+b'0'*63+b'g',b'',b'0'*129]
    fixtures={name:json.loads((ROOT/'crates/octra-node-runtime/tests/fixtures'/name).read_text()) for name in HISTORICAL}
    for report in fixtures.values():
        for case in report['cases']:
            if 'before' in case['expected']:
                root=case['expected']['before'].encode()
                if root not in roots: roots.append(root)
    observed=json.loads(subprocess.check_output([str((args.out/'oracle').resolve())],input=json.dumps(dict(roots=[b64(root) for root in roots],receipts=[])).encode(),env=env))
    observed=observed['roots']
    by_root={item['input']:item['expected'] for item in observed}
    metered=[]
    for name,report in fixtures.items():
        for index,case in enumerate(report['cases']):
            if case['input'].get('inspect',False):
                for tx_hash,encoded in case['expected'].get('receipts',[]):
                    metered.append(dict(fixture=name,case=index,tx_hash=tx_hash,root=case['expected']['before'],receipt=encoded))
    costs=json.loads(subprocess.check_output([str((args.out/'oracle').resolve())],
        input=json.dumps(dict(roots=[],receipts=metered)).encode(),env=env))['receipts']
    by_receipt={(row['fixture'],row['case'],row['tx_hash']):row for row in costs}
    projections=[]
    for name,report in fixtures.items():
        for index,case in enumerate(report['cases']):
            old=case['expected'].get('before','').encode()
            literal=b'"'+old+b'"'
            native=by_root.get(b64(old),{})
            if 'json' not in native: continue
            replacement=base64.b64decode(native['json'])
            for tx_hash,encoded in case['expected'].get('receipts',[]):
                receipt=base64.b64decode(encoded)
                count=receipt.count(literal)
                if not count: continue
                events=json.loads(receipt)['events']
                context_roots=sum(event['event'].lower()=='context' and len(event['values'])>6
                    and event['values'][6].encode()==old for event in events)
                assert count==context_roots, (name,index,tx_hash,count,context_roots)
                effort=json.loads(receipt)['effort']
                cost=by_receipt.get((name,index,tx_hash),dict(old=0,new=0))
                adjusted=effort-cost['old']+cost['new']
                old_effort=f'\"effort\":{effort}'.encode()
                new_effort=f'\"effort\":{adjusted}'.encode()
                assert receipt.count(old_effort)==1
                projected=receipt.replace(literal,replacement).replace(old_effort,new_effort)
                projections.append(dict(fixture=name,case=index,tx_hash=tx_hash,root=b64(old),
                    old_effort=effort,new_effort=adjusted,old_event_cost=cost['old'],new_event_cost=cost['new'],
                    old_receipt_sha256=hashlib.sha256(receipt).hexdigest(),
                    count=count,old_literal=b64(literal),replacement=b64(replacement),
                    projected_receipt=b64(projected)))
    result=dict(upstream_commit=PIN,scope=__doc__,
        source_sha256={k:hashlib.sha256(v).hexdigest() for k,v in originals.items()},
        extraction=dict(source=SOURCES[0],spans=spans,compiled_sha256=hashlib.sha256(extracted.encode()).hexdigest()),
        oracle_sha256=hashlib.sha256(oracle).hexdigest(),generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        historical_sha256={name:hashlib.sha256((ROOT/'crates/octra-node-runtime/tests/fixtures'/name).read_bytes()).hexdigest() for name in HISTORICAL},
        roots=observed,projections=projections)
    args.fixture.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(roots=len(roots),projections=len(projections),fixture=str(args.fixture))))
if __name__=='__main__':main()
