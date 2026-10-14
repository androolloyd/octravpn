#!/usr/bin/env python3
"""Qualify proof gadget constraints and selected full proofs against pristine native headers.

Only the platform entropy call is redirected inside this test translation unit.
No native source is edited and no real proving secrets enter these fixtures.
"""
import argparse
import hashlib
import json
import pathlib
import platform
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('use a fresh fixture path')
    pin = json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    actual = subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()
    if actual != pin:
        raise SystemExit('upstream pin mismatch')
    source_map = json.loads((ROOT/'docs/rust-node/source-map.json').read_text())['files']
    sources = sorted(str(path.relative_to(args.upstream)) for path in (args.upstream/'pvac/include').rglob('*.hpp'))
    sources.append('pvac_ffi/pvac_serialize.hpp')
    hashes = {}
    for source in sources:
        original = subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{source}'])
        digest = hashlib.sha256(original).hexdigest()
        if (args.upstream/source).read_bytes() != original:
            raise SystemExit(f'modified native source: {source}')
        if source_map[source] != digest:
            raise SystemExit(f'adopted source map mismatch: {source}')
        hashes[source] = digest
    inputs=[]
    def add(value): inputs.append(bytes(value))
    empty=bytearray(b'PVAC\x03\x06'+bytes(433))
    add(empty)
    for size in range(len(empty)): add(empty[:size])
    for position in range(len(empty)):
        changed=empty.copy();changed[position]^=255;add(changed)
    for version in range(7):
        for tag in range(8):
            changed=empty.copy();changed[4]=version;changed[5]=tag;add(changed)
    order=(1<<252)+27742317777372353535851937790883648493
    for position in [262,294,326,366,398]:
        for scalar in [0,1,order-1,order,order+1,(1<<256)-1]:
            changed=empty.copy();changed[position:position+32]=scalar.to_bytes(32,'little');add(changed)
    for position in [358,430]:
        for count in [0,1,2,(1<<24),(1<<24)+1,(1<<64)-1]:
            changed=empty.copy();changed[position:position+8]=count.to_bytes(8,'little');add(changed)
    for flag in [0,1,2,127,255]:
        changed=empty.copy();changed[-1]=flag;add(changed)
    proofs=json.loads((ROOT/'crates/octra-hfhe/tests/fixtures/zero.json').read_text())
    for case in proofs['cases']:
        if not case['prove']:continue
        raw=b'PVAC\x03\x06'+bytes.fromhex(case['expected']['proof'])+bytes([case['operation'] not in ['zero','legacy']])
        add(raw);add(raw+b'\0');add(raw[:-1]);add(raw[:-32])
    # Remove duplicates without losing stable fixture order.
    cases=[dict(input=value.hex()) for value in dict.fromkeys(inputs)]
    lines=[case['input'] for case in cases]
    oracle = ROOT/'scripts/node-port/hfhe-proof-wire-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-proof-wire-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2','-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        output = subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results=output.splitlines()
    if len(results)!=len(cases): raise SystemExit('native oracle output count mismatch')
    for case,result in zip(cases,results): case['expected']=json.loads(result)
    report=dict(upstream_commit=pin,source_sha256=hashes,architecture=platform.machine(),
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
        scope='Native zero proof wire acceptance, exact refusal errors and canonical reserialization; not complete backend parity',cases=cases)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f"Generated {len(cases)} native zero proof decodes")


if __name__=='__main__': main()
