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
    zero=bytes(433)
    cipher=(1).to_bytes(8,'little')+bytes(24)
    for tag in [4,5]:
        empty=b'PVAC\x03'+bytes([tag])+(64).to_bytes(8,'little')+cipher*64+(zero*65 if tag==4 else zero[:-1])
        add(empty);add(empty+b'\0')
        for cut in list(range(16))+list(range(14,len(empty),137))+[len(empty)-1]:add(empty[:cut])
        for version in range(7):
            changed=bytearray(empty);changed[4]=version;add(changed)
        for count in [0,1,63,65,1<<24,(1<<64)-1]:
            changed=bytearray(empty);changed[6:14]=count.to_bytes(8,'little');add(changed)
        for position in [0,5,14,21,22,30,38,14+64*32,14+64*32+256,14+64*32+352,len(empty)-1]:
            changed=bytearray(empty);changed[position]^=255;add(changed)
    zero_wire=json.loads((ROOT/'crates/octra-hfhe/tests/fixtures/proof_wire.json').read_text())
    for case in zero_wire['cases']:
        raw=bytearray.fromhex(case['input'])
        if len(raw)>=6:raw[5]=7
        add(raw)
    cases=[dict(input=value.hex()) for value in dict.fromkeys(inputs)]
    lines=[case['input'] for case in cases]
    oracle = ROOT/'scripts/node-port/hfhe-range-wire-oracle.cpp'
    with tempfile.TemporaryDirectory(prefix='octra-hfhe-range-wire-') as temp:
        executable = pathlib.Path(temp)/'oracle'
        subprocess.run(['clang++','-std=c++17','-O2','-I',str(args.upstream/'pvac/include'),
            '-I',str(args.upstream/'pvac_ffi'),str(oracle),'-o',str(executable)],check=True)
        output = subprocess.check_output([str(executable)],input='\n'.join(lines)+'\n',text=True)
    results=output.splitlines()
    if len(results)!=len(cases): raise SystemExit('native oracle output count mismatch')
    for case,result in zip(cases,results): case['expected']=json.loads(result)
    report=dict(upstream_commit=pin,source_sha256=hashes,architecture=platform.machine(),
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
        scope='Native legacy, aggregate and bound range wire acceptance, exact refusal errors and canonical reserialization; not complete backend parity',cases=cases)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f"Generated {len(cases)} native range proof decodes")


if __name__=='__main__': main()
