"""Native private balance proofs, arithmetic, and recovery/error boundaries."""
import argparse, base64, copy, hashlib, importlib.util, json, pathlib, struct, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
def b64(v): return base64.b64encode(v).decode()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream',type=pathlib.Path,required=True)
    p.add_argument('--builder',default='octra-vpn-latest-builder-20261012:latest')
    p.add_argument('--out',type=pathlib.Path,required=True)
    p.add_argument('--material',type=pathlib.Path,required=True)
    a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
    for name,digest in inventory['files'].items():
        assert hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()==digest,name
    source=ROOT/'scripts/node-port/private-balance-material.cpp'
    if not a.material.exists():
        with tempfile.TemporaryDirectory(prefix='private-balance-material-') as temp:
            executable=pathlib.Path(temp)/'material'
            subprocess.run(['clang++','-std=c++17','-O2','-I',str(a.upstream/'pvac/include'),
                '-I',str(a.upstream/'pvac_ffi'),str(source),'-o',str(executable)],check=True)
            a.material.write_bytes(subprocess.check_output([str(executable)]))
    material={k:bytes.fromhex(v) for k,v in json.loads(a.material.read_text()).items()}
    def cipher(v): return b'hfhe_v1|'+base64.b64encode(v)
    default=dict(operation='proof',strict=True,cap=True,recoverable=True,math=True,amount='7',
        public=b64(material['public']),current=b64(cipher(material['current'])),delta=b64(cipher(material['delta'])),
        proof=b64(b'zkzp_v2|'+base64.b64encode(material['proof'])),
        range=b64(b'rp_v1|'+base64.b64encode(material['range'])),
        commitment=b64(base64.b64encode(material['commitment'])),blinding=b64(base64.b64encode(material['blinding'])))
    cases=[]
    def add(name,**updates): cases.append(default|dict(name=name)|updates)
    for strict in [False,True]:
        for math in [False,True]:
            add('genuine amount proof',strict=strict,math=math)
    for field,values in {
        'public':[b'',b'PVAC',material['historical']],
        'delta':[b'',b'hfhe_v1|',b'hfhe_v1|AA==',b'hfhe_v1|!!!!',cipher(material['current'])],
        'proof':[b'',b'zkzp_v2|',b'zkzp_v2|AA==',b'zkzp_v2|!!!!',b'zkzp_v2|'+base64.b64encode(bytes(100))],
        'commitment':[b'',b'!!!!',base64.b64encode(bytes(32))],
        'blinding':[b'',b'!!!!',base64.b64encode(bytes(32)),base64.b64encode(bytes([255])*32)],
    }.items():
        for i,value in enumerate(values):add(field+' mutation '+str(i),**{field:b64(value)})
    for amount in ['-1','0','8','9223372036854775807','9223372036854775808']:
        add('amount '+amount,amount=amount)
    two_slots=cipher(b'PVAC\x03\x00'+struct.pack('<QQQQ',2,0,0,0))
    for operation in ['deposit','withdraw']:
        add('arithmetic exception aborts '+operation,operation=operation,current=b64(two_slots))
    for tag in [4,5]:
        raw=b'PVAC\x03'+bytes([tag])+struct.pack('<Q',64)+bytes(4096)
        add('legacy range format '+str(tag),operation='range',range=b64(b'rp_v1|'+base64.b64encode(raw)))
    for raw in [b'',b'PVAC\x03\x07']:
        add('truncated bound range',operation='range',range=b64(b'rp_v1|'+base64.b64encode(raw)))
    # Repeated deposits retain duplicate-seed layers; use native arithmetic to
    # supply the exact 4/6/8/10-layer wire images for both policy modes.
    spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    oracle=ROOT/'scripts/node-port/private-crypto-oracle.ml'
    layers=[b'',b'0',b'legacy',b'bad'*10,b'hfhe_v1|',b'hfhe_v1|!!!!',cipher(material['current'])]
    current=default['current']
    for i in range(4):
        row=default|dict(operation='deposit',recoverable=False,current=current)
        result=native.run(a.upstream,a.builder,oracle,[row],'octra_core yojson lwt.unix')['cases'][0]
        current=result['expected']['ok'];layers.append(base64.b64decode(current))
    for current in layers:
        for operation in ['deposit','withdraw','guard','refresh','range']:
            for cap in [False,True]:
                for recoverable in [False,True]:
                    add(operation+' layers',operation=operation,current=b64(current),cap=cap,recoverable=recoverable)
    # A valid withdrawal range proof belongs to the computed remainder.
    row=default|dict(operation='withdraw')
    remainder=native.run(a.upstream,a.builder,oracle,[row],'octra_core yojson lwt.unix')['cases'][0]['expected']['ok']
    for strict in [False,True]:
        for math in [False,True]:
            add('genuine remainder proof',operation='range',current=remainder,strict=strict,math=math)
    report=native.run(a.upstream,a.builder,oracle,cases,'octra_core yojson lwt.unix')
    report['material_sha256']=hashlib.sha256(a.material.read_bytes()).hexdigest()
    report['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    report['material_generator_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
    report['entropy_adapter_sha256']=hashlib.sha256((ROOT/'scripts/node-port/hfhe-zero-oracle.cpp').read_bytes()).hexdigest()
    report['scope']='Private FheBalance and proof verifier; small deterministic test keys, not full transaction/epoch qualification'
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(cases)} native private crypto cases')
if __name__=='__main__': main()
