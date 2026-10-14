"""Compare full native private balance plans and atomic account application."""
import argparse, base64, hashlib, importlib.util, json, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
def b64(v):return base64.b64encode(v).decode()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream',type=pathlib.Path,required=True)
    p.add_argument('--builder',default='octra-vpn-latest-builder-20261012:latest')
    p.add_argument('--material',type=pathlib.Path,required=True)
    p.add_argument('--out',type=pathlib.Path,required=True)
    a=p.parse_args()
    material={k:bytes.fromhex(v) for k,v in json.loads(a.material.read_text()).items()}
    payload=dict(cipher='hfhe_v1|'+b64(material['delta']),zero_proof='zkzp_v2|'+b64(material['proof']),
        amount_commitment=b64(material['commitment']),blinding=b64(material['blinding']),
        range_proof_balance='rp_v1|'+b64(material['range']))
    def encoded(v):return b64(json.dumps(v,separators=(',',':')).encode())
    default=dict(balance='100',amount='7',fee='2',nonce=1,withdraw=False,unique=True,
        strict=True,recoverable=True,public=b64(material['public']),
        current=b64(('hfhe_v1|'+b64(material['current'])).encode()),payload=encoded(payload))
    cases=[]
    def add(name,**kw):cases.append(default|dict(name=name)|kw)
    for withdraw in [False,True]:
        for unique in [False,True]:
            add('valid plan',withdraw=withdraw,unique=unique)
        add('insufficient fee or amount',withdraw=withdraw,balance='0')
        add('invalid nonce',withdraw=withdraw,nonce=2)
        add('stale prepared state',withdraw=withdraw,stale=True)
        add('no registered key',withdraw=withdraw,public=None)
        add('bad registered key',withdraw=withdraw,public=b64(b'bad'))
        add('historical key refused',withdraw=withdraw,public=b64(material['historical']))
        add('missing payload',withdraw=withdraw,payload=None)
        for value in [None,{},[],{'cipher':None},{'cipher':True}, {'cipher':'wrong','amount_commitment':'','zero_proof':'','blinding':''}]:
            add('malformed payload',withdraw=withdraw,payload=encoded(value))
        for name in ['cipher','amount_commitment','zero_proof','blinding','range_proof_balance']:
            for unique in [False,True]:
                raw=json.dumps(payload,separators=(',',':'))[:-1]+','+json.dumps(name)+':"second"}'
                add('duplicate '+name,withdraw=withdraw,unique=unique,payload=b64(raw.encode()))
        for name in ['blinding','amount_commitment','zero_proof','cipher']:
            add('invalid '+name,withdraw=withdraw,payload=encoded(payload|{name:'!'}))
    add('empty encrypted balance deposit',current=b64(b'0'))
    add('empty encrypted balance withdrawal',current=b64(b'0'),withdraw=True)
    add('public supply ceiling rollback',withdraw=True,balance='1000000000000000')
    add('wrong remaining balance proof',withdraw=True,payload=encoded(payload|{'range_proof_balance':'rp_v1|AA=='}))
    add('missing remaining balance proof',withdraw=True,payload=encoded({k:v for k,v in payload.items() if k!='range_proof_balance'}))
    for amount in ['-1','0','1000000000001']:
        add('decrypt amount bounds precede payload',withdraw=True,amount=amount,payload=None)
    spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    report=native.run(a.upstream,a.builder,ROOT/'scripts/node-port/private-balance-oracle.ml',cases,'octra_core yojson lwt.unix')
    report['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    report['material_sha256']=hashlib.sha256(a.material.read_bytes()).hexdigest()
    report['scope']='Real native worker verification and ledger account/root application; epoch admission gates are separate'
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f'Generated {len(cases)} native private balance cases')
if __name__=='__main__':main()
