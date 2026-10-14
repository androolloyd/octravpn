#!/usr/bin/env python3
"""Native raw transaction, payload and legacy archive differential fixtures."""
import argparse,base64,hashlib,importlib.util,json,pathlib,random,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
enc=lambda v:base64.b64encode(v).decode()
def cases():
    spec=importlib.util.spec_from_file_location('state',ROOT/'scripts/node-port/transaction-state-fixtures.py');state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
    base={'from':state.ADDR.decode(),'to_':'oct'+'1'*44,'amount':'17','nonce':1,'ou':'1000','timestamp':123.25,'signature':base64.b64encode(bytes(64)).decode(),'op_type':'standard','public_key':state.PUB.decode()}
    raw=lambda value:json.dumps(value,separators=(',',':')).encode()
    result=[];roots=[b'',b' ',b'null',b'[]',b'{}',b'NaN',b'Infinity',b'-Infinity',b'1e999',b'{foo:1}',b'{"x":01}',b'{"x":+1}',b'{"x":0x10}',b'{"x":1.}',b'{"x":.1}',b'/*hi*/{}//hi',b'{"x":(1,2)}',b'{"x":<"foo">}',b'{"x":"\\uD800"}',b'{"x":"\\uDC00"}',b'{"x":"\\xFF"}',b'{"x":"a\nraw"}',b'{"x":"\xff"}',b'{"x":1,}',b'[1,]',b'\xef\xbb\xbf{}']
    roots += [raw(base)]
    ints=[b'',b'+',b'-',b'0',b'-0',b'+1',b'1_0',b'_1',b'1_',b'1__',b'0x10',b'0Xff',b'0o10',b'0b10',b'0d10',b'010',b' 1',b'1 ',b'+0x10',b'0x',b'0x_1',b'0_x1',b'1\x00',b'++1',b'1\n',b'0b2',b'0o8',b'0xg']
    result += [dict(operation='integer',raw=enc(v)) for v in ints]
    for value in ints:
        for name in ['amount','ou']: roots.append(raw(base|{name:value.decode('latin1')}))
    for number in [b'0',b'-0',b'1.0',b'4611686018427387903',b'4611686018427387904',b'-4611686018427387904',b'-4611686018427387905',b'NaN',b'Infinity',b'-Infinity',b'1e999',b'null',b'"1"']:
        for name in ['amount','ou','nonce','timestamp']:
            v=raw({k:v for k,v in base.items() if k!=name});roots.append(v[:-1]+b',"'+name.encode()+b'":'+number+b'}')
    for name in base:
        roots.append(raw({k:v for k,v in base.items() if k!=name}))
        roots.append(raw(base)[:-1]+b',"'+name.encode()+b'":null}')
        roots.append(b'{"'+name.encode()+b'":null,'+raw(base)[1:])
    for value in [None,False,3,{},[],"unknown","compute_settle"]:
        roots.append(raw(base|{'op_type':value,'message':value,'encrypted_data':value,'public_key':value}))
    for value in [b'"\\uD800\\uDC00"',b'"\\uDC00"',b'"\x00\xff"',b'"raw\nline"',b'"\\uD800\\u0061"']:
        roots.append(raw(base)[:-1]+b',"message":'+value+b'}')
    roots += [raw(base).replace(b'"from":',b'from:'),b'/*legacy*/'+raw(base)+b'//end']
    rng=random.Random(7331)
    for _ in range(500):
        data=bytearray(rng.choice(roots)); pos=rng.randrange(len(data)+1)
        if rng.randrange(2) and pos<len(data):del data[pos]
        else:data[pos:pos]=rng.choice([b' ',b'\xff',b'0',b'/',b'"',b'\0',b'_',b'\n',b':',b','])
        roots.append(bytes(data))
    result += [dict(operation='decode',raw=enc(v)) for v in roots]
    for mode in ['exact','signed','operation']:
        for canonical in [False,True]:
            for signature in [None,enc(state.SEED)]:
                for account_key in [None,enc(state.PUB),enc(base64.b64encode(bytes(32)))]:
                    result.append(dict(operation='archive',mode=mode,canonical=canonical,seed=signature,account_key=account_key,raw=enc(raw(base))))
        for changes in [{'message':'unproved','encrypted_data':'ignored'}, {'message':3}, {'public_key':None}, {'unknown':'field'}, {'op_type':'call'}, {'op_type':None}, {'op_type':'unknown'}, {'amount':'0x11'}]:
            result.append(dict(operation='archive',mode=mode,canonical=False,seed=None,account_key=None,raw=enc(raw(base|changes))))
        for value in [raw(base)+b' ',b' '+raw(base),raw(base)[:-1]+b',"amount":"17"}',raw(base)[:-1]+b',"unknown":true}',b'{}',b'{',raw(base|{'timestamp':None})]:
            result.append(dict(operation='archive',mode=mode,canonical=False,seed=None,account_key=None,raw=enc(value)))
    for key in [b'',b'bad',base64.b64encode(bytes(32))]:
        result.append(dict(operation='archive',mode='signed',canonical=False,seed=None,account_key=enc(key),raw=enc(raw(base))))
    ops=[v['op_type']for v in state.cases() if v['operation']=='transaction' and v.get('seed')]
    result += [dict(operation='limits',op_type=op)for op in ops]
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);args=p.parse_args()
    pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    if subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()!=pin or args.out.exists():raise SystemExit('require pinned pristine sources and fresh output path')
    sources=['lib/core/transaction.ml','lib/core/tx_archive.ml','lib/core/tx_payload.ml','lib/core/crypto.ml','lib/core/compute_bill.ml'];hashes={};inputs=cases()
    with tempfile.TemporaryDirectory(prefix='octra-archive-oracle-')as temp:
        fixture=pathlib.Path(temp);(fixture/'cases.json').write_text(json.dumps(inputs));checks=[]
        for index,path in enumerate(sources):
            source=subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{path}'])
            if (args.upstream/path).read_bytes()!=source:raise SystemExit('modified native source '+path)
            (fixture/f'source-{index}').write_bytes(source);hashes[path]=hashlib.sha256(source).hexdigest();checks.append(f'cmp {path} /fixture/source-{index}')
        for name,index in [('archive',1),('payload',2)]:(fixture/f'native_{name}.ml').write_bytes(b'open Octra_core\n'+(fixture/f'source-{index}').read_bytes())
        shutil.copyfile(ROOT/'scripts/node-port/transaction-archive-oracle.ml',fixture/'main.ml');(fixture/'dune').write_text('(executable (name main) (libraries octra_core yojson base64))\n')
        command=' && '.join(checks+['mkdir vpn_archive_oracle','cp /fixture/main.ml /fixture/native_*.ml /fixture/dune vpn_archive_oracle/','opam exec -- dune exec ./vpn_archive_oracle/main.exe -- /fixture/cases.json'])
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={fixture},target=/fixture,readonly',args.builder_image,'bash','-lc',command],text=True)
    payload=next(line.removeprefix('ORACLE_RESULT=')for line in output.splitlines()if line.startswith('ORACLE_RESULT='))
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(dict(upstream_commit=pin,sources=hashes,oracle='native Yojson, Tx_payload, Tx_archive in isolated builder',cases=json.loads(payload)),indent=2)+'\n');print(f'Generated {len(inputs)} native archive cases: {args.out}')
if __name__=='__main__':main()
