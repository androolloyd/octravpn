#!/usr/bin/env python3
"""Compare Circle paths, raw metadata, policy and snapshot lookup against adopted native sources."""
import argparse, base64, hashlib, itertools, json, pathlib, random, shutil, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
def b64(raw): return base64.b64encode(raw).decode()
def raw(value): return json.dumps(value,separators=(',',':')).encode()
def digest(tag,*parts):
    return hashlib.sha256(tag+b'\0'+b''.join(len(p).to_bytes(4,'big')+p for p in parts)).hexdigest()
def meta(path=b'/index.html'):
    return dict(path_key=digest(b'octra:asset_path:v1',path),canonical_path=path.decode(),content_type='text/html',encoding='identity',size_bytes='5',blob_hash=hashlib.sha256(b'hello').hexdigest(),body_mode='public_resources',resource_key=digest(b'octra:circle_resource_key:v1',b'circle',path))
def fixtures():
    out=[];rng=random.Random(8176)
    paths=[b'',b'/',b'file',b'///a/./b/',b'a/../b',b'/%2E%2e',b'/%252e',b'/a%2Fb',b'/%',b'/%0',b'/%GG',b'/%\xffa',b'/\xff',b'/%ff',b'/%00',b'/%C0%80',b'/%ED%A0%80',b'/%F4%8F%BF%BF',b'/%F4%90%80%80',b'/a?x#y',b'\\foo',b'/' + b'x'*1023,b'/' + b'x'*1024]
    paths += [rng.randbytes(rng.randrange(0,80)) for _ in range(128)]
    paths += [('/'+'/'.join(rng.choices(['a','b','%25','%2e','%E2%82%AC','','.','..'],k=8))).encode() for _ in range(100)]
    for path in paths:out.append(dict(op='path',path=b64(path),circle=b64(b'circle\xff')))
    m=meta();metas=[raw(m),b'[]',b'null',b'{',b'{"expire_after_epoch":"bad"}',raw(dict(m,content_type='one'))[:-1]+b',"content_type":"two"}',raw(m).replace(b'text/html',b'text/\xff')]
    for key in m:
        for value in [None,3,False,{},[], '']:
            x=dict(m);x[key]=value;metas.append(raw(x))
        x=dict(m);del x[key];metas.append(raw(x))
    for key in ['plaintext_hash','key_id','padding_class','resource_key','locator_mode','slot_ref','activate_after_epoch','expire_after_epoch','metadata_mode']:
        for value in [None,3,False,'','0','path','opaque_slot','private_state','reveal','opaque','0x7fffffffffffffff','-9223372036854775808','9223372036854775808','bad']:
            metas.append(raw(dict(m,**{key:value})))
    for key in ['size_bytes','activate_after_epoch','expire_after_epoch']:
        for value in ['0','-1','+1','0xFFFFFFFFFFFFFFFF','0u18446744073709551615','1_2','_1',' 1','1 ','bad']:
            metas.append(raw(dict(m,**{key:value})))
    metas += [b'{"path_key":3,"expire_after_epoch":"bad"}',raw(dict(m,size_bytes='bad',body_mode='unknown')),raw(dict(m,body_mode='sealed_read',locator_mode='private_state',metadata_mode='opaque'))]
    out += [dict(op='meta',meta=b64(v)) for v in metas]
    vals=[None,b'0',b'3',b'4',b'5',b'bad',b' YES\n',b'\x0btrue\x0b',b'\x0ctrue\x0c',b'false',b'1',b'TrUe',b'-1',b'0x7fffffffffffffff']
    for _ in range(256):
        x=dict(m,activate_after_epoch=rng.choice([None,'2','4','-1']),expire_after_epoch=rng.choice([None,'3','5','-1']))
        case=dict(op='policy',meta=b64(raw(x)),epoch=str(rng.choice([-1,0,2,3,4,5,2**63-1])))
        for key in ['activate','expire','tombstone','revoked']:
            val=rng.choice(vals);case[key]=None if val is None else b64(val)
        out.append(case)
    def entries(metadata=raw(m),body=b'aGVsbG8='):
        base=[b'circles',b'circle'];asset=base+[b'assets',b'by_hash',m['path_key'].encode()]
        return [dict(path=list(map(b64,p)),value=b64(v)) for p,v in [(base+[b'browser',b'mode'],b'gateway_allowed'),(base+[b'resources',b'mode'],b'public_resources'),(asset+[b'meta'],metadata),(asset+[b'body_b64'],body)]]
    def asset(es,limit=5,path=b'/index.html'):
        return dict(op='asset',circle=b64(b'circle'),path=b64(path),max_bytes=limit,entries=es)
    out += [asset(entries(),limit) for limit in [-1,0,4,5,6]]
    out += [asset(entries()[:i]+entries()[i+1:]) for i in range(4)]
    for value in metas:out.append(asset(entries(value)))
    out += [asset(entries(raw(dict(m,canonical_path='/wrong')))),asset(entries(raw(dict(m,path_key='wrong')))),asset(entries(),-1,b'../bad'),asset(entries(),5,b'../bad'),asset(entries(),5,b'/%69ndex.html')]
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if pin!=inventory['upstream_commit'] or a.out.exists():raise SystemExit('require adopted pin and fresh output')
    for name,h in inventory['files'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=h:raise SystemExit(f'modified upstream: {name}')
    inputs=fixtures();oracle=ROOT/'scripts/node-port/circle-assets-oracle.ml'
    with tempfile.TemporaryDirectory(prefix='octra-circle-assets-') as temporary:
        work=pathlib.Path(temporary);shutil.copyfile(oracle,work/'main.ml')
        (work/'dune').write_text('(executable (name main) (libraries octra_core lwt.unix yojson base64 irmin))\n')
        (work/'input.json').write_text(json.dumps(inputs));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && mkdir vpn_circle_assets_oracle && cp /oracle/main.ml /oracle/dune vpn_circle_assets_oracle/ && opam exec -- dune exec ./vpn_circle_assets_oracle/main.exe < /oracle/input.json'],text=True)
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,scope='Native path, metadata, visibility policy and immutable Irmin asset lookup; browser disclosure policy is separately tested',cases=json.loads(output.splitlines()[-1]))
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(inputs)} native Circle asset cases: {a.out}')
if __name__=='__main__':main()
