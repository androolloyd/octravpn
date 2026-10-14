#!/usr/bin/env python3
"""Qualify native outcome encoding, candidate reconstruction and envelope gates."""
import argparse, base64, hashlib, json, pathlib, random, shutil, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
def b64(value): return base64.b64encode(value if isinstance(value,bytes) else value.encode()).decode()
def packed(value): return b64(json.dumps(value,separators=(',',':'),ensure_ascii=True))
def address(key):
    alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n=int.from_bytes(hashlib.sha256(key).digest(),'big'); value=''
    while n: n,r=divmod(n,58); value=alphabet[r]+value
    return 'oct'+value.rjust(44,'1')
def transaction(nonce=1, sender=1, op='standard', **fields):
    key=bytes([sender])*32
    tx=dict(from_=address(key),to_='oct'+'1'*44,amount='1',nonce=nonce,ou='1000000',timestamp=10.0,signature=b64(bytes(64)),op_type=op,public_key=b64(key))
    tx['from']=tx.pop('from_'); tx.update(fields); return packed(tx)
def rejection(tx,position=0,error_type=b'failed',reason=b'rejected',charged=False,**fields):
    return dict(position=position,tx=tx,error_type=b64(error_type),reason=b64(reason),charged=charged,**fields)
def fixtures():
    out=[]; rng=random.Random(20261013)
    texts=[b'',b'error',b'vm_exception',b'x_exception',b'\xff_exception',b'\0',bytes(range(256))]
    texts += [b'a'*n for n in [1,52,53,54,127,128,129,511,512,513,1024]]
    texts += [bytes([i]) for i in range(256)]
    for value in texts: out.append(dict(op='normalize',error_type=b64(value),reason=b64(value[::-1])))
    for _ in range(100): out.append(dict(op='normalize',error_type=b64(rng.randbytes(rng.randrange(1024))),reason=b64(rng.randbytes(rng.randrange(1200)))))
    base=transaction()
    for position in [-1,0,1,2047,2048,(1<<62)-1]:
      for charged in [False,True]:
        r=rejection(base,position,charged=charged); out.append(dict(op='encode',rejection=r))
        for admit in [False,True]: out.append(dict(op='parse',raw=r,admit=admit))
    for mutation in ['space','trailing','unknown','order','duplicate','false','hash','position_float','position_literal','txbad']:
      for charged in [False,True]: out.append(dict(op='parse',raw=rejection(base,charged=charged,mutation=mutation),admit=False))
    for value in texts:
      for field in ['error_type','reason']:
        r=rejection(base); r[field]=b64(value); out.append(dict(op='parse',raw=r,admit=False))
    for op,fields in [('standard',{'message':'a'*257}),('compute_return',{'message':'a'*65}),('validator_bond',{'message':'{}'}),('circle_call',{'message':'[]'}),('standard',{'public_key':None})]:
      for admit in [False,True]: out.append(dict(op='parse',raw=rejection(transaction(op=op,**fields)),admit=admit))
    for raw in [b'null',b'[]',b'true',b'{}',b'42',b'"raw"',b'{"schema":"other"}',b'{"schema":"octra_epoch_rejection"}',b'{"schema":null}',b'NaN',b'/* comment */{}',b'{"key":"\xff"}']:
      out.append(dict(op='parse',raw=b64(raw),admit=False))
    txs=[transaction(i) for i in range(1,9)]
    preverify=[b64(b'{}'),b64(b'{"schema":"preverify"}')]
    for _ in range(100):
      inputs=rng.sample(txs,rng.randrange(9)); rng.shuffle(inputs)
      rejected=rng.sample(inputs,rng.randrange(len(inputs)+1)); charged=rng.sample(inputs,rng.randrange(len(inputs)+1))
      out.append(dict(op='build',inputs=inputs,charged=charged,rejected=[rejection(tx,error_type=rng.choice(texts),reason=rng.choice(texts)) for tx in rejected]))
    for inputs,rejected in [([base,base],[base]),([base],[transaction(99)]),([base],[base,base])]:
      out.append(dict(op='build',inputs=inputs,rejected=[rejection(tx) for tx in rejected],charged=[]))
    for _ in range(140):
      count=rng.randrange(9); positions=rng.sample(range(count),rng.randrange(count+1)); positions.sort()
      rs=[rejection(txs[p],p,charged=rng.choice([False,True])) for p in positions]
      confirmed=[txs[p] for p in range(count) if p not in positions]
      out.append(dict(op='merge',confirmed=confirmed,rejections=rs))
      out.append(dict(op='decode',confirmed=confirmed,raws=preverify+rs,admit=False))
      if rs:
        out.append(dict(op='split',raws=rs+preverify,admit=False))
        out.append(dict(op='merge',confirmed=list(reversed(confirmed)),rejections=list(reversed(rs))))
    for positions in [[-1],[0,0],[1,0],[0,2],[2,3],[2047],[2048]]:
      for count in [0,1,2]: out.append(dict(op='merge',confirmed=txs[:count],rejections=[rejection(txs[min(i+count,7)],p) for i,p in enumerate(positions)]))
    for raws in [[rejection(base,0),rejection(base,1)],[rejection(base,1),rejection(transaction(2),0)],[rejection(base,0)]*2049]: out.append(dict(op='split',raws=raws,admit=False))
    for count in [2048,2049]: out.append(dict(op='merge',confirmed=[base]*count,rejections=[]))
    out.append(dict(op='merge',confirmed=[transaction(2),base],rejections=[]))
    out.append(dict(op='merge',confirmed=[base,base],rejections=[]))
    for envelope in [False,True]:
      for compute in [False,True]:
        for settle in [False,True]:
          for op in ['standard','compute_fund','compute_return','compute_settle']:
            tx=transaction(op=op)
            for charged in [False,True]:
              out.append(dict(op='envelope',envelope=envelope,compute=compute,settle=settle,confirmed=[],raws=[rejection(tx,charged=charged)]))
            out.append(dict(op='envelope',envelope=envelope,compute=compute,settle=settle,confirmed=[tx],raws=[]))
    for confirmed in [[base,transaction(1,amount='2')],[transaction(public_key=None)],[transaction(signature='')],[transaction(public_key=b64(bytes([1])*32)+ '====')]]:
      out.append(dict(op='envelope',envelope=True,compute=True,settle=True,confirmed=confirmed,raws=[]))
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if a.out.exists() or pin!=inventory['upstream_commit']:raise SystemExit('require adopted pin and fresh output')
    for name,h in inventory['files'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=h:raise SystemExit(f'modified upstream: {name}')
    oracle=ROOT/'scripts/node-port/outcome-oracle.ml';inputs=fixtures()
    with tempfile.TemporaryDirectory(prefix='octra-outcome-') as directory:
        work=pathlib.Path(directory);shutil.copyfile(oracle,work/'main.ml')
        shutil.copyfile(a.upstream/'lib/core/tx_outcome.ml',work/'native_outcome.ml')
        shutil.copyfile(a.upstream/'lib/core/tx_envelope.ml',work/'native_envelope.ml')
        (work/'dune').write_text('(executable (name main) (flags (:standard -open Octra_core)) (libraries octra_core yojson base64))\n')
        (work/'input.json').write_text(json.dumps(inputs));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && cmp lib/core/tx_outcome.ml /oracle/native_outcome.ml && cmp lib/core/tx_envelope.ml /oracle/native_envelope.ml && mkdir vpn_outcome_oracle && cp /oracle/main.ml /oracle/native_outcome.ml /oracle/native_envelope.ml /oracle/dune vpn_outcome_oracle/ && opam exec -- dune exec ./vpn_outcome_oracle/main.exe < /oracle/input.json'],text=True)
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,scope='Native outcomes and rule-selected envelope gates; malformed JSON diagnostic parity and preverify receipt execution are separate',cases=json.loads(output.splitlines()[-1]))
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(inputs)} native outcome cases: {a.out}')
if __name__=='__main__':main()
