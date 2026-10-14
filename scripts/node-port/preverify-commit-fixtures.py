#!/usr/bin/env python3
"""Native epoch receipt admission, rejection order, budgets and activation."""
import argparse,base64,copy,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def tx(op='encrypt',nonce=1,ou='3000'):return dict(op=op,nonce=nonce,ou=ou)
def receipt(index=0,kind='bound',**kw):return dict(dict(index=index,kind=kind,remove=[],set={}),**kw)
def case(txs,receipts,**kw):return dict(dict(transactions=txs,receipts=receipts,crypto=True,budget=None,activation=None,epoch=1),**kw)
def fixtures():
    out=[]
    for op in 'standard encrypt decrypt private stealth claim key_switch recrypt circle_call circle_balance_cell_put circle_register_cell_put program_exec'.split():
      for kind in ['legacy','bound','transition','circle']:
       for crypto in [False,True]:out.append(case([tx(op)],[receipt(kind=kind)],crypto=crypto))
    base=case([tx(),tx(nonce=2)],[receipt(),receipt(1)])
    for txs in [[],[tx()],[tx(),tx()],[tx('standard')],base['transactions']]:
      for rs in [[],[receipt()],[receipt(),receipt()],base['receipts'],[receipt(1),receipt()]]:
       if any(r['index']>=len(txs)for r in rs):continue
       out.append(case(txs,rs))
    for field,values in dict(tx_hash=['0'*64,'bad'],lane=['fhe','program','pvac'],engine=['fhe_preverify_v2','bad'],input_hash=['0'*64,'bad'],output_hash=['0'*64,'bad'],ok=[False,None],reason=['bad','x'*129],cost=[dict(txs=1,bytes=123,ou='3000',proof=1),dict(txs=2,bytes=0,ou='0',proof=1)],pre_state_hash=['bad']).items():
      for value in values:
       for index in [0,1]:
        v=copy.deepcopy(base);v['receipts'][index]['set'][field]=value;out.append(v)
    for field in ['tx_hash','cost','schema','pre_state_hash']:
      v=copy.deepcopy(base);v['receipts'][0]['remove']=[field];out.append(v)
    for raw in [b'bad',b'[]',b'{}']:
      out.append(case([tx()],[dict(raw=base64.b64encode(raw).decode())]))
    # Duplicate detection precedes receipt validation, preserving arbitrary
    # native string bytes in the duplicate-hash diagnostic.
    raw=json.dumps(dict(schema='octra_preverify_receipt_v1',tx_hash='x',lane='pvac',engine='pvac_preverify_v1',input_hash='a'*64,output_hash='b'*64,ok=True,reason='',cost=dict(txs=1,bytes=0,ou='0',proof=1)),separators=(',',':')).encode().replace(b'"x"',b'"\xff"')
    encoded=dict(raw=base64.b64encode(raw).decode());out.append(case([],[encoded,encoded]))
    for field,values in dict(txs=[0,1,2],bytes=[0,1,100,1000],ou=['0','1','5999','6000','10000000'],proof=[0,1,2]).items():
      for value in values:
       budget=dict(txs=10,bytes=100000,ou='10000000',proof=10);budget[field]=value;out.append(dict(base,budget=budget))
    for activation in [None,'','-1','0','1','2','0x10','0u4611686018427387904','4611686018427387903','4611686018427387904','bad','1_0']:
      for epoch in [-1,0,1,2,10,(1<<62)-1]:out.append(case([],[],activation=activation,epoch=epoch))
    rng=random.Random(14713)
    for _ in range(300):
      txs=[tx(rng.choice(['encrypt','stealth','circle_call','key_switch','standard']),rng.randrange(1,6),rng.choice(['0','3000','10000000']))for _ in range(rng.randrange(1,6))]
      rs=[receipt(rng.randrange(len(txs)),rng.choice(['legacy','bound','transition','circle']))for _ in range(rng.randrange(6))]
      if rs and rng.randrange(3)==0:rs[0]['set']['input_hash']='0'*64
      out.append(case(txs,rs,crypto=rng.choice([False,True])))
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/preverify-commit-oracle.ml',fixtures(),'octra_core yojson base64')
    report['scope']='Native epoch receipt admission with duplicates, orphan receipts, exact transaction bindings, resource budgets and receipt activation. Live ledger source checks and cryptographic execution are not exercised.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native receipt gate cases: {a.out}")
if __name__=='__main__':main()
