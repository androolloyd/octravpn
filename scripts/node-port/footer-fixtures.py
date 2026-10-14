#!/usr/bin/env python3
"""Qualify native final epoch reward credits, emission metadata and rollback."""
import argparse,base64,copy,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v if isinstance(v,bytes) else str(v).encode()).decode()
MAX=10**15
def fixtures():
    validators=[dict(address=b64(a),key=b64('key-'+a),weight='1') for a in ['a','b','c']]
    base=dict(epoch=10,guard=False,activation=None,legacy=None,meta=[[b64('emission_remaining'),b64('0')],[b64('total_supply'),b64('10000')]],accounts=[dict(address=b64('sender'),balance='9000',nonce=1,key=None)],proposer=b64('a'),proposer_key=b64('key-a'),validators=validators,fallback=[[b64('b'),b64('fallback-b')]],fees='1000')
    out=[]
    def add(**kw):out.append(copy.deepcopy(dict(base,**kw)))
    for guard in [False,True]:
        for activation in [None,10,11]:
            for fees in [0,1,4,5,1000,10000,MAX]:add(guard=guard,activation=activation,fees=str(fees))
    for key in ['emission_remaining','total_supply','supply_retired']:
        for value in [None,'','bad','-1','0','1','10000',str(MAX),str(MAX+1)]:
            for guard in [False,True]:
                meta=[m for m in base['meta'] if m[0]!=b64(key)]
                if value is not None:meta.append([b64(key),b64(value)])
                add(meta=meta,guard=guard)
    for legacy in [None,'bad','-1','9000','10000',str(MAX)]:
        for guard in [False,True]:add(meta=[],legacy=None if legacy is None else b64(legacy),guard=guard)
    for proposer in ['a','b','p']:
        for key in [None,b64('explicit')]:
            for prior in [None,b64('existing')]:
                for validator_key in [None,b64('declared')]:
                    vals=copy.deepcopy(validators);vals[1]['key']=validator_key
                    add(proposer=b64(proposer),proposer_key=key,validators=vals,accounts=base['accounts']+[dict(address=b64('b'),balance='0',nonce=7,key=prior)])
    for vals in [[],[validators[0],validators[0]],[dict(validators[0],weight='0')],[dict(validators[0],weight='-1')],[dict(v,weight=str(i+1)) for i,v in enumerate(validators)]]:
        for fees in ['0','1','1000']:add(validators=vals,fees=fees)
    for remaining in [0,10000,MAX-10000]:
        for epoch in [9,10,11,47304010,(1<<62)-1]:
            for mask in range(16):
                meta=[[b64('emission_remaining'),b64(remaining)],[b64('total_supply'),b64(10000)]]
                fields=[('emission_standard','security_curve'),('emission_activation_epoch','10'),('emission_initial',str(remaining)),('supply_retired',str(MAX-10000-remaining))]
                for i,(k,v) in enumerate(fields):
                    if mask&(1<<i):meta.append([b64(k),b64(v)])
                add(activation=10,epoch=epoch,meta=meta)
    add(accounts=[dict(address=b64('sender'),balance=str(MAX),nonce=1,key=None)],meta=[[b64('total_supply'),b64(MAX)]],fees='1000')
    return out
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/footer-oracle.ml',fixtures(),'octra_core octra_node_runtime yojson base64 lwt.unix irmin')
    report['scope']='Native runtime epoch footer, weighted credits, key attribution, emission metadata and ledger/Irmin savepoint rollback'
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native epoch footer cases: {a.out}")
if __name__=='__main__':main()
