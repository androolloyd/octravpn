#!/usr/bin/env python3
"""Differential traces for native ordered proposal recovery; no mock proof claims."""
import argparse, hashlib, importlib.util, json, pathlib, random
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

def fixtures():
    out = []
    def case(senders, responses, cap=100, name='script'):
        nonces = {}
        txs = []
        for i,sender in enumerate(senders):
            nonces[sender] = nonces.get(sender,0)+1
            txs.append(dict(id=i, **{'from':'oct_'+sender}, nonce=nonces[sender]))
        out.append(dict(name=name, txs=txs, responses=responses, cap=cap))
    case('', [], name='empty')
    case('abc', [], name='all-confirmed')
    case('aab', [{'status':['reject','ok','ok']}, {'status':['reject','ok','ok']}], name='nonce-successor-cutoff')
    case('abc', [{'status':['paid','reject','ok']}], name='paid-and-unpaid')
    case('abc', [{'status':['reject','ok','ok']}], cap=1, name='refill')
    case('abc', [{'status':['exhausted','ok','ok']}], name='resource')
    case('aab', [{'status':['unavailable','ok','ok']}], name='unavailable-sender')
    case('ab', [{'unknown_resource':True}], name='unknown-resource')
    case('ab', [{'duplicate':True}], name='invalid-partition')
    case('ab', [{'revoke':True}], name='revoked')
    case('abc', [{'status':['reject','reject','reject']}, {'fail':True}], name='failure')
    # Exercise shrinking partitions, repeated failures, reserve holds and refill.
    rng = random.Random(0x7f9be448)
    for i in range(650):
        count = rng.randint(1,9)
        senders = ''.join(sorted(rng.choices('abcd',k=count)))
        statuses = ['ok','ok','ok','reject','unavailable','exception','paid','exhausted']
        responses = [dict(status=rng.choices(statuses,k=count)) for _ in range(6)]
        if i%37 == 0: responses[rng.randrange(6)]['fail']=True
        if i%41 == 0: responses[rng.randrange(6)]['revoke']=True
        if i%43 == 0: responses[rng.randrange(6)]['unknown_resource']=True
        if i%47 == 0: responses[rng.randrange(6)]['duplicate']=True
        case(senders,responses,cap=rng.randint(1,count),name=f'random-{i}')
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--upstream',type=pathlib.Path,required=True)
    p.add_argument('--builder-image',required=True)
    p.add_argument('--out',type=pathlib.Path,required=True)
    a=p.parse_args()
    if a.out.exists(): raise SystemExit('require fresh report')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/proposal-build-oracle.ml',fixtures(),'octra_node_runtime octra_core octra_consensus yojson lwt.unix')
    report['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    report['scope']='Unmodified native make_proposal ordered control flow with scripted preview outcomes. Compares exact selection/retry traces, rejection bytes, evictions and holds. Does not qualify transaction execution, proofs, queue admission, frozen rounds or consensus.'
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(report['cases']),'native proposal recovery cases')
if __name__=='__main__': main()
