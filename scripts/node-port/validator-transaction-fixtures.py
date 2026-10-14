"""Native validator money/state operations through Epoch_exec and savepoints."""
import argparse,base64,copy,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v.encode()).decode()
def tx(op='validator_bond',sender=1,nonce=1,**kw):
    v=dict(op=op,nonce=nonce,amount='1000000' if op=='validator_bond' else '0',ou='7',to='escrow' if op=='validator_bond' else sender,**{'from':sender});
    if op=='validator_evidence':v.update(offender=1,vote_epoch=2)
    v.update(kw);return v
def round(epoch,txs,**kw):
    v=dict(epoch=epoch,transactions=txs,meta=[],active=[],legacy_active=[],standard_active=False,exit_active=False);v.update(kw);return v
def case(rounds,**kw):
    v=dict(chain=b64('validator-transaction-fixture'),accounts=[dict(id=id,balance='10000000',nonce=0)for id in range(1,5)],rounds=rounds);v.update(kw);return v
def slash(nonce=1,**kw):return tx('validator_evidence',sender=2,nonce=nonce,to=1,offender=1,vote_epoch=2,**kw)
def supply(total='40000000',remaining='999999960000000',retired='0'):
    return [dict(key=k,value=b64(v))for k,v in [('total_supply',total),('emission_remaining',remaining),('supply_retired',retired)]]
def fixtures():
    cases=[case([round(1,[tx()]),round(2,[tx('validator_exit',nonce=2)]),round(129,[tx('validator_withdraw',nonce=3)]),round(130,[tx('validator_withdraw',nonce=3)],legacy_active=[1]),round(130,[tx('validator_withdraw',nonce=3)]),round(131,[tx(nonce=4)])]),
           case([round(1,[tx(),tx(nonce=2)]),round(64,[slash()],meta=supply()),round(65,[slash(nonce=2)]),round(66,[tx(nonce=3)]),round(67,[slash(nonce=2)])]),
           case([round(1,[tx()]),round(2,[tx('validator_exit',nonce=2)]),round(8193,[tx('validator_withdraw',nonce=3)],exit_active=True),round(8194,[tx('validator_withdraw',nonce=3)],exit_active=True)]),
           case([round(1,[tx()]),round(2,[tx('validator_exit',nonce=2)]),round(130,[tx('validator_withdraw',nonce=3)],drain_escrow=True)]),
           case([round(1,[tx()]),round(64,[slash()],meta=supply(),drain_escrow=True)])]
    for changes in [dict(to=1),dict(amount='999999'),dict(amount='20000000'),dict(raw_message=b64('{')),dict(raw_message=b64('{}')),dict(proof_amount='999999'),dict(ou='10000000'),dict(nonce=2)]:
        cases.append(case([round(1,[tx(**changes),tx(nonce=2)])]))
    for op in ['validator_bond','validator_exit','validator_withdraw','validator_evidence','validator_set_update']:
        cases.append(case([round(1,[tx(op)])],inactive=True))
    for op in ['validator_exit','validator_withdraw']:
        for changes in [dict(amount='1'),dict(to=2),dict()]:cases.append(case([round(1,[tx(op,**changes)])]))
    for changes in [dict(vote_epoch=65),dict(vote_epoch=0),dict(vote_epoch=-1),dict(raw_message=b64('{}'))]:
        s=slash();s.update(changes);cases.append(case([round(1,[tx()]),round(64,[s],meta=supply())]))
    cases += [case([round(1,[tx()]),round(63,[slash()],meta=supply())]),case([round(1,[tx()]),round(102,[slash()],meta=supply())]),case([round(1,[tx()]),round(64,[slash()],meta=supply('1','999999999999999'))])]
    for meta in [[],supply('bad'),supply('-1'),supply(remaining='0'),supply(retired='bad'),[dict(key='bft.validator_registry',value=b64('{'))]]:
        cases.append(case([round(1,[tx()]),round(64,[slash()],meta=meta)]))
    cases.append(case([round(1,[tx()],meta=[dict(key='bft.validator_registry',value=b64('{'))])]))
    for standard,active,legacy in [(False,[],[1]),(True,[1],[]),(True,[],[1])]:
        cases.append(case([round(1,[tx()]),round(2,[tx('validator_exit',nonce=2)]),round(130,[tx('validator_withdraw',nonce=3)],standard_active=standard,active=active,legacy_active=legacy)]))
    cases.append(case([round(1,[tx()]),round(2,[tx('validator_exit',nonce=2)]),round(130,[tx('validator_withdraw',nonce=3)],fold_fail=True)]))
    # Operational failure after another sender succeeds must roll back the batch.
    cases.append(case([round(64,[tx(sender=1),slash()],fold_fail=True)]))
    rng=random.Random(2026101318)
    for _ in range(48):
        rounds=[round(1,[tx(sender=id)for id in range(1,5)])]
        for epoch in [2,3,64,130,132]:
            txs=[]
            for _ in range(9):
                op=rng.choice(['validator_bond','validator_exit','validator_withdraw','validator_set_update'])
                t=tx(op,sender=rng.randrange(1,5),nonce=rng.randrange(1,5));txs.append(t)
            rounds.append(round(epoch,txs,active=rng.choice([[],[1,2]]),standard_active=rng.choice([True,False])))
        cases.append(case(rounds))
    return cases

def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/validator-transaction-oracle.ml',fixtures(),'octra_core octra_node_runtime octra_consensus yojson lwt.unix mirage-crypto-ec')
    report['scope']='Unmodified native Epoch_exec validator bond, exit, withdraw, evidence and disabled manual update paths under real ledger/store savepoints and sender loop; trusted fold inputs injected. Native-generated signed proof transactions are supplied as execution inputs.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native validator transaction sequences')
if __name__=='__main__':main()
