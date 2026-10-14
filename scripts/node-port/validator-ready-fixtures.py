"""Readiness through the native transaction sender and coupled savepoints."""
import argparse,copy,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts/node-port'/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
base=module('stake','validator-transaction-fixtures.py');native=module('native','native-oracle.py')
tx,round,case,b64=base.tx,base.round,base.case,base.b64
CHAIN='validator-transaction-fixture'
def ready(nonce=2,head=1,**kw):return tx('validator_ready',nonce=nonce,head=head,**kw)
def parent(epoch):return dict(chain=b64(CHAIN),epoch=str(epoch),round=1,members=4,signers=[1,2,3])
def active(epoch,txs,**kw):
    v=round(epoch,txs,duty_active=True,ready_active=True,ref_active=True,exec_active=True,live_active=True,config=b64('b'*64),parent=parent(epoch-1));v.update(kw);return v
def claim(head,**kw):
    v=dict(chain_id=CHAIN,config_hash='b'*64,catchup_head_epoch=str(head));v.update(kw);return v
def fixtures():
    cases=[]
    def bonded(rounds):cases.append(case([round(1,[tx()])]+rounds,readiness=True))
    # Pre-activation root validation, delayed references and native normalization.
    for changes in [dict(),dict(head=2),dict(head=-1),dict(root=b64('wrong')),dict(root=b64('a'*64+'suffix')),dict(key=b64('bad')),dict(to=2),dict(amount='1'),dict(ou='10000000')]:
        bonded([round(2,[ready(**changes),ready(nonce=3)])])
    for roots in [None,{'1':b64('a'*64)},{'1':b64('bad')},{}]:
        bonded([round(4,[ready()],roots=roots),round(5,[ready()])])
    for prior in [True,False]:
        for catchup in [None,'0','1','2']:
            extra=claim(1,catchup_head_epoch=catchup)
            bonded([round(2,[ready(extra=extra)],ready_active=True,ref_active=not prior,config=b64('b'*64))])
    for config in [None,b64('c'*64),b64('b'*64)]:
        for extra in [{},claim(1),claim(1,chain_id='wrong'),claim(1,config_hash='c'*64)]:
            bonded([active(2,[ready(proposal='auto',extra=extra)],config=config,active=[1])])
    # Delivery window references old finalized proposals, not caller-supplied roots.
    for epoch in [6,7,8,9]:
        bonded([active(epoch,[ready(head=5,proposal='auto',extra=claim(5))],parent=parent(5),record_final=True,active=[1])])
    for meta in [[dict(key='bft.validator_duty',value=b64('{'))],[dict(key='bft.validator_registry',value=b64('{'))]]:
        bonded([active(2,[ready(proposal='auto',extra=claim(1))],meta=meta,active=[1])])
    # Real signed duty proof and owner mismatch, finalized reference missing.
    for record in [False,True]:
        for owner in [1,2]:
            bonded([active(2,[ready(proposal='auto',extra=claim(1),proof=True,proof_owner=owner)],record_final=record,active=[1])])
    # Rejoining candidate must pulse for 64 epochs before registry readiness is marked.
    for standard in [False,True]:
        bonded([active(epoch,[ready(nonce=epoch,head=epoch-1,proposal='auto',extra=claim(epoch-1))],standard_active=standard) for epoch in range(2,69)])
    # Replay credits, same-epoch nonce progression, and delayed inclusion do not age pulses twice.
    bonded([active(2,[ready(proposal='auto',extra=claim(1)),ready(nonce=3,proposal='auto',extra=claim(1))]),active(3,[ready(nonce=4,proposal='auto',extra=claim(1))],parent=parent(1),record_final=True)])
    for duty,reference,live in [(False,True,True),(True,False,False),(True,True,False),(True,False,True)]:
        bonded([active(2,[ready(proposal='auto',extra=claim(1))],duty_active=duty,ref_active=reference,live_active=live,standard_active=True)])
    # Legacy readiness and bonded fallback preserve exact metadata field order.
    for inactive in [True,False]:
        for changes in [dict(),dict(extra=claim(1,binary_hash='c'*64,shadow_epochs='3')),dict(fingerprint=b64('0'*64)),dict(head=2),dict(legacy=False),dict(to=2)]:
            cases.append(case([round(2,[ready(nonce=1,legacy=True,**{k:v for k,v in changes.items() if k!='legacy'})] if changes.get('legacy',True) else [ready(nonce=1)],pending=True)],inactive=inactive,readiness=True))
    for inactive in [True,False]:
        cases.append(case([round(2,[ready(nonce=1,legacy=True)])],inactive=inactive,readiness=True))
    for raw in ['{}','{','[]','{"duty_vote":"bad"}']:
        bonded([active(2,[ready(raw_message=b64(raw))])])
    # A prior successful transaction must roll back when a later readiness anchor fails.
    cases.append(case([round(64,[tx(sender=1),ready(sender=2,nonce=1)],fold_fail=True)],readiness=True))
    return cases
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/validator-ready-oracle.ml',fixtures(),'octra_core octra_node_runtime octra_consensus yojson lwt.unix mirage-crypto-ec')
    report['scope']='Native readiness execution, fee/nonce rollback, roots, registry/duty persistence and legacy metadata; trusted rule context injected. Native-produced transactions, parent wire and setup metadata are execution inputs.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native readiness sequences')
if __name__=='__main__':main()
