"""Offline native validator lifecycle traces and malformed persisted state."""
import argparse, base64, copy, importlib.util, json, pathlib, random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(raw):return base64.b64encode(raw.encode() if isinstance(raw,str) else raw).decode()
PARAM=dict(min='1000000',max=4,delay='64',wait='128')
CHAIN=b64('validator-parity\x00chain')
def bond(id=1,epoch=1,**kw):return dict(op='bond',address=id,key=id,sender=id,epoch=str(epoch),amount='1000000',nonce=1,chain=CHAIN,**kw)
def ready(id=1,epoch=2):return dict(op='ready',address=id,key=id,epoch=str(epoch))
def slash(id=1,epoch=10,**kw):return dict(op='slash',offender=id,signer=id,epoch=str(epoch),vote_epoch='5',round=1,chain=CHAIN,expected_chain=CHAIN,window='100',**kw)
def fixtures():
    rng=random.Random(2026101317);cases=[]
    # Exact due epoch, active membership gate, replay and rebond isolation.
    steps=[bond(),bond(),ready(),ready(epoch=3),dict(op='exit',address=1,epoch='4'),bond(),ready(),dict(op='exit',address=1,epoch='5')]
    steps += [dict(op='withdraw',address=1,epoch=e,active=a) for e,a in [('131',[]),('132',[1]),('132',[]),('133',[])]]
    steps += [bond(epoch=140),slash(epoch=145),ready(epoch=141),dict(op='reload')]
    cases.append(dict(kind='sequence',parameters=PARAM,steps=steps))
    steps=[bond(),slash(),slash(),bond(epoch=11),slash(epoch=12),slash(epoch=13)]
    steps[-1]['vote_epoch']='12'
    cases.append(dict(kind='sequence',parameters=PARAM,steps=steps))
    for mutate in ['window','future','expired','chain','bad_signature','other_signer','predates']:
        s=slash()
        if mutate=='window':s['window']='0'
        if mutate=='future':s['vote_epoch']='11'
        if mutate=='expired':s['epoch']='105'
        if mutate=='chain':s['expected_chain']=b64('other')
        if mutate=='bad_signature':s['corrupt']=True
        if mutate=='other_signer':s['signer']=2
        if mutate=='predates':s['vote_epoch']='0'
        cases.append(dict(kind='sequence',parameters=PARAM,steps=[bond(),s,dict(op='reload')]))
    for field,value in [('amount','999999'),('amount','-1'),('epoch','-1'),('sender','bad'),('sender',2),('corrupt',True),('proof_amount','1000001'),('nonce',2)]:
        s=bond();s[field]=value
        cases.append(dict(kind='sequence',parameters=PARAM,steps=[s]))
    cases.append(dict(kind='sequence',parameters=PARAM,steps=[bond(1),dict(bond(2),key=1,sender=1),dict(bond(1),key=2,sender=2)]))
    cases.append(dict(kind='sequence',parameters=PARAM,steps=[bond(epoch=5),ready(epoch=4),dict(op='reload'),dict(op='exit',address=1,epoch='3'),dict(op='reload')]))
    for _ in range(96):
        steps=[bond(n) for n in range(1,7)]+[ready(n) for n in range(1,7)]+[dict(op='snapshot',epoch='66')]
        for _ in range(28):
            id=rng.randrange(1,8);epoch=rng.choice([-1,0,1,2,10,66,130,132,200,2**63-1]);op=rng.choice(['bond','ready','exit','withdraw','slash','reload','snapshot'])
            if op=='bond':
                step=bond(id,epoch);step['amount']=rng.choice(['1000000','2000000','1','100000000000000000000000000000000000'])
                if rng.randrange(4)==0:step['proof_amount']='7'
            elif op=='ready':step=ready(id,epoch);step['key']=rng.choice([id,id,2,'bad'])
            elif op=='withdraw':step=dict(op=op,address=id,epoch=str(epoch),active=rng.choice([[],[id],[1,2,3]]))
            elif op=='slash':step=slash(id,epoch);step['vote_epoch']=str(rng.choice([0,1,5,128,201]));step['window']=rng.choice(['0','1','100','9223372036854775807'])
            else:step=dict(op=op,address=id,epoch=str(epoch))
            steps.append(step)
        cases.append(dict(kind='sequence',parameters=PARAM,steps=steps))
    # Snapshot order, weighted AND count quorum, incumbent retention, byte strings.
    for idx in range(200):
        candidates=[dict(address=b64(bytes([n+1,255,0])),key=b64(bytes([n])*32),bond=str(rng.choice([1,1000000,2000000,10**60])),bonded=str(rng.choice([0,1,10])),ready=rng.choice([None,'0','10','70']),exit=rng.choice([None,None,None,'20'])) for n in range(rng.choice([0,3,4,5,7,12]))]
        if idx%3==0:
            for c in candidates:c.update(bonded='0',ready='1',exit=None,bond='1000000')
        if candidates and idx%11==0:candidates.append(copy.deepcopy(candidates[0]))
        if candidates and idx%13==0:candidates[-1]['key']=b64(b'')
        rng.shuffle(candidates)
        params=dict(PARAM)
        if idx%7==0:params['max']=3
        if idx%17==0:params['min']='0'
        if idx%19==0:params['delay']='0'
        if idx%23==0:params['wait']='-1'
        signers=[c['address'] for c in candidates[:rng.randrange(len(candidates)+1)]]
        if idx%5==0:signers+=signers
        if idx%17==1:signers.append(b64('unknown'))
        cases.append(dict(kind='snapshot',parameters=params,candidates=candidates,activate=rng.choice(['63','64','65','134','9223372036854775807']),incumbents=[c['address'] for c in candidates[-2:]],seed=b64(b'\xff\x00seed') if idx%19 else '',epoch='7' if idx%23 else '-1',round=idx if idx%29 else -1,signers=signers))
    for raw in [None,'','63','64','128','0x100','1_024','-1','garbage','4611686018427387903','4611686018427387904','0u9223372036854775807']:
        for source in [-1,0,63,64,65,128,2**63-1]:
            cases.append(dict(kind='policy',raw=None if raw is None else b64(raw),source=str(source),cadence=str(rng.choice([0,1,64,-1])),delay=str(rng.choice([1,64,128])),window='86400',active=rng.choice([True,False])))
    candidate=dict(address='oct'+'1'*44,consensus_pubkey=b64(bytes(32)),bond='1000000',bonded_epoch='1',ready_epoch=None,exit_epoch=None)
    registry=dict(standard='bonded_stake',candidates=[candidate],slashes=[])
    def decode(value):cases.append(dict(kind='decode',raw=b64(json.dumps(value))))
    for value in [None,[],{},dict(standard='bonded_stake'),dict(standard='wrong',candidates=[]),registry,dict(registry,slashes=None),dict(registry,candidates=[None]),dict(registry,candidates=[candidate,candidate])]:decode(value)
    for field in candidate:
        for value in [None,[],0,-1,'','bad','-1','0x8000000000000000','9223372036854775808']:
            v=copy.deepcopy(registry);v['candidates'][0][field]=value;decode(v)
        v=copy.deepcopy(registry);del v['candidates'][0][field];decode(v)
    slash_record=dict(id=b64(bytes(32)),offender=candidate['address'],evidence_epoch='1',applied_epoch='2',amount='1000000')
    for field in slash_record:
        for value in [None,[],0,'','bad','-1']:
            v=copy.deepcopy(registry);s=dict(slash_record);s[field]=value;v['slashes']=[s];decode(v)
    for v in [dict(registry,slashes=[slash_record]),dict(registry,slashes=[slash_record,slash_record])]:decode(v)
    for raw in ['{','{"standard":"bonded_stake","standard":"bad","candidates":[]}', '{standard:"bonded_stake",candidates:[]}']:
        cases.append(dict(kind='decode',raw=b64(raw)))
    return cases

def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/validator-lifecycle-oracle.ml',fixtures(),'octra_core octra_consensus yojson mirage-crypto-ec')
    report['scope']='Native admission, registry serialization and lifecycle, signed bond/evidence checks, snapshot and policy. Execution escrow and canonical activation are separate integration gates.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native validator lifecycle cases')
if __name__=='__main__':main()
