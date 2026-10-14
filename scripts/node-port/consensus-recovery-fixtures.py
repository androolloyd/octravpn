#!/usr/bin/env python3
"""Qualify native validator relief, finality retries and root-query cancellation."""
import argparse,copy,hashlib,itertools,json,pathlib,random,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
CHAIN=b'octra-devnet-9871-cluster'.hex()
def fixtures():
    out=[];rng=random.Random(20261013)
    for value in [None,b'',b'0',b'1',b'-1',b'+3',b' 3',b'3 ',b'1_2',b'_3',b'0x7fffffffffffffff',b'0xFFFFFFFFFFFFFFFF',b'0u18446744073709551615',b'9223372036854775808',b'bad',b'\xff']:
        for epoch in [-2**63,-1,0,1,12,2**63-1]:out.append(dict(op='protocol',value=None if value is None else value.hex(),epoch=str(epoch)))
    for flags in itertools.product([False,True],repeat=5):out.append(dict(op='route',**dict(zip(['complete_request','finality_request','complete','legacy','legacy_complete'],flags))))
    bounds=[-2**63,-1,0,1,4_999_999_999,5_000_000_000,5_000_000_001,59_999_999_999,60_000_000_000,60_000_000_001,2**63-1]
    for now,sent in itertools.product(bounds,repeat=2):
        for attempts in [-2**62,-1,0,1,2,3,4,2**62-1]:
            out.append(dict(op='query',idle=False,prior_epoch='12',epoch='12',attempts=attempts,sent_at=str(sent),now=str(now)))
    for idle,prior,epoch in itertools.product([False,True],[-2**63,0,12,2**63-1],[-2**63,0,12,2**63-1]):out.append(dict(op='query',idle=idle,prior_epoch=str(prior),epoch=str(epoch),attempts=3,sent_at='0',now='0'))
    for _ in range(32):
        steps=[];leases={};next_id=0
        for __ in range(96):
            op=rng.choice(['join','join','add','read','leave']) if leases else 'join';epoch=rng.choice([-2**63,0,1,12,2**63-1])
            if op=='join':name=next_id;next_id+=1;leases[name]=epoch
            else:name=rng.choice(list(leases))
            # Retain cancelled leases so late read/leave and rejoin races are tested.
            steps.append(dict(op=op,epoch=str(epoch),lease=name,value=rng.choice(['','00','01','02','ff'])))
        out.append(dict(op='roots',steps=steps))
    def validators(n):return [dict(id=i,key=i,weight='10')for i in range(1,n+1)]
    def sync(i,**kwargs):return dict(chain=CHAIN,height='1380000',round=64,step=1,request=False,id=i,corrupt=False)|kwargs
    base=dict(op='relief',chain=CHAIN,height='1380000',activate='1380001',fingerprint=b'a'*64,current=validators(7),target=validators(6),weighted=True,target_weighted=True,proof=[sync(i)for i in range(1,8)],mutation='none',restore_height='1380000')
    base['fingerprint']=base['fingerprint'].hex()
    def add(**kwargs):out.append(copy.deepcopy(base|kwargs))
    add()
    for height in [-(2**63),-1,0,1_379_999,1_380_000,1_380_001,2**63-1]:add(height=str(height))
    for lead in [-2**63,-1,0,1,63,64,65,2**63-1]:add(activate=str(lead if abs(lead)>100 else 1_380_000+lead))
    for chain in ['',b'octra-mainnet'.hex(),CHAIN]:add(chain=chain)
    for fingerprint in [b'',b'a'*63,b'a'*65,b'A'*64,b'g'*64,b'\0'*64,b'0123456789abcdef'*4]:add(fingerprint=fingerprint.hex())
    for mutation in ['none','height','activation','fingerprint','source','target','round','proof','inactive']:
        for restore in [1_379_999,1_380_000,1_380_001,1_380_002]:add(mutation=mutation,restore_height=str(restore))
    for weighted,target_weighted,n,m in itertools.product([False,True],[False,True],[0,3,4,5,7,10],[0,3,4,5,6,9]):
        add(weighted=weighted,target_weighted=target_weighted,current=validators(n),target=validators(m))
    for n in range(9):add(proof=[sync(i)for i in range(1,n+1)])
    for i in [1,3,7]:
        for change in [dict(id=9),dict(corrupt=True),dict(chain='00'),dict(height='1380001'),dict(round=63),dict(round=65),dict(step=2),dict(step=3),dict(request=True)]:
            proof=[sync(j)for j in range(1,8)];proof[i-1]|=change;add(proof=proof)
    add(proof=[sync(1),sync(1),sync(2)]);add(proof=[sync(i)for i in reversed(range(1,8))])
    for _ in range(128):
        current=validators(rng.randrange(4,13));target=copy.deepcopy(current[:rng.randrange(4,len(current)+1)])
        for member in current:member['weight']=str(rng.randrange(1,100))
        for member in target:member['weight']=current[member['id']-1]['weight']
        if rng.randrange(4)==0:target[0][rng.choice(['key','weight'])]=rng.choice([1,2,3]) if rng.randrange(2) else '1'
        for member in target:member['key']=int(member['key']);member['weight']=str(member['weight'])
        proof=[sync(i)for i in rng.sample(range(1,len(current)+1),rng.randrange(len(current)+1))]
        add(current=current,target=target,proof=proof)
    return out
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if a.out.exists() or pin!=inventory['upstream_commit']:raise SystemExit('require adopted pin and fresh output')
    for name,h in inventory['files'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=h:raise SystemExit(f'modified upstream: {name}')
    oracle=ROOT/'scripts/node-port/consensus-recovery-oracle.ml'
    with tempfile.TemporaryDirectory(prefix='octra-consensus-recovery-')as directory:
        work=pathlib.Path(directory);shutil.copyfile(oracle,work/'main.ml');shutil.copyfile(a.upstream/'lib/consensus/c_relief.ml',work/'native_relief.ml')
        (work/'dune').write_text('(executable (name main) (flags (:standard -open Octra_consensus)) (libraries octra_consensus yojson zarith))\n')
        (work/'input.json').write_text(json.dumps(fixtures()));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && cmp lib/consensus/c_relief.ml /oracle/native_relief.ml && mkdir vpn_consensus_recovery_oracle && cp /oracle/main.ml /oracle/native_relief.ml /oracle/dune vpn_consensus_recovery_oracle/ && opam exec -- dune exec ./vpn_consensus_recovery_oracle/main.exe -- /oracle/input.json'],text=True)
    cases=json.loads(output.splitlines()[-1]);report=dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,scope='Native relief authentication and marker recovery, finality retry/routing and root-query cancellation; live async driver remains separate',cases=cases)
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(cases)} native consensus recovery cases: {a.out}')
if __name__=='__main__':main()
