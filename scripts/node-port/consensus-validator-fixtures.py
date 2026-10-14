#!/usr/bin/env python3
"""Generate native weighted-quorum, leader, activation and epoch-time fixtures."""
import argparse,copy,hashlib,json,math,pathlib,random,shutil,struct,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
SOURCES=['lib/consensus/'+name+'.ml' for name in ['c_types','c_quorum_policy','c_protocol','c_config','c_codec','epoch_time','c_epoch_time_policy','c_reward_source']]+['net/oce1.ml','net/hash_domain.ml']
def cases():
    rng=random.Random(202610131955);out=[]
    def entry(i,weight):return {'address':f'validator-{i:03}'.encode().hex(),'pubkey':i.to_bytes(32,'little').hex(),'weight':str(weight)}
    for weighted in [False,True]:
        for n in [0,1,2,3,4,5,6,7,8,10,25]:
            for pattern in range(4):
                entries=[entry(i+1,1 if pattern==0 else (1<<256) if pattern==1 and i==0 else rng.randrange(1,1000) if pattern==2 else i+1) for i in range(n)]
                rng.shuffle(entries)
                for chain,epoch in [(b'octra-devnet-9871-cluster',1306546),(b'octra-devnet-9871-cluster',1306547),(b'octra-mainnet',0),(b'local',-1)]:
                    signers=[x['address'] for x in entries[:(n*2)//3+1]]
                    if pattern==1:signers+=signers[:1]
                    if pattern==2:signers+=[b'unknown'.hex()]
                    out.append({'op':'set','weighted':weighted,'entries':entries,'chain_id':chain.hex(),'epoch_id':str(epoch),'signers':signers,
                                'signer_count':len(signers),'signed_weight':str(sum(int(e['weight']) for e in entries[:len(signers)])), 'rounds':[-1,0,1,2,17,1000000,(1<<62)-1]})
    base=[entry(i,1) for i in range(1,5)]
    invalid=[[],[dict(base[0],address='')],[dict(base[0],pubkey='')],[dict(base[0],pubkey='00'*31)],[dict(base[0],weight='0')],[dict(base[0],weight='-1')],base+[base[0]],base+[dict(base[0],address=b'other'.hex())]]
    for entries in invalid:out.append({'op':'set','weighted':True,'entries':entries,'chain_id':b'octra-mainnet'.hex(),'epoch_id':'1','signers':[],'signer_count':0,'signed_weight':'0','rounds':[0]})
    for value in [b'',b'+',b'-',b'_1',b'1_',b'1__2',b' 1',b'1 ',b'\t1',b'1\n',b'-0x1',b'0x_1',b'+0b10',b'012',b'0o8',b'00',b'-0',b'0XAf',b'0B10',b'0O17',b'0d10',b'0x',b'0b',b'0o',b'0x_',b'_',b'__',b'-+1',b'-+0x1',b'+_1',b'++1',b'+-1',b'1\x002',b'9'*256]:out.append({'op':'parse_weight','value':value.hex()})
    for chain in [b'octra-mainnet',b'octra-devnet-9871-cluster',b'',b'other\xff']:
        for epoch in [-(1<<63),-1,0,1,1306546,1306547,1319999,1320000,(1<<63)-1]:
            for activation in [0,1306547]:out.append({'op':'policy','chain_id':chain.hex(),'epoch_id':str(epoch),'to_epoch':str(epoch-1 if epoch>-(1<<63) else epoch),'activation':str(activation)})
    bits=lambda x:'0x'+struct.pack('>d',x).hex()
    for candidate in [float('nan'),float('inf'),-float('inf'),-1.0,-0.0,0.0,5e-324,0.0009999999999999998,0.001,9.999999999999998,10.0,10.000000000000002,15.0,300.0,300.001,9.22e15,math.nextafter(9.22e15,math.inf)]:
        for previous in [None,'0','10000']:
            for rule,kind in [('historical','fresh'),('historical','reproposal'),('uniform','reproposal')]:
                out.append({'op':'time','now_bits':bits(0.0),'candidate_bits':bits(candidate),'previous':previous,'rule':rule,'kind':kind})
    for i in range(64):
        now=rng.uniform(0,2e9);candidate=now+rng.choice([-300,-10,-5,0,5,10,300])+rng.uniform(-0.002,0.002)
        out.append({'op':'time','now_bits':bits(now),'candidate_bits':bits(candidate),'previous':None if i%2 else str(int((now-10)*1000)),'rule':'uniform','kind':'fresh'})
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip();manifest=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
    if pin!=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit'] or a.out.exists():raise SystemExit('require pinned source and fresh fixture path')
    source_hashes={};inputs=cases()
    with tempfile.TemporaryDirectory(prefix='octra-validator-oracle-') as temp:
        f=pathlib.Path(temp)
        for name in SOURCES:
            data=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{name}'])
            if (a.upstream/name).read_bytes()!=data:raise SystemExit('modified oracle source '+name)
            digest=hashlib.sha256(data).hexdigest()
            if manifest['files'][name]!=digest:raise SystemExit('source mismatch '+name)
            source_hashes[name]=digest;target=f/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        shutil.copyfile(ROOT/'scripts/node-port/consensus-validator-oracle.ml',f/'main.ml')
        (f/'dune').write_text('(executable (name main) (libraries octra_consensus yojson zarith))\n')
        command=' && '.join(f'cmp {name} /fixture/{name}' for name in SOURCES)+' && mkdir vpn_validator_oracle && cp /fixture/main.ml /fixture/dune vpn_validator_oracle/ && opam exec -- dune exec ./vpn_validator_oracle/main.exe -- /fixture/cases.json'
        def run(values):
            (f/'cases.json').write_text(json.dumps(values));return json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True))
        results=run(inputs)
        selected=next(x['expected']['set']['wire'] for x in results if x['input'].get('weighted') and len(x['input'].get('entries',[]))==4 and 'set' in x['expected'])
        wire=bytes.fromhex(selected);extra=[{'op':'decode_set','wire':wire[:n].hex()} for n in range(len(wire)+1)]
        extra.extend({'op':'decode_set','wire':v.hex()} for v in [wire+b'\0',b'\2'+wire[1:],wire[:1]+b'\xff'*4+wire[5:],wire[:1]+(4097).to_bytes(4,'big')+wire[5:]])
        for x in results:
            if isinstance(x['expected'],dict) and 'set' in x['expected']:extra.append({'op':'decode_set','wire':x['expected']['set']['wire']})
        # Spellings accepted by Zarith must still fail canonical validator-set wire checks.
        position=5
        for _ in range(2):
            length=int.from_bytes(wire[position:position+4],'big');position+=4+length
        weight_length=int.from_bytes(wire[position:position+4],'big')
        for weight in [b'',b'+',b'-',b'01',b'+1',b'0x1',b'1_',b'1__0',b'_1',b'-+1',b'9'*257]:
            altered=wire[:position]+len(weight).to_bytes(4,'big')+weight+wire[position+4+weight_length:]
            extra.append({'op':'decode_set','wire':altered.hex()})
        results+=run(extra)
    report={'upstream_commit':pin,'source_sha256':source_hashes,'oracle_sha256':hashlib.sha256((ROOT/'scripts/node-port/consensus-validator-oracle.ml').read_bytes()).hexdigest(),'builder_image':a.builder_image,'scope':'Validator sets, weighted leader/quorum/cap, canonical encoding, activation and epoch-time policy; full BFT execution remains under development','cases':results}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'Generated {len(results)} native validator/policy cases')
if __name__=='__main__':main()
