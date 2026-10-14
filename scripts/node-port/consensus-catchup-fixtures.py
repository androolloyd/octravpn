#!/usr/bin/env python3
"""Native catch-up authentication, execution gates and driver policy fixtures."""
import argparse,hashlib,json,pathlib,random,shutil,struct,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
SOURCES=['lib/consensus/'+name+'.ml' for name in ['c_types','c_quorum_policy','c_protocol','c_config','c_codec','epoch_time','c_epoch_time_policy','c_reward_source','c_hash','c_qc','c_engine','c_catchup','c_driver','c_pace','c_seen']]+['net/oce1.ml','net/hash_domain.ml','crypto_guard/octra_ed25519.ml']
def cases():
 out=[];rng=random.Random(202610132238);bounds=[-(1<<63),-(1<<62),-1,0,1,12,1306547,(1<<62)-1,(1<<63)-1]
 for _ in range(320):
  head,target,start=[rng.choice(bounds)for _ in range(3)]
  out.append(dict(op='policy',head=str(head),target=str(target),start=str(start),max_lag=rng.choice([-1,0,1,16,(1<<62)-1]),soft=rng.choice([-1,0,16]),heads=[str(rng.choice(bounds))for _ in range(rng.randrange(8))],faults=rng.randrange(-1,8),current=rng.choice([False,True]),target_quorum=rng.choice([False,True]),matches=rng.choice([False,True]),empty=rng.choice([False,True])))
 for _ in range(160):
  now,started,interval,delay,read_now=[rng.choice(bounds+[99_999_999,100_000_000,100_000_001,1_000_000_000])for _ in range(5)]
  bits=rng.choice([0,1,1<<63,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000001,struct.unpack('>Q',struct.pack('>d',rng.uniform(-1000,1000)))[0]])
  out.append(dict(op='pace',height='12',generation=3,now=str(now),started=str(started),interval=str(interval),delay=str(delay),read_height=str(rng.choice([12,13])),read_generation=rng.choice([3,4]),read_now=str(read_now),grace=rng.choice([0,1,100,180000]),seconds_bits=str(bits if bits<(1<<63)else bits-(1<<64))))
 for capacity in [-1,0,1,2,8,64]:out.append(dict(op='seen',capacity=capacity,ids=[rng.choice(['','00','01','02','03','04'])for _ in range(80)]))
 source=json.loads((ROOT/'crates/octra-node-protocol/tests/fixtures/consensus-wire.json').read_text())['cases']
 valid=[c['input']for c in source if 'error'not in c['expected']]
 for kind in ['catchup_v2','proposal','vote','sync']:
  selected=[x for x in valid if x['kind']==kind][:32]
  for seed in selected:
   if kind=='catchup_v2':
    for mutation in ['none','epoch','previous','root','txroot','receipts','timestamp','creator','round','missing','signature','set','txid','chain','count','tx']:out.append(dict(op='record',wire=seed['wire'],mutation=mutation))
   else:
    for round in [-1,0,2,3,64,1000000]:out.append(dict(seed,op=kind,height=str(rng.choice(bounds)),round=round,step=rng.choice([1,2,3])))
 for _ in range(160):out.append(dict(op='apply',head=str(rng.choice(bounds)),root=rng.choice(['','00','01']),eic=rng.choice([None,'','00','01']),txid=str(rng.choice(bounds)),from_=str(rng.choice(bounds)),last=str(rng.choice(bounds)),expected_root=rng.choice(['','00','01']),expected_eic=rng.choice(['','00','01']),expected_txid=str(rng.choice(bounds))))
 for c in out:
  if 'from_'in c:c['from']=c.pop('from_')
 for from_ in bounds:
  for epoch in bounds:
   for maximum in [-1,0,1,16]:out.append({'op':'window','from':str(from_),'epoch':str(epoch),'max':maximum})
 return out

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip();manifest=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
 if pin!=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']or a.out.exists():raise SystemExit('require pinned source and fresh fixture path')
 hashes={}
 with tempfile.TemporaryDirectory(prefix='octra-consensus-catchup-')as temp:
  f=pathlib.Path(temp)
  for name in SOURCES:
   data=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{name}'])
   if(a.upstream/name).read_bytes()!=data:raise SystemExit('modified oracle source '+name)
   digest=hashlib.sha256(data).hexdigest()
   if manifest['files'][name]!=digest:raise SystemExit('source mismatch '+name)
   hashes[name]=digest;target=f/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
  shutil.copyfile(ROOT/'scripts/node-port/consensus-catchup-oracle.ml',f/'main.ml');(f/'dune').write_text('(executable (name main) (libraries octra_consensus yojson zarith))\n');(f/'cases.json').write_text(json.dumps(cases()))
  command=' && '.join(f'cmp {name} /fixture/{name}'for name in SOURCES)+' && mkdir vpn_consensus_catchup_oracle && cp /fixture/main.ml /fixture/dune vpn_consensus_catchup_oracle/ && opam exec -- dune exec ./vpn_consensus_catchup_oracle/main.exe -- /fixture/cases.json'
  results=json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True))
 report={'upstream_commit':pin,'source_sha256':hashes,'oracle_sha256':hashlib.sha256((ROOT/'scripts/node-port/consensus-catchup-oracle.ml').read_bytes()).hexdigest(),'builder_image':a.builder_image,'scope':'Catchup/finality gates and pure driver policies. Live driver, durable signing and canonical store integration are separate.','cases':results};a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'Generated {len(results)} native catchup/driver policy cases')
if __name__=='__main__':main()
