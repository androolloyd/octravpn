#!/usr/bin/env python3
"""Generate deterministic signed native BFT transition traces."""
import argparse,hashlib,json,pathlib,random,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
SOURCES=['lib/consensus/'+name+'.ml' for name in ['c_types','c_quorum_policy','c_protocol','c_config','c_codec','epoch_time','c_epoch_time_policy','c_reward_source','c_hash','c_qc','c_engine']]+['net/oce1.ml','net/hash_domain.ml','crypto_guard/octra_ed25519.ml','logging/octra_log.ml']
def cases():
 out=[];rng=random.Random(202610132212)
 def step(op,**args):return dict(op=op,**args)
 for n in [1,3,4,7]:
  for weighted in [False,True]:
   for chain,epoch in [('local',12),('octra-devnet-9871-cluster',1306546),('octra-devnet-9871-cluster',1306547)]:
    base=dict(n=n,weighted=weighted,me=1,chain=chain.encode().hex(),epoch=str(epoch),ready=True)
    votes=lambda kind,name=10,round=0:[step('vote',who=i,type=kind,name=name,round=round)for i in range(1,n+1)]
    flows=[
      [step('start'),step('proposal')]+votes(1)+votes(2)+[step('drain'),step('drain'),step('ack'),step('drain'),step('height',height='13')],
      [step('start'),step('local_proposal')]+votes(1)+votes(2)+[step('ack')],
      [step('start')]+votes(1)+votes(2)+[step('proposal'),step('drain'),step('ack')],
      [step('start'),step('ready',ready=False),step('proposal')]+votes(1)+votes(2)+[step('ready',ready=True),step('drain')],
      [step('start'),step('proposal',execute=False)]+[step('vote',who=i,nil=True,type=1)for i in range(1,n+1)]+[step('timeout'),step('timeout')],
      [step('start'),step('proposal')]+votes(1)+[step('realign',round=1),step('proposal',name=11,valid_round=0),step('proposal',name=10,valid_round=0)]+votes(2)+[step('drain')],
      [step('restore',round=2),step('restore',round=2),step('restore',round=3),step('timeout'),step('realign',round=70)]+votes(1,round=2),
      [step('start'),step('timeout',generation=-1),step('timeout',step=2),step('timeout'),step('timeout'),step('timeout'),step('timeout')],
      [step('start'),step('skip_ready',ready=False)]+[step('sync',who=i,round=12)for i in range(1,n+1)]+[step('skip_ready',ready=True),step('sync',who=1,round=12),step('sync',who=1,round=2000)],
      [step('start'),step('proposal')]+votes(1)+[step('reconfigure',round=2,n=n,weighted=not weighted)]+votes(2)+[step('proposal',round=2,valid_round=0)],
      [step('start'),step('finalize'),step('drain'),step('ack'),step('finalize')],
      [step('start'),step('finalize',corrupt=True),step('finalize',count=0),step('proposal',corrupt=True),step('vote',who=1,corrupt=True),step('sync',who=1,round=10,corrupt=True)],
    ]
    for flow in flows:out.append(dict(base,steps=flow))
    for _ in range(4):
     flow=[step('start')]
     for _ in range(45):
      kind=rng.choice(['vote','vote','proposal','timeout','sync','ready','reconfigure','drain'])
      if kind=='vote':flow.append(step(kind,who=rng.randint(1,n+1),type=rng.choice([1,2]),name=rng.choice([10,11]),round=rng.choice([0,1,2,3,64,65]),nil=rng.random()<.25,corrupt=rng.random()<.1))
      elif kind=='proposal':flow.append(step(kind,name=rng.choice([10,11]),round=rng.choice([0,1,2,3]),execute=rng.random()<.8))
      elif kind=='sync':flow.append(step(kind,who=rng.randint(1,n),round=rng.choice([2,4,64,1024,1025])))
      elif kind=='ready':flow.append(step(kind,ready=rng.random()<.7))
      elif kind=='reconfigure':flow.append(step(kind,round=rng.choice([1,2,5,70]),n=n,weighted=rng.random()<.5))
      else:flow.append(step(kind))
     out.append(dict(base,steps=flow))
 return out

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip();manifest=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
 if pin!=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']or a.out.exists():raise SystemExit('require pinned source and fresh fixture path')
 hashes={}
 with tempfile.TemporaryDirectory(prefix='octra-consensus-engine-')as temp:
  f=pathlib.Path(temp)
  for name in SOURCES:
   data=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{name}'])
   if(a.upstream/name).read_bytes()!=data:raise SystemExit('modified oracle source '+name)
   digest=hashlib.sha256(data).hexdigest()
   if manifest['files'][name]!=digest:raise SystemExit('source mismatch '+name)
   hashes[name]=digest;target=f/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
  shutil.copyfile(ROOT/'scripts/node-port/consensus-engine-oracle.ml',f/'main.ml');(f/'dune').write_text('(executable (name main) (libraries octra_consensus yojson zarith mirage-crypto-ec))\n');(f/'cases.json').write_text(json.dumps(cases()))
  command=' && '.join(f'cmp {name} /fixture/{name}'for name in SOURCES)+' && mkdir vpn_consensus_engine_oracle && cp /fixture/main.ml /fixture/dune vpn_consensus_engine_oracle/ && opam exec -- dune exec ./vpn_consensus_engine_oracle/main.exe -- /fixture/cases.json'
  result=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True)
  results=json.loads(result)
 report={'upstream_commit':pin,'source_sha256':hashes,'oracle_sha256':hashlib.sha256((ROOT/'scripts/node-port/consensus-engine-oracle.ml').read_bytes()).hexdigest(),'builder_image':a.builder_image,'scope':'Signed native BFT state-engine traces, including invalid peer input filtered by native verification before raw engine callbacks. Driver, execution and storage qualification remain separate.','cases':results}
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'Generated {len(results)} traces / {sum(len(c["expected"])for c in results)} native state transitions')
if __name__=='__main__':main()
