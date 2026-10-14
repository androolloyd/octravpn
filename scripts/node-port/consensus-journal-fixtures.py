#!/usr/bin/env python3
"""Generate native local-vote journal bytes, conflict and restart evidence."""
import argparse,hashlib,json,pathlib,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
SOURCES=['lib/consensus/'+name+'.ml'for name in['c_vote_log','c_sync_log','c_engine','c_codec','c_types','c_protocol','c_quorum_policy','c_reward_source']]+['net/oce1.ml']
def cases():
 source=json.loads((ROOT/'crates/octra-node-protocol/tests/fixtures/consensus-wire.json').read_text())['cases'];out=[]
 votes=[c['input']for c in source if c['input']['kind']=='vote'and'error'not in c['expected']][:48]
 for v in votes:out.append(dict(op='meta',wire=v['wire']))
 wire=bytes.fromhex(votes[0]['wire'])
 out.extend(dict(op='decode',wire=wire[:i].hex())for i in range(len(wire)))
 for op,values in [('floor',[b'',b'0',b'0\n',b'-1\n',b'01\n',b'+1\n',b'1\n\n',b'a\n',b'0x1\n',b'-9223372036854775808\n',b'9223372036854775807\n',b'0'*33]),('mark',[b'',b'0 0',b'0 0\n',b'1 1000000\n',b'1 1000001\n',b'01 1\n',b'1 01\n',b'1 -1\n',b'-1 0\n',b'a 0\n',b'1 a\n',b'1  1\n',b'1\t1\n',b'9223372036854775807 0\n',b'1 +1\n'])]:out.extend(dict(op=op,wire=v.hex())for v in values)
 for epoch in [-1,0,1,(1<<63)-1]:
  for round in [-1,0,1,1000000,1000001]:
   for digest in ['0'*64,'A'*64,'0'*63]:out.append(dict(op='position',value=f'{epoch:020}_{round:08}_{digest}.vote'.encode().hex()))
 first=votes[0];raw=bytes.fromhex(first['wire']);off=4+int.from_bytes(raw[:4],'big');epoch=int.from_bytes(raw[off:off+8],'big',signed=True);round=int.from_bytes(raw[off+8:off+12],'big',signed=True);pid_at=off+13;addr_at=pid_at+32;alen=int.from_bytes(raw[addr_at:addr_at+4],'big');validator=raw[addr_at+4:addr_at+4+alen].hex()
 altered=bytearray(raw);altered[pid_at]^=1;conflict=altered.hex();sig=bytearray(raw);sig[-1]^=1;signature=sig.hex()
 def step(op,**kw):return dict(op=op,epoch=str(epoch),round=round,**kw)
 for mode in ['memory','disk']:
  flow=[step('read'),step('check',wire=raw.hex()),step('find',wire=raw.hex()),step('keep',wire=raw.hex()),step('keep',wire=signature),step('check',wire=conflict),step('keep',wire=conflict),step('find',wire=conflict),step('find',wire=raw.hex()),step('mark'),step('floor')]
  flow+=[dict(op='mark',epoch=str(epoch),round=round+1),dict(op='mark',epoch=str(epoch),round=round),dict(op='floor',epoch=str(epoch-1),round=0),step('prune'),step('find',wire=raw.hex())]
  out.append(dict(op='trace',mode=mode,chain=first['chain'],validator=validator,steps=flow))
 for data in ['',raw[:-1].hex(),'00'*513,conflict]:out.append(dict(op='trace',mode='disk',chain=first['chain'],validator=validator,steps=[step('keep',wire=raw.hex()),step('corrupt',wire=raw.hex(),data=data),step('find',wire=raw.hex()),step('check',wire=raw.hex()),step('prune'),step('read')]))
 sync_base=dict(chain=b'local'.hex(),validator=b'validator-1'.hex(),epoch='12',round=0,step=1,request=False,corrupt=False)
 for epoch in [-1,0,12,(1<<63)-1]:
  for round in [-1,0,1024,1000000,1000001]:
   for phase in [1,2,3]:out.append(dict(sync_base,op='sync_meta',epoch=str(epoch),round=round,step=phase))
 for value in [b'',b'0',b'00000000000000000000',b'-0000000000000000001',b'-00000000000000000001',b'09223372036854775807',b'00000000000000000001',b'0000000000000000001a']:out.append(dict(op='sync_epoch',value=value.hex()))
 for mode in ['memory','disk']:
  steps=[dict(sync_base,op='load')]
  for round in [0,1,1023,1024,1025,2048]:
   for phase in [1,2,3]:steps.append(dict(sync_base,op='keep',round=round,step=phase))
   steps.append(dict(sync_base,op='load'))
  steps += [dict(sync_base,op='keep',round=2048),dict(sync_base,op='keep',round=2048,request=True),dict(sync_base,op='keep',round=2048,corrupt=True),dict(sync_base,op='load',validator=b'other'.hex()),dict(sync_base,op='load',chain=b'other'.hex()),dict(sync_base,op='prune'),dict(sync_base,op='load')]
  out.append(dict(op='sync_trace',mode=mode,steps=steps))
 return out

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip();manifest=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
 if pin!=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']or a.out.exists():raise SystemExit('require pinned source and fresh fixture path')
 hashes={}
 with tempfile.TemporaryDirectory(prefix='octra-consensus-journal-')as temp:
  f=pathlib.Path(temp)
  for name in SOURCES:
   data=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{name}'])
   if(a.upstream/name).read_bytes()!=data:raise SystemExit('modified oracle source '+name)
   digest=hashlib.sha256(data).hexdigest()
   if manifest['files'][name]!=digest:raise SystemExit('source mismatch '+name)
   hashes[name]=digest;target=f/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
  shutil.copyfile(ROOT/'scripts/node-port/consensus-journal-oracle.ml',f/'main.ml');(f/'dune').write_text('(executable (name main) (libraries octra_consensus yojson mirage-crypto-ec) (flags (:standard -open Octra_consensus)))\n');(f/'cases.json').write_text(json.dumps(cases()))
  command=' && '.join(f'cmp {name} /fixture/{name}'for name in SOURCES)+' && mkdir vpn_consensus_journal_oracle && cp /fixture/main.ml /fixture/dune vpn_consensus_journal_oracle/ && cp /fixture/lib/consensus/c_vote_log.ml vpn_consensus_journal_oracle/native_vote.ml && cp /fixture/lib/consensus/c_sync_log.ml vpn_consensus_journal_oracle/native_sync.ml && opam exec -- dune exec ./vpn_consensus_journal_oracle/main.exe -- /fixture/cases.json'
  results=json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True))
 report={'upstream_commit':pin,'source_sha256':hashes,'oracle_sha256':hashlib.sha256((ROOT/'scripts/node-port/consensus-journal-oracle.ml').read_bytes()).hexdigest(),'builder_image':a.builder_image,'scope':'Native vote-journal bytes, memory/disk conflicts, floors, corrupt-record recovery and pruning. OS-generated error text is not a wire-parity claim.','cases':results};a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'Generated {len(results)} native journal cases')
if __name__=='__main__':main()
