#!/usr/bin/env python3
"""Replay actual pristine resource models offline; never instruments native sources.

The first native run creates signed proof witnesses with the pinned implementation.
The second captures its exported API results for deterministic bounded mutations.
Native signing keys here are fixed public fixtures, never operator credentials.
"""
import argparse, copy, hashlib, importlib.util, itertools, json, math, pathlib, struct
ROOT=pathlib.Path(__file__).resolve().parents[2]

def inputs(fixtures):
 cases=[]
 def add(v,label):
  v=copy.deepcopy(v);v['label']=label;cases.append(v)
 def mutate(v,path,value,label):
  v=copy.deepcopy(v);node=v
  for k in path[:-1]:node=node[k]
  node[path[-1]]=value;add(v,label)
 def hx(v):return v.encode().hex()
 def zero(n):return '00'*n
 def flip(v):return ('01' if v[:2]!='01' else '02')+v[2:]
 def scalar_paths(v,prefix=()):
  for k,x in v.items():
   if isinstance(x,dict):yield from scalar_paths(x,prefix+(k,))
   elif isinstance(x,(str,int)):yield prefix+(k,),x
 base=fixtures[0];ats=[v['attestation'] for v in fixtures[:9]];seed=base['seed'];challenge=base['challenge'];pub=base['public']
 add({'op':'constants'},'constants')
 for kind,side in itertools.product([-1,0,1,2,3,4,5,255,256],[0,1,2,3]):add({'op':'enum','kind':kind,'side':side},f'enum/{kind}/{side}')
 # Every actual resource proof family, including both two-leaf paths.
 for index,v in enumerate(fixtures):
  tag=f"proof/{v['op']}/{v.get('plugin',index)}"
  add(v,tag+'/positive')
  for path,value in [(('challenge',),zero(32)),(('commitment',),hx('wrong')), (('max_weight',),'0'),(('attestation','weight'),'0'),(('attestation','weight'),'11'),(('attestation','score'),zero(32)),(('attestation','signature'),zero(64)),(('attestation','kind'),4), (('attestation','proof_hash'),zero(32))]:
   mutate(v,path,value,tag+'/'+'/'.join(path))
  if index>=9:
   mutate(v,('evidence','leaf_index'),str(1-int(v['evidence']['leaf_index'])),tag+'/opposite-index')
   mutate(v,('evidence','path',0,'side'),3-v['evidence']['path'][0]['side'],tag+'/opposite-side')
   mutate(v,('evidence','chunk'),hx('wrong'),tag+'/wrong-chunk')
 # Shape/encoding boundaries are separate from cryptographic admission.
 attcase={'op':'attestation','attestation':ats[0],'challenge':challenge,'private':base['private'],'public':pub,'raw':base['raw_attestation']}
 add(attcase,'attestation/positive')
 for key,values in {'chain_id':['',hx('x'*128),hx('x'*129)],'node_id':['',hx('n'*128),hx('n'*129)],'commitment':['',hx('x'*65536),hx('x'*65537)],'epoch_id':['-9223372036854775808','-1','0','9223372036854775807'],'weight':['-9223372036854775808','-1','0','9223372036854775807'],'proof_hash':['',zero(31),zero(33),hx('ab'*32)],'score':['',zero(31),zero(33),hx('ab'*32)],'signature':['',zero(63),zero(65)]}.items():
  for i,x in enumerate(values):mutate(attcase,('attestation',key),x,f'attestation/{key}/{i}')
 for i,x in enumerate(['',zero(31),zero(33)]):mutate(attcase,('private',),x,f'attestation/private/{i}')
 for i,x in enumerate(['',zero(31),zero(32),zero(33)]):mutate(attcase,('public',),x,f'attestation/public/{i}')
 wire=bytes.fromhex(base['raw_attestation'])
 for i in [0,1,3,4,20,28,len(wire)-65,len(wire)-1,len(wire)]:mutate(attcase,('raw',),wire[:i].hex(),f'attestation/truncate/{i}')
 mutate(attcase,('raw',),wire.hex()+'00','attestation/trailing')
 # Serialize boundary shapes with a tiny independent wire framing helper (not a hash/proof oracle).
 def u32(n):return struct.pack('>I',n)
 def u64(n):return struct.pack('>Q',n%(1<<64))
 def blob(b):return u32(len(b))+b
 def raw_att(a):
  return blob(bytes.fromhex(a['chain_id']))+u64(int(a['epoch_id']))+blob(bytes.fromhex(a['node_id']))+bytes([a['kind']])+blob(bytes.fromhex(a['commitment']))+bytes.fromhex(a['proof_hash'])+u64(int(a['weight']))+bytes.fromhex(a['score'])+bytes.fromhex(a['signature'])
 for key,n in [('chain_id',128),('chain_id',129),('node_id',128),('node_id',129),('commitment',65536),('commitment',65537)]:
  a=copy.deepcopy(ats[0]);a[key]=hx('a'*n);mutate(attcase,('raw',),raw_att(a).hex(),f'attestation/decode-bound/{key}/{n}')
 for bad in [0,5,255]:
  a=copy.deepcopy(ats[0]);a['kind']=bad;mutate(attcase,('raw',),raw_att(a).hex(),f'attestation/decode-kind/{bad}')
 # Model arithmetic: exact BigInt signed division and stable ordering/ties/duplicates.
 mathbase={'op':'math','attestations':ats,'total':'9','left':'6','right':'7','byzantine':'2','budget_z':'100','weight':'3','budget':'103','size':5,'prior':[[hx('a'),'5'],[hx('z'),'-2']],'node':hx('a'),'amount':'7'}
 add(mathbase,'math/normal')
 for total in [-10,-3,-1,0,1,2,3,7,2**63-1,2**128+13]:
  for weight in [-2**63,-3,0,1,2**63-1]:
   v=copy.deepcopy(mathbase);v.update(total=str(total),weight=str(weight),budget_z=str(-(2**127+31) if weight<0 else 2**129+1));add(v,f'math/division/{total}/{weight}')
 for budget,size in itertools.product([-1,0,1,2,3,10,2**63-1],[-1,0,1,9,50]):
  v=copy.deepcopy(mathbase);v.update(budget=str(budget),size=size);add(v,f'math/reward-size/{budget}/{size}')
 for variant in range(10):
  v=copy.deepcopy(mathbase);a=copy.deepcopy(ats[0]);a['score']=zero(32);a['node_id']=hx('shared');values=[copy.deepcopy(a) for _ in range(8)]
  for i,x in enumerate(values):
   if variant==0:x['weight']=str(i+1)
   elif variant==1:x['kind']=i%4+1
   elif variant==2:x['proof_hash']=f'{i:064x}'
   elif variant==3:x['commitment']=hx(str(i))
   elif variant==4:x['node_id']=bytes([255-i]).hex()
   elif variant==5:x['signature']=f'{i:0128x}'
   elif variant==6:x['score']=f'{i%2:064x}'
   elif variant==7:x['weight']=str(-i)
   elif variant==8:x['node_id']=''
   else:x['weight']=str(2**63-1)
  v['attestations']=values[::-1];add(v,f'math/ties/{variant}')
 mutate(mathbase,('attestations',),[],'math/empty')
 # Exact float bits across the common finite/native exceptional domains.
 def bits(x):return struct.pack('>d',x).hex()
 for p,q in itertools.product([0.,-0.,1.,-1.,math.inf,-math.inf,math.nan,0.01,0.1,0.2,0.3,0.5,0.9,math.nextafter(1.,0.),math.ulp(0.)],[0.,1.,math.nan,0.01,0.1,0.3,0.5,0.9]):
  add({'op':'float','p':bits(p),'q':bits(q),'size':17},f'float/{bits(p)}/{bits(q)}')
 for size in [-1,0,1,2**32,2**62-1]:add({'op':'float','p':bits(.67),'q':bits(.25),'size':size},f'float/size/{size}')
 for rawp,rawq in itertools.product(['7ff8000000000001','fff8000000000000','fff8000000000123','7ff0000000000001'],['3fd0000000000000','7ff8000000000001','fff8000000000123']):
  add({'op':'float','p':rawp,'q':rawq,'size':17},f'float/nan-payload/{rawp}/{rawq}')
 # Evidence encoders, geometry, short/hex hashes, resource-specific validation.
 for v in fixtures[:9]:
  tag=f"evidence/{v['op']}/{v.get('plugin',0)}"
  for path,x in scalar_paths(v.get('evidence',{})):
   if path[-1] not in {'leaf_index','leaf_count','iterations','work_units','cost_units','byte_count','range_start','range_end','step_limit','tile_row','tile_col','tile_depth','field_modulus','claimed_value','difficulty_bits'}:
    mutate(v,('evidence',)+path,flip(x) if x else '01',tag+'/'+'/'.join(path)+'/tamper')
   elif path[-1] not in ['difficulty_bits']:
    for n in [-1,0,2**62-1 if path[-1]=='iterations' else 2**63-1]:
     xcase=copy.deepcopy(v);sub=xcase['evidence']
     for part in path[:-1]:sub=sub[part]
     sub[path[-1]]=str(n)
     if path[-1]=='iterations' and n>100:xcase['encode_only']=True
     add(xcase,tag+'/'+'/'.join(path)+f'/{n}')
  if v['op']=='plugin':
   for key in ['hash','resource_hash']:
    for raw in ['',zero(31),zero(32),hx('ab'*32)]:mutate(v,(key,),raw,tag+'/'+key+'/'+str(len(raw)))
   for n in [-1,0,1,2**63-1]:mutate(v,('work_units',),str(n),tag+f'/work/{n}')
   if v['plugin']==2:
    for key in ['private','public']:
     for n in [0,31,33]:mutate(v,(key,),zero(n),tag+f'/{key}/{n}')
  if v['op']=='hashchain':
   for iterations in [-1,0,1,8,9,2**32,2**62-1]:
    x=copy.deepcopy(v);x['evidence']['iterations']=iterations;x['encode_only']=iterations>100;add(x,tag+f'/iterations/{iterations}')
   for low,high in [(-1,8),(0,0),(8,7),(7,7),(8,8)]:
    x=copy.deepcopy(v);x.update(min_iterations=low,max_iterations=high);add(x,tag+f'/range/{low}/{high}')
  if v['op']=='pow':
   for n in [-1,0,1,7,8,9,255,256,257]:mutate(v,('difficulty',),n,tag+f'/difficulty/{n}')
   for n in [-1,0,1,2,127,128,255,256,511]:mutate(v,('byte',),n,tag+f'/byte/{n}')
   for n in [0,1,255,256,257]:mutate(v,('nonce',),zero(n),tag+f'/nonce/{n}')
  if v['op']=='storage':
   for n in [-1,0,1,2,3,31,32,33,63,64,2**63-1]:
    mutate(v,('leaf_count',),str(n),tag+f'/count/{n}')
    for idx in [-1,0,n-1,n]:
     x=copy.deepcopy(v);x['evidence'].update(leaf_count=str(n),leaf_index=str(idx));add(x,tag+f'/path/{n}/{idx}')
   for n in [0,1,7,8,32]:mutate(v,('digest',),zero(n),tag+f'/prefix/{n}')
   for n in [0,1,2,63,64]:
    x=copy.deepcopy(v);x['evidence']['path']=[{'side':1,'sibling_hash':zero(32)}]*n;add(x,tag+f'/depth/{n}')
 # Matrix work domain: exact modular dot, large signed values, mismatch/empty inputs.
 matrix=fixtures[8]
 for modulus,left,right in [(0,[1],[1]),(1,[0],[0]),(-1,[0],[0]),(17,[],[]),(17,[1],[]),(17,[-1],[1]),(17,[17],[1]),(2**63-1,[2**63-2]*8,[2**63-2]*8),(17,[2,3],[4,5])]:
  x=copy.deepcopy(matrix);x['evidence'].update(field_modulus=str(modulus),perturbed_left_values=list(map(str,left)),perturbed_right_values=list(map(str,right)));add(x,f'matrix/field/{modulus}/{left}/{right}')
 # Flow eligibility and unweighted conversion are separate from signature admission.
 flow={'op':'flow','attestations':ats,'seed':seed,'challenge':challenge,'delay':2,'size':4,'target':'9','source':'7','minimum':'1','budget':'103','public':pub,'missing':''}
 add(flow,'flow/normal')
 for delay,target,source in itertools.product([-1,0,1,2,10],[-1,0,1,7,9,2**63-1],[-1,7]):
  x=copy.deepcopy(flow);x.update(delay=delay,target=str(target),source=str(source));add(x,f'flow/delay/{delay}/{target}/{source}')
 for count in [0,1,2,4,7,10]:
  x=copy.deepcopy(flow);x['attestations']=[ats[0]]*count;add(x,f'flow/duplicates/{count}')
 for key,value in [('public',None),('public',''),('public',zero(32)),('missing',ats[0]['node_id']),('challenge',zero(31)),('challenge',zero(32)),('minimum','0'),('minimum','9223372036854775807')]:mutate(flow,(key,),value,f'flow/{key}/{value}')
 for key in ['prev_state_root','prev_qc_randomness']:
  for x in ['',zero(31),hx('ab'*32)]:mutate(flow,('seed',key),x,'flow/seed/'+key+'/'+str(len(x)))
 g={'chain_id':ats[0]['chain_id'],'seen_epoch':'7','attestation':ats[0]};gcase={'op':'gossip','gossip':g,'raw':base['raw_gossip']}
 add(gcase,'gossip/normal')
 raw=bytes.fromhex(base['raw_gossip'])
 for n in [0,1,3,4,20,28,32,len(raw)-1]:mutate(gcase,('raw',),raw[:n].hex(),f'gossip/truncate/{n}')
 mutate(gcase,('raw',),raw.hex()+'00','gossip/trailing')
 for chain in [b'',b'x'*128,b'x'*129]:
  encoded=blob(chain)+u64(7)+blob(bytes.fromhex(base['raw_attestation']));mutate(gcase,('raw',),encoded.hex(),f'gossip/chain/{len(chain)}')
 for payload in [b'',b'x'*65536,b'x'*65537,b'x'*262144,b'x'*262145]:
  encoded=blob(b'chain')+u64(7)+blob(payload)+b'!';mutate(gcase,('raw',),encoded.hex(),f'gossip/nested-precedence/{len(payload)}')
 for n in [0,11,12,13,128]:
  x={'op':'logging','gossip':copy.deepcopy(g)};x['gossip']['attestation']['node_id']=bytes((i*17)%256 for i in range(n)).hex();add(x,f'logging/bytes/{n}')
 # Admission: native ordering, reason precedence, signed fixtures, exact pool caps and fold order.
 w={'current_epoch':'7','fraud_window':'3','future_window':'2'}
 def event(action,**kw):return {'action':action,'window':copy.deepcopy(w),**kw}
 def ingest(a=ats[0],**kw):return event('ingest',attestation=a,chain_id=ats[0]['chain_id'],challenge=challenge,public=pub,**kw)
 def transcript(events,label):add({'op':'admission','events':events},'admission/'+label)
 transcript([event('snapshot'),ingest(),ingest(),event('snapshot')],'accept-replay')
 for key,x in [('chain_id',hx('wrong')),('challenge',''),('public',None),('public',zero(32)),('public','')]:
  e=ingest();e[key]=x;transcript([e,event('snapshot')],key+'/'+str(x))
 for key,vals in {'chain_id':[''], 'node_id':[''], 'weight':['0','-1'], 'epoch_id':['-1','0','3','4','9','10'], 'score':['',zero(32)],'proof_hash':[zero(31)],'signature':['',zero(64)],'commitment':[hx('wrong')]}.items():
  for x in vals:
   a=copy.deepcopy(ats[0]);a[key]=x;transcript([ingest(a),event('snapshot')],f'attestation/{key}/{x}')
 for current,fraud,future,epoch in [(-1,3,2,7),(7,-1,2,7),(7,3,-1,7),(7,3,2,4),(7,3,2,3),(2**63-1,0,0,-2**63)]:
  win=dict(current_epoch=str(current),fraud_window=str(fraud),future_window=str(future));e=ingest();e['window']=win
  transcript([event('expired',epoch=str(epoch),**{} )|{'window':win},e,event('snapshot')],f'window/{current}/{fraud}/{future}/{epoch}')
 for reason in ['disabled','capacity','chain_mismatch','epoch_too_old','epoch_too_new','missing_challenge','malformed','bad_score','unknown_node','bad_signature','conflicting_identity']:
  transcript([event('remember',attestation=ats[0],decision='reject',reason=reason),event('remember',attestation=ats[1],decision='quarantine',reason=reason),event('snapshot'),event('prune')|{'window':dict(current_epoch='11',fraud_window='3',future_window='2')},event('snapshot')],'evidence/'+reason)
 def bulk(action,count,**kw):return event(action,count=count,chain_id=ats[0]['chain_id'],challenge=challenge,epoch='7',prefix=hx('bulk-node-'),start=0,kind=1,commitment=hx('task'),weight='1',public=pub,**kw)
 for count in [129,513,4097]:
  b=bulk('ingest_many',count)
  transcript([b,event('snapshot'),bulk('ingest_many',1),event('snapshot'),event('prune')|{'window':dict(current_epoch='11',fraud_window='3',future_window='2')},event('snapshot')],f'accepted-resize-cap-prune/{count}')
 for decision_,reason in [('reject','bad_score'),('quarantine','unknown_node')]:
  for count in [129,4097]:
   b=bulk('remember_many',count,decision=decision_,reason=reason)
   transcript([b,event('snapshot'),bulk('remember_many',1,decision=decision_,reason=reason),event('snapshot'),event('prune')|{'window':dict(current_epoch='11',fraud_window='3',future_window='2')},event('snapshot')],f'{decision_}-resize-cap-prune/{count}')
 # Same signed identity with a changed commitment creates a conflict rather than replacing accepted.
 b=bulk('ingest_many',1);b2=copy.deepcopy(b);b2['commitment']=hx('other')
 transcript([b,b2,event('snapshot')],'conflicting-identity')
 # Invalid window must not prune a previously accepted record.
 b=bulk('ingest_many',1);e=ingest();e['window']=dict(current_epoch='100',fraud_window='-1',future_window='0')
 transcript([b,e,event('snapshot')],'invalid-window-preserves-pool')
 return cases

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--upstream',type=pathlib.Path,required=True)
 p.add_argument('--builder-image',required=True)
 p.add_argument('--out',type=pathlib.Path,required=True)
 a=p.parse_args()
 if a.out.exists():raise SystemExit('require a fresh output')
 spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/resource-native-oracle.py')
 native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
 oracle=ROOT/'scripts/node-port/resource-attestation-oracle.ml'
 factory_inputs=[dict(op='factory',kind=kind)for kind in ['pow','storage','hashchain']]
 factory_inputs += [dict(op='factory',kind='plugin',plugin=i)for i in range(1,7)]
 factory_inputs += [dict(op='factory',kind='storage',leaves=2,challenge_byte=i)for i in range(16)]
 libraries='octra_consensus octra_node_runtime yojson zarith base64 lwt.unix mirage-crypto-ec'
 factory=native.run(a.upstream,a.builder_image,oracle,factory_inputs,libraries)
 witnesses=[case['expected']['ok']for case in factory['cases']]
 report=native.run(a.upstream,a.builder_image,oracle,inputs(witnesses),libraries)
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(report,separators=(',',':'))+'\n')
 a.out.with_suffix('.factories.json').write_text(json.dumps(factory,indent=2)+'\n')
 print(f'PASS: {len(report["cases"])} actual native resource cases')
if __name__=='__main__':main()
