#!/usr/bin/env python3
"""Native signed peer records, discovery registry, abuse guards and endpoints."""
import argparse,base64,copy,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b(v):return base64.b64encode(v if isinstance(v,bytes) else str(v).encode()).decode()
def record(seed=1,host=b'8.8.8.8',ts=1000):
 return dict(seed=b(bytes([seed])*32),chain_id=b('peer-chain'),address=b('node'),binary=b(bytes([1])*32),config=b(bytes([2])*32),host=b(host),port=9000,features=[b('bft'),b('pex')],timestamp=str(ts))
def fixtures():
 out=[];rng=random.Random(719);base=record()
 common=dict(op='record',chain=base['chain_id'],config=base['config'],binary=base['binary'],allowed=[])
 out.append(dict(common,record=base))
 for field,values in dict(chain_id=[b(''),b('other'),b(b'c'*128),b(b'c'*129)],node_id=[b(''),b('0'*63),b('0'*64)],address=[b(''),b(b'\xff'),b('a'*129)],public_key=[b(b''),b(bytes(32)),b(bytes([255])*32)],binary=[b(bytes(32)),b('01'*32),b('01'*31),b('FF'*32)],config=[b(bytes(32)),b('02'*32)],host=[b(''),b('h'*255),b('h'*256),b(b'\x00'),b(b'\xff')],port=[-1,0,1,65535,65536],features=[[],[b('x')]*32,[b('x')]*33,[b(b'\x00')],[b('f'*64)],[b('f'*65)]],timestamp=[str(-(1<<63)),str(-1),str(0),str((1<<63)-1)],signature=[b(bytes(64)),b(bytes(63))]).items():
  for value in values:out.append(dict(common,record=dict(base,**{field:value})))
 for field,values in dict(chain=[b('other')],config=[b(bytes(32))],binary=[None,b(bytes(32))],allowed=[[b(bytes(32))],[]]).items():
  for value in values:out.append(dict(common,record=base,**{field:value}))
 for _ in range(40):
  row=record(rng.randrange(1,255),rng.randbytes(rng.randrange(1,255)),rng.randrange(-(1<<63),(1<<63)-1));row['features']=[b(rng.randbytes(rng.randrange(65))) for _ in range(rng.randrange(33))]
  out.append(dict(common,record=row))
 decode=dict(op='decode',record=base,list=False,count=1,append=b(''))
 for cut in range(400):out.append(dict(decode,cut=cut))
 for offset in [0,1,2,3,4,5,16,17,18,19,20,21,22]:
  for byte in [0,1,127,128,255]:out.append(dict(decode,offset=offset,byte=byte))
 for count in [0,1,2,31,32,33]:out.append(dict(decode,list=True,count=count))
 out.extend([dict(decode,append=b('x')),dict(decode,list=True,append=b('x'))])
 for field,values in dict(chain_id=[b('x'*129)],node_id=[b('x'*63),b('x'*65)],address=[b('x'*129)],host=[b('x'*256)],features=[[b('x')]*33,[b('x'*65)]],port=[-1,65536]).items():
  for value in values:out.append(dict(decode,record=dict(base,**{field:value})))
 hosts=[b'localhost',b'::1',b'LOCALHOST',b'127.bad.bad.bad',b'10.a.b.c',b'192.168.x.y',b'169.254.x.y',b'8.8.8.8',b'999.-2.0xA.0u5',b'1.2.3.',b'\xff',b'']
 for first in ['172','100','8']:
  for second in ['15','16','31','32','63','64','127','128','0x10','0x40','1_6','+16','-1',str(1<<62),'0x7fffffffffffffff']:
   for end in ['2.3','a.b']:hosts.append(f'{first}.{second}.{end}'.encode())
 for host in hosts:out.append(dict(op='bucket',host=b(host)))
 for maximum in [-1,0,1,4]:
  steps=[]
  for host in [b'8.8.8.8',b'127.bad.bad.bad',b'100.64.1.1',b'example']:
   for seed in range(1,7):steps.append(dict(kind='add',now=1000.,record=record(seed,host)))
  for now,ts in [(1000,1030),(1000,1031),(1000,700),(1000,699),(999,1000),(1200,1000),(1301,1000)]:steps.append(dict(kind='add',now=float(now),record=record(10,b'other',ts)))
  steps.extend([dict(kind='clear',now=1301.),dict(kind='add',now=1302.,record=record(1,b'8.8.8.8',1302))]);out.append(dict(op='registry',ttl=300.,maximum=maximum,steps=steps))
 cfg=dict(bad_window=60.,max_bad=3,ban=120.,connection_window=10.,max_connections=64)
 reasons=[b'bad_signature',b'decode exception stale_root signature',b'wrong_height',b'bad',b'\xff',b'malformed',b'handshake timeout']
 for c in [cfg,dict(cfg,max_bad=1,max_connections=1),dict(cfg,bad_window=0.,ban=0.,connection_window=0.),dict(cfg,max_bad=-1,max_connections=-1)]:
  steps=[dict(kind='admit',now=1000.,key=b('ip')) for _ in range(66)]
  for t in [1000.,1009.99,1010.,1059.99,1060.,1119.99,1120.,1120.01,1720.,1720.01,900.]:
   for reason in reasons:steps.append(dict(kind='report',now=t,key=b('node'),reason=b(reason)))
   steps.append(dict(kind='check',now=t,key=b('node')))
  steps.extend([dict(kind='prune',now=1120.,key=b(''),ttl=600.,maximum=1),dict(kind='check',now=1720.01,key=b('ip'))]);out.append(dict(op='guard',config=c,steps=steps))
 for _ in range(50):
  steps=[];now=1000.
  for _ in range(60):
   now+=rng.choice([-10,0,0.001,10,60,120,600]);kind=rng.choice(['admit','report','check','prune']);steps.append(dict(kind=kind,now=now,key=b(bytes([rng.randrange(8)])),reason=b(rng.choice(reasons)),ttl=rng.choice([0.,600.]),maximum=rng.randrange(5)))
  out.append(dict(op='guard',config=cfg,steps=steps))
 out.append(dict(op='guard',config=cfg,steps=[dict(kind='admit',now=1000.,key=b(f'{i:05}')) for i in range(4100)]+[dict(kind='prune',now=1000.,key=b(''),ttl=600.,maximum=4)]))
 for raw in [b'host:1',b'::1:80',b'unix',b'bad_signature_handshake',b'handshake failed: invalid Ed25519 signature',b'node_id does not match pubkey',b'frame_payload_limit handshake timeout',b'expected HELLO_ACK',b'handshake timeout',b'other',b'\xff']:
  out.append(dict(op='guard_key',value=b(raw)))
 endpoints=[b'',b'h:1',b' h : 65535 ',b'h:65536',b'h:-1',b'h:0',b'h:0xA',b'h:1_0',b'h:0u10',b'h:0x7fffffffffffffff',b':80',b'::1:80',b'h:80:x',b'\vh:80',b'\fh:80\f',b'\xff:80',b'h\x00:80',b'a:80,a:0x50,b:90,invalid,a:80']
 for raw in endpoints:out.append(dict(op='endpoint',value=b(raw)))
 out.append(dict(op='bootstrap',configured=[b('a:80'),b('invalid'),b('b:90')],base=b('a:0x50,c:100'),extra=b('b:90,d:110')))
 return out

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/peer-oracle.ml',fixtures(),'octra_net yojson base64 mirage-crypto-ec')
 report['scope']='Unmodified signed peer records, byte codecs, discovery expiry and bucket limits, peer guard traces, endpoint parsing; no live consensus claim'
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native peer policy cases: {a.out}")
if __name__=='__main__':main()
