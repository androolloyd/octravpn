"""Differential core OCTB execution, including failed VM state and work budgets."""
import argparse,base64,hashlib,importlib.util,itertools,json,pathlib,random,struct
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v).decode()
def text(v,kind='str'):return {kind:b64(v if isinstance(v,bytes) else v.encode())}
def integer(v,kind='int'):return {kind:str(v)}
def ins(tag,*args):return bytes([tag,*args])
def jump(tag,label,reg=None):return bytes([tag])+ (b'' if reg is None else bytes([reg])) + struct.pack('<I',label)
def constant(tag,index,reg=None):
 c=struct.pack('<H',index)
 return bytes([tag])+(c if reg is None else (bytes([reg])+c if tag in [0x0b,0x0d] else c+bytes([reg])))
def emit(index,regs):return bytes([0x27])+struct.pack('<H',index)+bytes([len(regs),*regs])
def wire(code,constants):
 return b'OCTB'+struct.pack('<HHI',1,len(constants),len(code))+b''.join(bytes([t])+struct.pack('<I',len(s))+s for t,s in constants)+b''.join(code)
def fixtures():
 out=[];modes=[dict(strict=s,bytes=b,integer_work=i,typed=t) for s,b,i,t in itertools.product([False,True],repeat=4)]
 def add(name,code,regs=(),constants=(),mode_set=None,**kw):
  for mode in modes if mode_set is None else mode_set:
   out.append(dict(name=name,raw=b64(wire(code,constants)),regs=list(regs),**mode,**kw))
 def binary(tag,a,b,name='binary',**kw):add(f'{name} {tag} {a} {b}',[ins(tag,0,1,2),ins(0x17)],[(1,a),(2,b)],**kw)
 nums=[0,1,-1,7,-7,2**63-1,2**64,-2**129,2**256+1]
 pairs=[(a,b) for a,b in itertools.product([0,7,-7],repeat=2)]+[(a,b) for a,b in zip(nums,nums[1:]+[0])]
 for tag in [0,1,2,3,4,7,8,9,10,0x47,0x48,0x49,0x4a,0x4b]:
  for a,b in pairs:binary(tag,integer(a),integer(b))
 # Cross-type coercion and strict guards; numeric zero + parsed string is a
 # deliberate native ADD exception, while byte strings never parse as integers.
 values=[integer(0),integer(9),integer(7,'u64'),integer(2**65,'u128'),integer(2**130,'u256'),{'bool':True},{'bool':False},text(''),text('0x2a'),text('bad'),text(b'12','bytes'),text(b'x'*32,'bytes32'),text('oct'+'2'*44,'addr')]
 for tag in [0,3,7,8,10,0x28,0x44]:
  for a in values:
   for b in [integer(0),text('12'),text(b'12','bytes')]:binary(tag,a,b,'coercion',mode_set=modes[::3])
 for tag in [5,6,0x2c,0x41,0x52,0x45,0x1e]:
  for value in values:add(f'unary {tag} {value}',[ins(tag,0,1),ins(0x17)],[(1,value)])
 for tag in [0x29,0x42]:
  for value in values:add(f'assert {tag} {value}',[ins(tag,1),ins(0x2a,0),ins(0x17)],[(1,value)])
 for a,b in [(-1,2),(0,0),(0,4),(2,100),(6,1),(7,1),(2,-1),(2**63,1)]:
  for source in [text(b'a\0bc\xffd'),text(b'a\0bc\xffd','bytes')]:
   add(f'substr {a} {b} {source}',[ins(0x43,0,1,2,3),ins(0x17)],[(1,source),(2,integer(a)),(3,integer(b))])
 for a,b in [('abcabc','bc'),('',''),('abc','abcd'),('abc','x'),('a'*2000,'a'*100+'b')]:binary(0x44,text(a),text(b),'substring search')
 for kind in range(9):
  for value in [None,b'42',b'-1',b'true',b'false',b'bad',b'\0'*32,('oct'+'2'*44).encode(),str(2**256).encode()]:
   add(f'typed load {kind} {value}',[constant(0x0d,0,0),ins(0x17)],constants=[(2,b'key')],kinds=[[b64(b'key'),kind]],storage=[] if value is None else [[b64(b'key'),b64(value)]],mode_set=modes[::3])
  for value in values:
   add(f'typed store {kind} {value}',[constant(0x0e,0,1),constant(0x0d,0,0),ins(0x17)],[(1,value)],constants=[(2,b'key')],kinds=[[b64(b'key'),kind]],mode_set=modes[::3])
 for key in [b'key',b'',b'\0private',b'\xffkey']:
  for view in [False,True]:
   add(f'storage {key} {view}',[constant(0x0e,0,1),ins(0x10,2,3),constant(0x0f,0),ins(0x11,3,1),ins(0x54,3),ins(0x17)],[(1,integer(42)),(3,text(key))],constants=[(2,key)],view=view)
 for action in [0x25,0x26]:
  for point in [False,True]:
   for view in [False,True]:
    add(f'nested undo {action} {point} {view}',[ins(0x24),constant(0x0e,0,1),ins(0x24),constant(0x0e,0,2),ins(action),ins(0x25),constant(0x0d,0,0),ins(0x17)],[(1,integer(1)),(2,integer(2))],constants=[(2,b'key')],point=point,view=view)
 for index in [-1,0,3,16777216,16777217,2**62,2**129]:
  for typed in [integer(index),text(str(index))]:
   add(f'memory {typed}',[ins(0x2f,1,2),ins(0x2e,0,1),ins(0x17)],[(1,typed),(2,text('written'))])
 add('immediate memory',[ins(0x13,255,255,1),ins(0x12,0,255,255),ins(0x17)],[(1,text('high'))])
 add('missing memory',[ins(0x12,0,0,0),ins(0x17)])
 add('context',[ins(t,r) for r,t in enumerate([0x19,0x1a,0x1b,0x1c,0x7b,0x1d,0x1f,0x20,0x7a])]+[ins(0x2b),ins(0x17)])
 for amount in [-1,0,1,2**80]:
  for target in [text('bad'),text('oct'+'2'*44),text('oct'+'2'*44,'addr')]:
   for success in [False,True]:add(f'transfer {amount} {target} {success}',[ins(0x23,0,1,2),ins(0x17)],[(1,target),(2,integer(amount))],transfer_ok=success,mode_set=modes[::3])
 for truth in values:
  add(f'branch {truth}',[jump(0x15,100,1),ins(0x18),jump(0x16,100),ins(0x2a,0),ins(0x17)],[(1,truth)])
 add('internal saved registers',[jump(0x2d,500,2),ins(0x0c,0,2),ins(0x17),jump(0x16,500),constant(0x0b,0,0),constant(0x0b,0,1),ins(0x17)],[(1,integer(9))],constants=[(0,b'42')])
 add('internal depth',[jump(0x16,500),jump(0x2d,500,0),ins(0x17)],limit=1000)
 add('infinite jump effort',[jump(0x16,5),jump(0x14,5)],limit=100)
 add('jump past end',[jump(0x14,900)],[(0,text('output'))])
 add('invalid register exception',[ins(0x0c,0,255),ins(0x2a,0),ins(0x17)])
 add('explicit revert',[constant(0x0e,0,1),ins(0x18),ins(0x2a,0),ins(0x17)],[(1,integer(123))],constants=[(2,b'key')])
 caps=[dict(scope=b64(b'x'*32),kind=1,id=2,revision=3),dict(scope=b64(b'x'*31),kind=1,id=2,revision=3),dict(scope=b64(b'x'*32),kind=-1,id=2,revision=3)]
 for cap in caps:
  for live in [False,True]:
   for view in [False,True]:
    for kind in [0,1]:add(f'cap {cap} {live} {view} {kind}',[constant(0x89,0,1),ins(0x24),constant(0x8a,0,1),ins(0x25),constant(0x8a,0,1),constant(0x8a,0,1),ins(0x17)],[(1,{'cap':cap})],constants=[(0,str(kind).encode())],cap_live=live,view=view,mode_set=modes[::3])
 for value in values:
  add(f'event {value}',[emit(0,[1,1]),ins(0x17)],[(1,value)],constants=[(2,b'ev\0\xff')],depth=3)
 add('event exhaustion',[emit(0,[])]*257+[ins(0x17)],constants=[(2,b'e')],mode_set=modes[::3])
 # Costs at refusal boundaries, including allocations consumed without a
 # successful output/event, and preflight parsing before the fixed opcode cost.
 for limit in range(0,45):
  for code,regs,consts in [([ins(0,0,1,2),ins(0x17)],[(1,text('123')),(2,integer(0))],[]),([ins(0x17)],[(0,integer(2**130))],[]),([emit(0,[1,2]),ins(0x17)],[(1,integer(1)),(2,integer(2**129))],[(2,b'e')])]:
   add(f'fuel {limit} {code}',code,regs,constants=consts,limit=limit,mode_set=[dict(bytes=True,strict=False),dict(bytes=True,strict=True)])
 for size in [0,1,10,63,64,65,100,255,256,257]:
  add(f'custom byte limits {size}',[constant(0x0e,0,1),emit(1,[1]),ins(0x17)],[(1,text(b'x'*size))],constants=[(2,b'key'),(2,b'e')],mode_set=[dict(bytes=True)],limits=[64,256,256,257,512,64])
 rng=random.Random(62179)
 for n in range(200):
  code=[ins(rng.choice([0,1,2,3,4,7,8,9,10,0x47,0x48,0x49]),rng.randrange(4),rng.randrange(4),rng.randrange(4)) for _ in range(20)]+[ins(0x17)]
  add(f'arithmetic sequence {n}',code,[(i,rng.choice(values)) for i in range(4)],mode_set=[rng.choice(modes)],limit=2000)
 # Parsing differs by budget mode: active parsing is preflighted and atomic;
 # prior execution can retain already-written cells on refusal.
 for source in [b'',b',,,',b'1,2,3',b' \t1 , \n2\r, ,3\x0c',b'1,bad,3',b'1 2,3',b'0x10,-0b11,+4,1__2',b'\x0b1,2',b'1,\xff,2',b'0'*80+b'1,2']:
  for base in [-1,0,16777215,16777216,16777217,2**62]:
   add(f'parse {source} {base}',[ins(0x40,0,1,2),ins(0x17)],[(1,text(source)),(2,integer(base))],memory=[[0,integer(99)]],mode_set=modes[::3])
 for limit in [9,10,11,12,13,14,15,20,40,100]:
  add(f'parse fuel {limit}',[ins(0x40,0,1,2),ins(0x17)],[(1,text('1,2,bad,4')),(2,integer(0))],limit=limit,mode_set=modes[::3])
 storage=[[b64(k),b64(v)] for k,v in [(b'',b'empty'),(b'\0reserved',b'hide'),(b'a:2',b'two'),(b'a:1',b'one'),(b'a:',b'prefix'),(b'z',b'last'),(b'\xff',b'nonutf')]]
 for prefix in [b'',b'a:',b'\0',b'absent']:
  for after in [b'',b'1',b'2',b'\xff']:
   for base in [-1,0,16777215,16777216,2**62-1,2**62]:
    for paged in [False,True]:
     code=ins(0x51,0,4,1,2,3) if paged else ins(0x4c,0,1,3)
     add(f'keys {prefix} {after} {base} {paged}',[code,ins(0x17)],[(1,text(prefix)),(2,text(after)),(3,integer(base))],storage=storage,mode_set=modes[::5])
 for limit in [49,50,51,54,55,59,60,70,100,1000]:
  add(f'keys fuel {limit}',[ins(0x51,0,4,1,2,3),ins(0x17)],[(1,text('a:')),(2,text('')),(3,integer(0))],storage=storage,limit=limit,mode_set=modes[::5])
 many=[[b64(f'key:{i:04d}'.encode()),b64(b'value')] for i in range(1005)]
 for base in [0,16776216,16777215]:
  add(f'paged key limit {base}',[ins(0x51,0,4,1,2,3),ins(0x17)],[(1,text('key:')),(2,text('')),(3,integer(base))],storage=many,mode_set=[dict(bytes=True),dict(bytes=False)])
 for tag in [0x4d,0x4e]:
  for keys,vals,count in [(0,100,-1),(0,100,0),(0,100,1),(0,100,4),(0,100,1001),(-1,100,2),(0,-1,2),(0,1,3),(2**62-2,100,4),(0,2**62-2,4),(16777216,0,1)]:
   for bad_key in [b'good',b'',b'\0reserved']:
    memory=[[0,text(bad_key)],[1,text('a:1')],[2,text('a:2')],[100,integer(123)],[101,text('new')],[102,{'bool':True}]]
    add(f'batch {tag} {keys} {vals} {count} {bad_key}',[ins(tag,1,2,3),ins(0x17)],[(1,integer(keys)),(2,integer(vals)),(3,integer(count))],memory=memory,storage=storage,mode_set=modes[::5])
  for limit in [49,50,64,65,99,100,129,130,179,180,181,260,300]:
   for view in [False,True]:
    add(f'batch fuel {tag} {limit} {view}',[ins(tag,1,2,3),ins(0x17)],[(1,integer(0)),(2,integer(10)),(3,integer(2))],memory=[[0,text('a:1')],[1,text('a:2')],[10,integer(123)],[11,integer(456)]],storage=storage,limit=limit,view=view,mode_set=modes[::5])
 for size in [0,1,1023,1024,1025,2048]:
  for limit in [49,50,51,52,53,100,150,10000]:
   for view in [False,True]:
    add(f'blob {size} {limit} {view}',[ins(0x4f,2,1),ins(0x50,0,2),ins(0x17)],[(1,text(b'x'*size))],limit=limit,view=view,mode_set=modes[::5])
 for value in values:add(f'keccak {value}',[ins(0x46,0,1),ins(0x17)],[(1,value)],mode_set=modes[::3])
 # RFC 8032 test vector 1, plus base64 and malformed encodings. Native peer
 # authentication remains the signature verifier, not an oracle stub.
 pk=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
 signature=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
 for key in [pk,b64(pk).encode(),b'bad',pk[:-1]]:
  for sig in [signature,b64(signature).encode(),b'bad',signature[:-1],bytes(64)]:
   for message in [b'',b'changed']:
    for kind in ['str','bytes','bytes32']:
     add(f'signature {len(key)} {len(sig)} {len(message)} {kind}',[ins(0x55,0,1,2,3),ins(0x17)],[(1,text(key,kind)),(2,text(message,kind)),(3,text(sig,kind))],mode_set=modes[::5])
 return out
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
 if a.out.exists():raise SystemExit('Require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/octb-execution-oracle.ml',fixtures(),'octra_vm octra_core yojson')
 report.update(generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),scope='Core OCTB synchronous and stepped execution against unmodified native VM. Host callbacks are controlled fixtures. No Circle transaction integration, private/compute opcodes, program certificates or full-node qualification.')
 a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native OCTB core execution cases')
if __name__=='__main__':main()
