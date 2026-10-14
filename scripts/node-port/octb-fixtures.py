"""Exact OCTB images and legacy admission outcomes from pinned production code."""
import argparse,base64,hashlib,importlib.util,itertools,json,pathlib,random,struct
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
# Wire operand widths for tags 00..8a; EMIT has an additional register vector.
WIDTHS=[3, 3, 3, 3, 3, 2, 2, 3, 3, 3, 3, 3, 2, 3, 3, 2, 2, 2, 3, 3, 4, 5, 4, 0, 0, 1, 1, 1, 1, 1, 2, 1, 1, 5, 2, 3, 0, 0, 0, 3, 3, 1, 1, 0, 2, 5, 2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 5, 3, 3, 2, 2, 2, 2, 4, 3, 2, 1, 4, 3, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 5, 2, 4, 1, 4, 2, 11, 2, 3, 3, 4, 4, 3, 3, 1, 6, 4, 2, 2, 4, 2, 3, 2, 3, 5, 3, 4, 5, 6, 3, 6, 3, 2, 3, 3, 4, 5, 4, 3, 8, 4, 1, 1, 2, 2, 4, 3, 2, 4, 8, 4, 3, 3, 5, 4, 3, 3, 3]
def b64(v):return base64.b64encode(v).decode()
def u16(v):return struct.pack('<H',v)
def u32(v):return struct.pack('<I',v)
def wire(constants=(),code=b'',count=0):
 return b'OCTB'+u16(1)+u16(len(constants))+u32(count)+b''.join(bytes([t])+u32(len(d))+d for t,d in constants)+code
def fixtures():
 out=[]
 def add(name,raw):
  for active in [False,True]:out.append(dict(name=name,raw=b64(raw),active=active))
 def image(name,code=b'',constants=(),count=1):add(name,wire(constants,code,count))
 base=wire([(2,b'key'),(0,b'42'),(1,b'1'),(3,b'\0\xff'),(4,b'oct'+b'2'*44)],b'\x17',1)
 for size in range(len(base)):add('truncation '+str(size),base[:size])
 for start,data in [(0,b'NOPE'),(4,u16(2)),(6,u16(32769)),(8,u32(1048577)),(8,u32(0xffffffff)),(6,u16(32768)),(8,u32(1048576))]:
  add('header '+str(start)+' '+data.hex(),base[:start]+data+base[start+len(data):])
 add('trailing',base+b'garbage');add('empty program',wire());image('raw byte strings',b'\x0b\x01\x00\x00',[(2,b'\x00\xff\xc0\x80')])
 all_code=[]
 constants=[(2,b'key'),(0,b'42')]
 for tag in range(256):
  if tag>=len(WIDTHS):image('unknown '+str(tag),bytes([tag]));continue
  width=WIDTHS[tag];args=bytes(range(1,width+1))
  if tag in [0x0b,0x0d]:args=b'\x01\x00\x00'
  elif tag==0x0e:args=b'\x00\x00\x01'
  elif tag==0x0f:args=b'\x00\x00'
  elif tag in [0x89,0x8a]:args=b'\x01\x00\x02'
  elif tag==0x27:args=b'\x00\x00\x03\x01\x02\x03'
  code=bytes([tag])+args;all_code.append(code)
  image('opcode '+str(tag),code,constants)
  for length in range(1,len(code)):image('operand truncated '+str(tag)+' '+str(length),code[:length],constants)
  for offset in range(1,len(code)):
   for value in [0,63,64,255]:
    image('operand boundary '+str(tag)+' '+str(offset)+' '+str(value),code[:offset]+bytes([value])+code[offset+1:],constants)
 image('all instructions',b''.join(all_code),constants,len(all_code))
 for tag in range(8):
  for raw in [b'',b'0',b'1',b'false',b'2',b'\xff',b'00']:
   image('constant '+str(tag)+' '+raw.hex(),b'\x0b\x00\x00\x00',[(tag,raw)])
 for raw in [b'',b'-',b'+',b'-+',b'0x',b'0b',b'0o',b'_1',b'1_',b'1__2',b' 1',b'1 ',b'0x_f',b'0XAf',b'-+12',b'--1',b'0u12',b'00012',b'9'*1000,b'-'+b'9'*1000,b'\xff',b'NaN']:
  for opcode,code in [('unused',b'\x17'),('ldi',b'\x0b\x00\x00\x00'),('cap',b'\x89\x00\x00\x00'),('sload',b'\x0d\x00\x00\x00')]:image('integer '+opcode+' '+raw[:20].hex(),code,[(0,raw)])
 for tag in [0x0b,0x0d,0x0e,0x0f,0x27,0x89,0x8a]:
  for ci in [0,1,255,65535]:
   if tag in [0x0b,0x0d]:args=b'\x01'+u16(ci)
   elif tag==0x0f:args=u16(ci)
   elif tag==0x27:args=u16(ci)+b'\x02\x03\x04'
   else:args=u16(ci)+b'\x01'
   for kind in range(5):image('constant reference '+str((tag,ci,kind)),bytes([tag])+args,[(kind,b'1')])
 for n in [0,1,63,64,255]:image('emit count '+str(n),b'\x27\0\0'+bytes([n])+bytes(i%64 for i in range(n)),[(2,b'\xffevent')])
 for length in [16777216,16777217,0xffffffff]:add('constant length '+str(length),b'OCTB'+u16(1)+u16(1)+u32(0)+b'\x02'+u32(length))
 prefixes=[b'\0OCTRA_STATE_V1\0',b'\0OCTRA_AML_PROOF\0',b'\0OCTRA_AML_EMISSION\0',b'\0OCTRA_AML_VEIL\0']
 valid=[prefixes[0]+b64(u16(0)).encode(),prefixes[1]+b64(b'\0\xffproof').encode(),prefixes[2]+b'lowered',prefixes[3]+b'1:2']
 for index,prefix in enumerate(prefixes):
  for suffix in [b'',b'bad',b'AA==',b'AAA=',b'AAAA',b'A===',b'AB==',b'AAA',b'!!!!',b'lowered',b'specialized',b'0:0',b'0:1',b'01:1',b'1:+1',b'-1:0',b'0x1:1',b'1:2',b'1:2:3',b'9'*62+b':0',b'9'*63+b':0']:
   image('metadata '+str(index)+' '+suffix.decode(errors='replace'),b'\x17',[(2,prefix+suffix)])
  for kind in [0,1,2,3,4]:image('metadata constant type '+str((index,kind)),b'\x17',[(kind,valid[index])])
  image('repeated metadata '+str(index),b'\x17',[(2,valid[index])]*2)
 image('all metadata',b'\x17',[(2,v) for v in valid]);image('metadata failure priority',b'\x17',[(2,p+b'bad') for p in prefixes])
 for drop in range(4):image('metadata failure priority subset '+str(drop),b'\x17',[(2,p+b'bad') for p in prefixes[:drop]])
 for name in [b'a',b'_ok1',b'A',b'1',b'',b'\xff',b'a-b',b'a\0',b'a/b']:
  for kind in range(11):
   state=u16(1)+u16(len(name))+name+bytes([kind]);image('state name/kind '+name.hex()+' '+str(kind),b'\x17',[(2,prefixes[0]+b64(state).encode())])
 for rows in [[(b'z',0),(b'a',1)],[(b'a',0),(b'a',1)],[(b'a',0),(b'z',8)]]:
  state=u16(len(rows))+b''.join(u16(len(n))+n+bytes([k]) for n,k in rows);image('state ordering '+str(rows),b'\x17',[(2,prefixes[0]+b64(state).encode())])
 for body in [b'',u16(4097),u16(0)+b'x',u16(1),u16(1)+u16(4)+b'abc']:
  image('state framing '+body.hex(),b'\x17',[(2,prefixes[0]+b64(body).encode())])
 # Duplicate labels are rejected before individual bad registers, with the last duplicate winning.
 for code in [b'\x0c\xff\xff'+b'\x16'+u32(1)+b'\x16'+u32(1),b'\x16'+u32(1)+b'\x16'+u32(1)+b'\x16'+u32(2)+b'\x16'+u32(2),b'\x14'+u32(42)+b'\x16'+u32(42)]:
  image('jump verification '+code.hex(),code,count=3 if code[0]==0x0c else 4 if len(code)==20 else 2)
 for key in [b'\0reserved',b'',b'public',b'\xff']:
  image('storage reserved '+key.hex(),b'\x0e\0\0\xff',[(2,key)])
 for kind in [b'-1',b'0',b'1000000',b'1000001',b'999999999999999999999999']:
  image('capability kind '+kind.decode(),b'\x89\0\0\xff',[(0,kind)])
 effects=[b'\x12\0\0\0',b'\x13\0\0\0',b'\x0d\0\0\0',b'\x0e\0\0\0',b'\x21\0\x01\x02\x04\x02',b'\x22\0\x01',b'\x23\0\x01\x02',b'\x27\0\0\x01\x01',b'\x30\0\x01',b'\x24']
 for ordered in [effects,list(reversed(effects))]:
  image('ordered repeated effects '+str(ordered[0].hex()),b''.join(ordered*2),[(2,b'key')],20)
 for ordered in itertools.permutations([b'\x62\0\x01',b'\x7c\0\x01',b'\x5f\0']):
  image('policy priority '+b''.join(ordered).hex(),b''.join(ordered),count=3)
 for ordered in itertools.permutations([b'\x62\0\x01',b'\x7c\0\x01']):
  image('legacy policy priority '+b''.join(ordered).hex(),b''.join(ordered),count=2)
 rng=random.Random(79325)
 for i in range(500):
  size=rng.randrange(0,40);raw=rng.randbytes(size)
  image('deterministic instruction fuzz '+str(i),raw,constants,rng.randrange(0,8))
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
 if a.out.exists():raise SystemExit('Require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/octb-oracle.ml',fixtures(),'octra_vm octra_core yojson')
 report.update(generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),scope='Unmodified OCTB image decoder, metadata and canonical encoder; legacy admission, verifier and opcode policy. No AML compiler, program certificate/type-flow or VM execution qualification.')
 a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native OCTB cases')
if __name__=='__main__':main()
