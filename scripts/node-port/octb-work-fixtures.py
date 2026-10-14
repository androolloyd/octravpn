"""Native VM byte-work and integer-work boundaries without interpreter patches."""
import argparse,base64,hashlib,importlib.util,itertools,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
MAX=(1<<62)-1;STRING=(1<<57)-9
LIMITS=list(map(str,[16777216,4194304,16777216,4194304,134217728,32]))
def b64(v):return base64.b64encode(v).decode()
def fixture():
 out=[]
 def add(op,**v):out.append(dict(op=op)|v)
 for kind in ['add','sub','mul','div','mod','neg','abs']:
  for left,right in itertools.product([-33,-1,0,1,7,1<<63,(1<<64)+1,1<<129],repeat=2):
   add('integer',kind=kind,left=str(left),right=str(right),base='3')
 for used,cost,limit in itertools.product([-1,0,1,32,MAX],repeat=3):
  for z in [str(cost),str(1<<80),str(-(1<<80))]:add('cost',used=str(used),cost=str(cost),limit=str(limit),z=z,factors=list(map(str,[cost,limit])),divisor='32')
 for factors in [[-1,0],[MAX,MAX,MAX],[MAX,MAX,0],[],[MAX,2]]:
  for divisor in [-1,0,1,MAX]:add('cost',used='0',cost='0',limit='0',z='0',factors=list(map(str,factors)),divisor=str(divisor))
 for length,count,bits,cached in itertools.product([-1,0,1,2,3,4,31,32,33,STRING,MAX],[-1,0,1,MAX],[-1,0,1,7,8,9,MAX],[False,True]):
  add('helpers',length=str(length),count=str(count),bits=str(bits),cached=cached)
 requests=[['write','0','0'],['write','1','0'],['write','1','4194304'],['write','16777217','0'],['erase','-1'],['erase','0'],['erase','4194304'],['copy','-1','1'],['copy','0','0'],['copy','16777216','0'],['copy','16777216','1'],['alloc','0'],['alloc','134217728'],['alloc','134217729'],['scan',str(MAX)]]
 for request,used,base,limit in itertools.product(requests,[-1,0,1],[0,1],[0,1,32,MAX]):
  add('plan',limits=LIMITS,remaining='4194304',available='134217728',used=str(used),base=str(base),limit=str(limit),requests=[request])
 for field in range(6):
  for value in [-1,0,1,STRING,STRING+1,MAX]:
   lim=LIMITS.copy();lim[field]=str(value);add('plan',limits=lim,remaining=lim[3],available=lim[4],used='0',limit='100',base='0',requests=[])
 for remaining,available in itertools.product([-1,0,1,4194304,4194305],[-1,0,1,134217728,134217729]):
  add('plan',limits=LIMITS,remaining=str(remaining),available=str(available),used='0',base='1',limit='1',requests=[])
 for op in ['emit','output']:
  for size in [-1,0,1,31,32,33,4194303,4194304,MAX]:
   actions=[dict(action=op,used='0',limit=str(MAX),size=str(size))]*258
   add('budget',limits=LIMITS,actions=actions)
 rng=random.Random(387543)
 for _ in range(50):
  actions=[]
  for _ in range(24):
   actions.append(dict(action='charge',used=str(rng.randrange(40)),limit=str(rng.randrange(20000000)),base=str(rng.randrange(30)),requests=[rng.choice(requests) for _ in range(rng.randrange(1,5))]))
  add('budget',limits=LIMITS,actions=actions)
 for value in [b'',b'abc',bytes(range(256)),b'\0"\\\x7f\xff',b'\t\r\n\x0b\x0c']:
  for limit in [-1,0,1,2,3,4,8,16,256,1024]:
   add('text',value=b64(value),limit=str(limit))
   for depth in [-1,0,MAX]:add('event',limit=str(limit),address=b64(value),name=b64(b'event\0'),depth=str(depth),values=[b64(value),b64(b'"')])
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
 if a.out.exists():raise SystemExit('Require fresh output')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/octb-work-oracle.ml',fixture(),'octra_vm yojson')
 report.update(generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),scope='Unmodified Byte_work, Int_work and Cost. Shared gross allocations, writes, receipts and event count; no VM execution qualification.')
 a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native VM work cases')
if __name__=='__main__':main()
