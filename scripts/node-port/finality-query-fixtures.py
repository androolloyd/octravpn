import argparse,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
 rng=random.Random(2026101320);out=[]
 for count in [1,3,4,7,13]:
  for epoch in [0,1,123,1000000]:
   for now in [0,1,5000000000,1<<62]:
    for attempt in [1,2,3,4]:
     records=[dict(address='v'+str(rng.randrange(1,count+3)),head=str(epoch+rng.randrange(-2,3)))for _ in range(rng.randrange(20))]
     out.append(dict(validators=count,epoch=str(epoch),now=str(now),attempt=attempt,address=rng.randbytes(rng.randrange(12)).hex(),records=records))
 return out
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh report')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/finality-query-oracle.ml',fixtures(),'octra_consensus octra_net yojson mirage-crypto-ec')
 report['scope']='Unmodified native finality peer selection and request ID helpers; live handler and full consensus acquisition remain separately qualified.'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native finality request cases')
if __name__=='__main__':main()
