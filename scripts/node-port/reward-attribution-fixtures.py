"""Qualify reward attribution and finality binding against unmodified native code."""
import argparse,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
 data=json.loads((ROOT/'crates/octra-node-protocol/tests/fixtures/consensus-wire.json').read_text())
 seeds=[c['input'] for c in data['cases'] if c['input']['kind']=='finalize' and 'wire' in c['expected']]
 parents=[c['input']['wire'] for c in data['cases'] if c['input']['kind']=='parent' and 'wire' in c['expected']]
 rng=random.Random(2026101321);rng.shuffle(seeds);out=[]
 for index in range(720):
  seed=seeds[index%len(seeds)]
  out.append(dict(wire=seed['wire'],parent_wire=parents[index%len(parents)],validators=seed['validators'],chain=rng.choice(['octra-devnet-9871-cluster','octra-mainnet','fixture']).encode().hex(),epoch=str(rng.choice([-1,0,1,1499999,1500000,1500001,(1<<62)-1,1<<62])),version=rng.choice([3,4,9]),parent=rng.choice(['none','original','empty','unknown','unknown_member']),supply=rng.choice(['full','parent','reverse','weight','bad_key','short_key','duplicate','empty','no_key']),activation=str(rng.choice([0,1500000]))))
 return out
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh report')
 report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/reward-attribution-oracle.ml',fixtures(),'octra_node_runtime octra_consensus octra_core octra_net yojson unix')
 report['scope']='Unmodified native reward source conversion, standard activation, parent participant attribution, finality binding and protocol resolution; historical epoch-log fallback remains separate.'
 a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native reward attribution cases')
if __name__=='__main__':main()
