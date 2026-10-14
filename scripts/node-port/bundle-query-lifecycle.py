#!/usr/bin/env python3
"""Reproduce native bundle query cancellation, validation failure and overlap."""
import argparse,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--fix',action='store_true');a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh report')
 cases=[dict(kind=kind,chain='bundle-fixture',height='1',local=1,weights=['1']*4,weighted=False)for kind in ['cancel','throw','overlap']]
 replacements=None
 if a.fix:
  spec=importlib.util.spec_from_file_location('fix',ROOT/'scripts/node-port/bundle-query-ownership.py');fix=importlib.util.module_from_spec(spec);spec.loader.exec_module(fix);replacements=fix.REPLACEMENTS
 r=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/bundle-query-lifecycle-oracle.ml',cases,'octra_consensus octra_net yojson lwt.unix mirage-crypto-ec',replacements=replacements)
 r['scope']='Unmodified native bundle query lifecycle with no peers. Cancellation and callback failure should release the slot; another query must not remove an active query slot.'
 r['candidate_fix']=a.fix
 if a.fix:
  assert all(not c['expected']['slot_after'] for c in r['cases'])
  assert r['cases'][2]['expected']['result']==dict(first_waiting=True,second_waiting=True,slot_after_second=True)
 a.out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps([c['expected']for c in r['cases']]))
if __name__=='__main__':main()
