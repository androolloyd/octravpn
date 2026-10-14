#!/usr/bin/env python3
"""Reproduce pending-balance accounting across a canonical debit."""
import argparse,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('staging',ROOT/'scripts/node-port/staging-fixtures.py');staging=importlib.util.module_from_spec(spec);spec.loader.exec_module(staging)
def main():
 p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--fix',action='store_true');a=p.parse_args()
 if a.out.exists():raise SystemExit('require fresh output')
 txs=[staging.tx('a',1),staging.tx('a',2),staging.tx('a',3,amount='2999')]
 steps=[staging.step(index=0),staging.step(index=1),staging.step('account',sender=staging.b('a'),balance='3999',nonce=1),staging.step('processed',indices=[0]),staging.step(index=2)]
 case=staging.case(txs,steps,accounts=[dict(sender=staging.b('a'),balance='5000',nonce=0)])
 replacements=None
 if a.fix:
  spec=importlib.util.spec_from_file_location('fix',ROOT/'scripts/node-port/staging-reservations.py');fix=importlib.util.module_from_spec(spec);spec.loader.exec_module(fix);replacements=fix.REPLACEMENTS
 report=staging.native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/staging-oracle.ml',[case],'octra_core yojson base64',prefixes={'lib/core/tx_staging.ml':staging.CLOCK},replacements=replacements)
 report['scope']='Native staging boundary reproducer: initial public balance 5000; two 1001-cost transactions; commit first with new canonical balance 3999 and nonce 1; attempt another 3999-cost transaction while second still reserves 1001. No consensus or execution modification.'
 report['expected_safe_result']='insufficient balance (including pending)'
 report['candidate_fix']=a.fix
 if a.fix:assert report['cases'][0]['expected'][-1]['result']=={'error':report['expected_safe_result']}
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report['cases'][0]['expected'][-1]['result']))
if __name__=='__main__':main()
