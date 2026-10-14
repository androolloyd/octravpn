#!/usr/bin/env python3
"""Native signed pending recovery and bundle gates with immutable upstream hashes."""
import argparse, importlib.util, json, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
    out=[]
    mutations=['none','proposal_chain','header_chain','creator','proposer','valid_round','tx_root','receipt_root','parent_root','proposal_signature','vote_chain','vote_epoch','vote_round','vote_type','vote_pid','vote_validator','vote_signature','epoch','round','pid','root','txid','validator','legacy_proposal','legacy_vote','base64','tx_length','tx_invalid','tx_other','hashes','receipts']
    for chain,epoch in [('recovery-fixture',1),('octra-mainnet',1),('octra-devnet-9871-cluster',1300000),('octra-devnet-9871-cluster',1500000)]:
      for mutate in mutations:
       for ops in [[],['standard'],['standard','standard']]:
        out.append(dict(chain=chain,epoch=epoch,round=0,mutate=mutate,ops=ops,receipts=[]))
    for op in ['encrypt','stealth','circle_call','compute_fund','compute_settle','validator_bond']:
      out.append(dict(chain='recovery-fixture',epoch=1,round=0,mutate='none',ops=[op],receipts=[]))
    for receipt in [b'{}',b'[]',b'bad']:
      out.append(dict(chain='recovery-fixture',epoch=1,round=0,mutate='none',ops=[],receipts=[receipt.hex()]))
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh report')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/pending-recovery-oracle.ml',fixtures(),'octra_node_runtime octra_core octra_consensus yojson mirage-crypto-ec base64')
    report['scope']='Unmodified signed pending recovery, live precommit binding and finalized bundle admission. Execution against a canonical parent and peer reconciliation are separate gates.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native pending recovery cases")
if __name__=='__main__':main()
