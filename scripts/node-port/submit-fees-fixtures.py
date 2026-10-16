#!/usr/bin/env python3
"""Native read-only fee advice edge vectors; no transaction submission or network."""
import argparse, hashlib, importlib.util, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    cases=[]
    def add(params,staging='0',settings=None,last=False):
        cases.append(dict(params=params,staging_ou=staging,staging_size=17,settings=settings or {},last=last))
    for op in ['standard','unknown','stealth','private','encrypt','decrypt','recrypt','keyswitch','program_deploy','circle_asset_put','circle_asset_put_encrypted','circle_sealed_slot_put']:
        for usage in [0,49,50,79,80,94,95,100]:add([op],str(usage*100_000_000))
    for op in ['program_deploy','circle_asset_put']:
        for hint in [0,1,4096,4097,16384,16385,131072,524288,2**62-1,-1,'0x1000',{'asset_wire_bytes': '16385'},{'asset_wire_bytes':-1,'encrypted_data_len':9999}]:add([op,hint])
    for settings in [dict(OCTRA_STEALTH_MIN_OU=v) for v in ['0','-1','10000000000','10000000001','0x100','invalid']]:add(['stealth'],settings=settings)
    for low,high in [('5','9'),('9','5'),('-10','-1'),(str(-(2**62)),str(2**62-1)),('bad','bad')]:
        for last in [False,True]:add(['encrypt'],settings=dict(OCTRA_STEALTH_FEE_JITTER_MIN=low,OCTRA_STEALTH_FEE_JITTER_MAX=high),last=last)
    spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/submit-fees-oracle.ml',cases,'octra_node_runtime octra_core yojson zarith lwt.unix')
    report['generator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['scope']='Native fee advice JSON bytes, base/usage tiers, heavy fee floor and jitter capture including machine-int hint overflow. Read-only advice; no mempool admission or confirmation claim.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS native submit fee advice',len(report['cases']),'cases')
if __name__=='__main__':main()
