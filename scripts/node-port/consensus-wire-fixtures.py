#!/usr/bin/env python3
"""Qualify native BFT codecs, signed domains, quorum certificates and evidence."""
import argparse,hashlib,json,pathlib,random,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
SOURCES=['lib/consensus/'+name+'.ml' for name in ['c_types','c_quorum_policy','c_protocol','c_config','c_codec','epoch_time','c_epoch_time_policy','c_reward_source','c_hash','c_qc','c_parent_commit','c_evidence']]+['net/oce1.ml','net/hash_domain.ml','crypto_guard/octra_ed25519.ml']
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip();manifest=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
    if pin!=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit'] or a.out.exists():raise SystemExit('require pinned source and fresh fixture path')
    hashes={}
    with tempfile.TemporaryDirectory(prefix='octra-consensus-wire-') as temp:
        f=pathlib.Path(temp)
        for name in SOURCES:
            data=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{name}'])
            if (a.upstream/name).read_bytes()!=data:raise SystemExit('modified oracle source '+name)
            digest=hashlib.sha256(data).hexdigest()
            if manifest['files'][name]!=digest:raise SystemExit('source mismatch '+name)
            hashes[name]=digest;target=f/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        shutil.copyfile(ROOT/'scripts/node-port/consensus-wire-oracle.ml',f/'main.ml')
        (f/'dune').write_text('(executable (name main) (libraries octra_consensus yojson zarith mirage-crypto-ec))\n')
        command=' && '.join(f'cmp {name} /fixture/{name}' for name in SOURCES)+' && mkdir vpn_consensus_wire_oracle && cp /fixture/main.ml /fixture/dune vpn_consensus_wire_oracle/ && opam exec -- dune exec ./vpn_consensus_wire_oracle/main.exe -- /fixture/cases.json'
        def run(values):
            (f/'cases.json').write_text(json.dumps(values));return json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True))
        seeds=run([]);results=run(seeds)
        extra=[];seen=set();rng=random.Random(202610132102)
        for x in results:
            if 'error' in x['expected']:continue
            case=x['input'];wire=bytes.fromhex(case['wire']);kind=case['kind']
            if kind not in seen:
                seen.add(kind)
                # Every truncation offset, then signed-length/cap mutations and corruption.
                extra.extend(dict(case,wire=wire[:n].hex()) for n in range(len(wire)))
                extra.extend(dict(case,wire=(wire+suffix).hex()) for suffix in [b'\0',b'\xff'])
                for offset in range(min(len(wire),150)):
                    for replacement in [b'\xff',b'\x80',b'\0']:
                        extra.append(dict(case,wire=(wire[:offset]+replacement+wire[offset+1:]).hex()))
                for _ in range(48):
                    offset=rng.randrange(len(wire));changed=bytearray(wire);changed[offset]^=1<<rng.randrange(8);extra.append(dict(case,wire=changed.hex()))
        results+=run(extra)
    report={'upstream_commit':pin,'source_sha256':hashes,'oracle_sha256':hashlib.sha256((ROOT/'scripts/node-port/consensus-wire-oracle.ml').read_bytes()).hexdigest(),'builder_image':a.builder_image,'scope':'Native consensus encoding, hashes, signed QC validation, evidence and malformed inputs. Does not qualify the BFT state engine or driver.','cases':results}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'Generated {len(results)} native consensus wire cases')
if __name__=='__main__':main()
