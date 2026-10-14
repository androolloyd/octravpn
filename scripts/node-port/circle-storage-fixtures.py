#!/usr/bin/env python3
"""Qualify native Circle stable-storage guards and legacy traversal semantics."""
import argparse, base64, hashlib, json, pathlib, random, shutil, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
def b64(v):return base64.b64encode(v if isinstance(v,bytes) else v.encode()).decode()
def fixtures():
    cases=[];h='a'*64;addr='oct'+'1'*44
    suffixes={
      'slot_policy':'delivery_key_id activate_after_epoch expire_after_epoch tombstone revoked',
      'state_policy':'delivery_key_id activate_after_epoch expire_after_epoch tombstone revoked',
      'state_descriptor':'state_class codec schema_hash subject_addr hfhe_profile mutable_state',
      'object_policy':'delivery_key_id activate_after_epoch expire_after_epoch member_quorum tombstone revoked allow_detach allow_root_state_rotation transition_mode required_proof_kind',
      'object_binding':'current_state_ref version status last_transition_ref',
      'balance_binding':'current_state_ref version status last_workflow_ref',
      'register_binding':'current_state_ref version status last_workflow_ref',
      'object_member':'state_ref member_kind state_class codec status',
      'object_transition':'object_ref touched_members_hash proof_receipt_hash intent_id previous_state_ref next_state_ref proof_kind status',
      'balance_cell':'ciphertext_commitment amount_commitment proof_kind proof_receipt_hash',
      'register_cell':'ciphertext_commitment proof_kind proof_receipt_hash',
      'balance_workflow':'flow_kind status debit_subject_addr credit_subject_addr debit_state_ref credit_state_ref amount_commitment proof_kind proof_receipt_hash intent_id',
      'register_workflow':'register_ref proof_receipt_hash intent_id previous_state_ref next_state_ref workflow_kind status proof_kind',
    }
    values=[b'',b' ',b'\t\n\r\x0c',b'\x0b',b'\xff\x00',b'word',b'0',b'1',b'-1',b'+1',b'1_0',b'0xFFFFFFFFFFFFFFFF',b'0x7FFFFFFFFFFFFFFF',b'9223372036854775808',b'0u18446744073709551615',b'FALSE',b' YeS\n',b'no',b'none',b'NONE',h.encode(),(' \t'+h.upper()+'\n').encode(),b'g'*64,addr.encode(),(' '+addr+' ').encode(),b'open',b'proof_required',b'frozen',b'opaque_cell',b'cipher_cell',b'balance_cell',b'register_cell',b'program_object',b'ciphertext_v1',b'balance_cell_v1',b'register_cell_v1',b'commit_bound_v1']
    values += [x.encode() for x in ['zero_receipt_v1','range_v1','range_receipt_v1','bound_zero_v1','bound_zero_receipt_v1']]
    values += [base64.b64encode(b'x'*n) for n in [0,1,31,32,33]]
    values += [base64.b64encode(b'x'*32)+b'====',b'A===',b'%%%%']
    keys=[]
    for prefix,fields in suffixes.items():
        ident=addr if prefix=='balance_binding' else h
        middle=':member' if prefix=='object_member' else ''
        for suffix in fields.split()+['unknown','']:
            key=f'{prefix}:{ident}{middle}:{suffix}';keys.append(key)
            for value in values:cases.append(dict(op='write',key=b64(key),value=b64(value)))
        for ident in ['',h[:-1],h+'a','g'*64,' '+h+' ',h.upper(),addr,' '+addr+' ','\x00','\xff']:
            key=f'{prefix}:{ident}{middle}:{fields.split()[0]}';keys.append(key)
            cases.append(dict(op='write',key=b64(key),value=b64('value')))
        keys += [prefix,prefix+':',prefix+':bad',f'{prefix}:{h}:extra:extra',f'{prefix}:{h}: :state_ref']
    keys += ['transport_policy:', 'hfhe_policy:x','key_policy:x','mailbox:x','outbox:x','ingress:x','counter','object_policy','',':','\x00','\xff']
    for key in keys:
        cases.append(dict(op='delete',key=b64(key)))
        cases.append(dict(op='write',key=b64(key),value=b64('')))
    rng=random.Random(8131)
    for n in list(range(128))+[255,256,257,1023,4096]:cases.append(dict(op='hash',key=b64(bytes(rng.randrange(256) for _ in range(n)))))
    def table(pairs,capacity=0,remove=()):return dict(capacity=capacity,pairs=[[b64(k),b64(v)] for k,v in pairs],remove=list(map(b64,remove)))
    for count in [0,1,15,16,17,31,32,33,63,64,65,127,128,129,255,256,257,1024]:
        pairs=[(f'key{i}',str(i)) for i in range(count)];rng.shuffle(pairs)
        for capacity in [0,8,16,100,count]:
            pairs2=pairs+[(key,'replacement') for key,_ in pairs[::3]]
            cases.append(dict(op='table',table=table(pairs2,capacity,[key for key,_ in pairs[::4]])))
    edits=[('counter','4'),('hfhe_policy:bad','x'),('slot_policy:bad:revoked','true'),(f'balance_cell:{h}:proof_kind','none'),(f'register_cell:{h}:proof_kind','none'),(f'state_descriptor:{h}:codec','x')]
    for key,value in edits:
        for old,new in [([],[(key,value)]),([(key,value)],[]),([(key,value)],[(key,value)]),([(key,'old')],[(key,value)])]:
            for active in [False,True]:cases.append(dict(op='delta',active=active,before=table(old,100),after=table(new,len(new))))
    for _ in range(64):
        before=rng.sample(edits,len(edits))+[(f'good{i}','value') for i in range(rng.randrange(130))]
        rng.shuffle(before);after=[(k,v if rng.randrange(3)==0 else 'changed') for k,v in before if rng.randrange(4)];rng.shuffle(after)
        for active in [False,True]:cases.append(dict(op='delta',active=active,before=table(before,100),after=table(after,len(after))))
    return cases

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text());pin=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if a.out.exists() or pin!=inventory['upstream_commit']:raise SystemExit('require adopted pin and fresh output')
    for name,h in inventory['files'].items():
        if hashlib.sha256((a.upstream/name).read_bytes()).hexdigest()!=h:raise SystemExit(f'modified upstream: {name}')
    oracle=ROOT/'scripts/node-port/circle-storage-oracle.ml';inputs=fixtures()
    with tempfile.TemporaryDirectory(prefix='octra-circle-storage-') as directory:
        work=pathlib.Path(directory);shutil.copyfile(oracle,work/'main.ml')
        (work/'dune').write_text('(executable (name main) (libraries octra_core octra_circle_runtime yojson base64))\n')
        (work/'input.json').write_text(json.dumps(inputs));(work/'runtime.sha256').write_text(''.join(f'{h}  {name}\n' for name,h in inventory['files'].items()))
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={a.upstream.resolve()},target=/native,readonly',a.builder_image,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && mkdir vpn_circle_storage_oracle && cp /oracle/main.ml /oracle/dune vpn_circle_storage_oracle/ && opam exec -- dune exec ./vpn_circle_storage_oracle/main.exe < /oracle/input.json'],text=True)
    report=dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),builder_image=a.builder_image,scope='Native Circle storage authorization and seed-zero historical table traversal',cases=json.loads(output.splitlines()[-1]))
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n');print(f'PASS: {len(inputs)} native Circle storage cases: {a.out}')
if __name__=='__main__':main()
