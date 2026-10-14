#!/usr/bin/env python3
"""Native relief journal encoding, durability, conflicts and recovery."""
import argparse, base64, copy, importlib.util, json, pathlib, random
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)

def fixtures():
    source=json.loads((ROOT/'crates/octra-node-protocol/tests/fixtures/consensus-wire.json').read_text())['cases']
    proof=[c['input']['wire']for c in source if c['input']['kind']=='sync'and'error'not in c['expected']][:3]
    def mark(**kw):return dict(height='100',round=64,activate_epoch='120',source_hash='01'*32,target_hash='02'*32,fingerprint=(b'f'*64).hex(),proof=proof[:1])|kw
    def action(op,**kw):return dict(op=op,height='100')|kw
    def keep(m):return action('keep',height=m['height'],mark=m)
    def wire(m):
        value=dict(standard='octra-consensus-relief',height=m['height'],round=m['round'],activate_epoch=m['activate_epoch'],source_hash=m['source_hash'],target_hash=m['target_hash'],fingerprint=bytes.fromhex(m['fingerprint']).decode(),proof=[base64.b64encode(bytes.fromhex(p)).decode()for p in m['proof']])
        return json.dumps(value,separators=(',',':')).encode()
    out=[]
    for mode in ['memory','disk']:
        steps=[action('latest'),keep(mark()),keep(mark(round=100,proof=proof)),keep(mark(fingerprint=(b'e'*64).hex())),action('restart'),action('latest',height='99'),action('latest')]
        if mode=='disk':steps.append(action('read'))
        steps += [keep(mark(height='101',activate_epoch='130')),action('prune',height='118'),action('latest'),action('prune',height='119'),action('latest'),action('latest',height='101'),action('prune',height='129'),action('latest',height='101')]
        out.append(dict(mode=mode,steps=steps))
        steps=[keep(mark(height=str(n),activate_epoch='1000'))for n in range(65)]
        steps += [action('latest',height='1000'),action('prune',height='999'),action('latest',height='1000')]
        out.append(dict(mode=mode,steps=steps))
        for height in [-2**63,-1,0,1,2**63-1]:
            for activation in [-2**63,-1,0,1,2**63-1]:
                out.append(dict(mode=mode,steps=[keep(mark(height=str(height),activate_epoch=str(activation))),action('latest',height=str(height)),action('prune',height=str(activation)),action('latest',height=str(height))]))
    for fingerprint in [b'',b'\x00\xff\x80"\\\n\r\t',bytes(range(256))]:
        out.append(dict(mode='disk',steps=[keep(mark(fingerprint=fingerprint.hex())),action('read'),action('restart'),action('latest')]))
    base=wire(mark());obj=json.loads(base)
    corrupt=[b'',b'{',b'[]',b'null',base+b'\n',b' '+base,base.replace(b'"100"',b'"0100"'),base.replace(b'"100"',b'"0x64"'),base.replace(b'"round":64',b'"round":4.0'),base.replace(b'"source_hash":"01',b'"source_hash":"0_'),base.replace(b'"source_hash":"01',b'"source_hash":"FF'),wire(mark(height='101')),base+b' '*262145]
    def dump(v):return json.dumps(v,separators=(',',':')).encode()
    for field in obj:
        absent=copy.deepcopy(obj);del absent[field];corrupt.append(dump(absent))
        for value in [None,False,1,'',[],{},'0xFFFFFFFFFFFFFFFF']:
            changed=copy.deepcopy(obj);changed[field]=value;corrupt.append(dump(changed))
    for value in ['*','AAAA','====',base64.b64encode(bytes.fromhex(proof[0])[:-1]).decode(),base64.b64encode(bytes.fromhex(proof[0])+b'\x00').decode()]:
        changed=copy.deepcopy(obj);changed['proof']=[value];corrupt.append(dump(changed))
    for data in corrupt:
        out.append(dict(mode='disk',steps=[action('corrupt',data=data.hex()),action('latest'),keep(mark()),action('prune',height='999')]))
    for count in [0,1,63,64,65]:out.append(dict(mode='disk',steps=[action('stage',count=count),keep(mark()),action('latest')]))
    out.append(dict(mode='disk',steps=[action('symlink',data=base.hex()),action('latest'),keep(mark()),action('prune',height='999')]))
    for name in ['100.mark','00000000000000000100.mark.staged','junk','0000000000000000010a.mark','-0000000000000000001.mark']:
        out.append(dict(mode='disk',steps=[action('file',name=name.encode().hex(),data=base.hex()),action('latest',height='1000'),action('prune',height='999')]))
    rng=random.Random(2026101311)
    for mode in ['memory','disk']:
        for _ in range(24):
            steps=[]
            for n in range(70):
                op=rng.choice(['keep']*4+['latest','latest','prune','restart'])
                height=rng.randrange(80,150)
                steps.append(keep(mark(height=str(height),round=rng.randrange(64,100),activate_epoch=str(height+20),proof=rng.choice([proof,[]]),fingerprint=(b'f'*64 if rng.randrange(4)else b'e'*64).hex()))if op=='keep'else action(op,height=str(height)))
            out.append(dict(mode=mode,steps=steps))
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/relief-log-oracle.ml',fixtures(),'octra_consensus yojson')
    report['scope']='Unmodified native relief journal through its public memory/disk API. Exact record bytes, semantic diagnostics, conflicts, restart and pruning; OS and malformed JSON parser diagnostic text is normalized, acceptance is not.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native relief journal traces")
if __name__=='__main__':main()
