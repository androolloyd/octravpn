#!/usr/bin/env python3
"""Native checkpoint/manifest commitment and signer differential vectors."""
import argparse,base64,copy,hashlib,importlib.util,json,random,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def sha(v):return hashlib.sha256(v).hexdigest()
def b64(v):return base64.b64encode(v).decode()
def lp(v):return struct.pack('>I',len(v))+v
def root(files):
    data=struct.pack('>I',sum(len(f['chunks']) for f in files))
    for f in files:
        for c in f['chunks']:
            data+=lp(f['path'].encode())+struct.pack('>IQI',c['index'],int(c['offset']),c['size'])+bytes.fromhex(c['sha256'])
    return sha(b'octra:state_sync_chunks\0'+data)
def file(path='HEAD.json',size=3):
    return dict(path=path,size=str(size),sha256=sha(b'file'),chunks=[dict(index=0,offset='0',size=size,sha256=sha(b'chunk'))] if size else [])
def manifest(files=None):
    files=files or [file()]
    return dict(version='octra-state-sync',checkpoint_hash='11'*32,snapshot_id='11'*32,irmin_commit=None,chunk_size=1048576,total_size=str(sum(int(f['size']) for f in files)),file_count=len(files),chunk_count=sum(len(f['chunks']) for f in files),chunks_root=root(files),files=files)
def checkpoint():
    return dict(chain_id='octra-devnet-9871-cluster',epoch='1692994',state_root='11'*32,ledger_state_root='22'*64,txid_hi='2620493',config_hash='33'*32,validator_set_hash='44'*32,quorum_cert_hash='55'*32,epoch_index_hash='66'*32,epoch_index_root='77'*32,created_at='1000',valid_until='2000')
def checkpoint_hash(c):
    data=lp(c['chain_id'].encode())+struct.pack('>Q',int(c['epoch']))+bytes.fromhex(c['state_root'])+lp(c['ledger_state_root'].encode())+struct.pack('>Q',int(c['txid_hi']))
    data+=bytes.fromhex(c['config_hash'])+bytes.fromhex(c['validator_set_hash'])
    for name in ['quorum_cert_hash','epoch_index_hash','epoch_index_root']:
        data+=b'\0' if c[name] is None else b'\1'+bytes.fromhex(c[name])
    return sha(b'octra:state_sync_checkpoint\0'+data+struct.pack('>QQ',int(c['created_at']),int(c['valid_until'])))
def manifest_hash(m):
    data=lp(m['version'].encode())+bytes.fromhex(m['checkpoint_hash'])+lp(m['snapshot_id'].encode())
    data+=b'\0' if m['irmin_commit'] is None else b'\1'+lp(m['irmin_commit'].encode())
    data+=struct.pack('>IQII',m['chunk_size'],int(m['total_size']),m['file_count'],m['chunk_count'])+bytes.fromhex(m['chunks_root'])+struct.pack('>I',len(m['files']))
    for f in m['files']:
        data+=lp(f['path'].encode())+struct.pack('>Q',int(f['size']))+bytes.fromhex(f['sha256'])+struct.pack('>I',len(f['chunks']))
        for c in f['chunks']:
            data+=lp(f['path'].encode())+struct.pack('>IQI',c['index'],int(c['offset']),c['size'])+bytes.fromhex(c['sha256'])
    return sha(b'octra:state_sync_manifest\0'+data)
def cases():
    out=[]
    def add(op,value,**extra):out.append(dict(op=op,raw=b64(json.dumps(value,separators=(',',':')).encode()),**extra))
    body=checkpoint();add('checkpoint',body)
    for field in body:
        for value in [None,True,[],{},'',0,-1,'-1','0','A'*64,'0'*64,'9223372036854775807','18446744073709551616','0x7f','1_024']:
            b=body.copy();b[field]=value;add('checkpoint',b)
        b=body.copy();del b[field];add('checkpoint',b)
        b=body.copy();b[field]=('88'*32 if field.endswith(('hash','root')) else '1001');add('same',dict(left=body,right=b))
    for epoch in ['0','4611686018427387903','4611686018427387904','9223372036854775807']:
        b=body.copy();b['epoch']=epoch;add('checkpoint',b)
    for start,end in [(0,1),(1,2678401),(1,2678402),(1000,1000),(1000,999),(9223372036854775806,9223372036854775807)]:
        b=body.copy();b.update(created_at=str(start),valid_until=str(end));add('checkpoint',b)
    for n in [0,128,129]:
        b=body.copy();b['chain_id']='x'*n;add('checkpoint',b)
    for n in [0,1,256,257]:
        b=body.copy();b['ledger_state_root']='r'*n;add('checkpoint',b)
    # Duplicate fields must remain visible to the native exact-field check.
    for field in body:
        raw=json.dumps(body)[:-1]+','+json.dumps(field)+':null}'
        out.append(dict(op='checkpoint',raw=b64(raw.encode())))
    m=manifest();add('manifest',m)
    for field in m:
        for value in [None,True,[],{},'',0,-1,1,'1','f'*64]:
            changed=copy.deepcopy(m);changed[field]=value;add('manifest',changed)
    for path in ['', '/', '../x','x/../y','x//y','x/./y','x/','/absolute','a\\b','a\0b','a'*1024,'a'*1025,'HEAD.json','ready_roots','pvac/migration_state.json','pvac/blobs/'+'a'*64+'.pk','pvac/blobs/'+'A'*64+'.pk','C:/file','hello/é']:
        add('path',path);add('reference_file',path)
        f=file(path);add('file',f,chunk_size=1048576)
    for field in ['index','offset','size','sha256']:
        for value in [None,-1,0,1,4,1048577,'1','-1','bad','F'*64]:
            f=file();f['chunks'][0][field]=value;add('file',f,chunk_size=1048576)
    for f in [file(size=0),dict(file(),size='4'),dict(file(),chunks=[]),dict(file(),size='0'),dict(file(),size='-1')]:add('file',f,chunk_size=1048576)
    for paths in [['HEAD.json','ledger.dat','ready_roots','state_root'],['HEAD.json','ledger.dat','state_root'],['bad'],['HEAD.json','HEAD.json'],['state_root','HEAD.json']]:
        m=manifest([file(p) for p in paths]);add('manifest',m);add('reference',m)
    rng=random.Random(71)
    for n in range(1,40):
        files=[file(f'file-{i:03}',rng.randrange(1,100000)) for i in range(n)]
        add('manifest',manifest(files))
    for value in ['', 'x','!!!!','AAAA','AAAA====',b64(bytes(32)),b64(bytes(64)),b64(bytes([1])+bytes(31)),b64(bytes([255])*32)]:
        add('pubkey',value);add('signature',value)
    for weighted in [False,True]:
        for weights in [[1,1,1,1],[1000,1,1,1]]:
            for signers in [[],[0],[0,1],[0,1,2],[0,1,2,3],[0,0,1,2]]:
                for epoch in ['100','1692994']:
                    b=body.copy();b['epoch']=epoch
                    add('quorum',b,weighted=weighted,weights=weights,signers=signers,ordered=True,tamper=False,mutate=False)
    for tamper,mutate,ordered in [(True,False,True),(False,True,True),(False,False,False)]:
        add('quorum',body,weighted=False,weights=[1]*4,signers=[0,1,2,3],ordered=ordered,tamper=tamper,mutate=mutate)
    for signers in [[],[0],[0,1],[0,1,2,3],[0,0]]:
        for required in [1,2,4]:
            for tamper,mutate,ordered in [(False,False,True),(True,False,True),(False,True,True),(False,False,False)]:
                add('exporters',body,weighted=False,weights=[1]*4,signers=signers,ordered=ordered,tamper=tamper,mutate=mutate,required=required,message=b64(b'snapshot manifest commitment'))
    public='iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w='
    address='oct4XmjKEd9A96KhoMX94zWJmd28dcPisbWGYWtad1dQ9v5'
    entry=address+':'+public
    for entries in [[],[entry],[entry,entry],[' '+entry+'\n'],['\v'+entry],['x:'+public],[address+':AAAA'],[':'],['x'],[entry+':x'],[address+':'+b64(bytes(32))]]:add('entries',entries)
    for op in ['pubkey','signature']:
        for value in [public,public+'=',public+'====',public[:-1],public[:-2]+'x=',public+'\n']:
            add(op,value)
    for op in ['checkpoint','manifest','file']:
        for value in [None,[],True,'',0]:add(op,value,chunk_size=1048576)
    # A valid two-chunk file, then gaps, overlaps, duplicate indexes, and total overflow.
    f=file(size=7);f['chunks']=[dict(index=0,offset='0',size=3,sha256=sha(b'a')),dict(index=1,offset='3',size=4,sha256=sha(b'b'))]
    add('manifest',manifest([f]))
    for name,value in [('offset','2'),('offset','4'),('index',0),('size',3),('size',5)]:
        changed=copy.deepcopy(f);changed['chunks'][1][name]=value;add('file',changed,chunk_size=1048576)
    changed=manifest([dict(file('a'),size=str(2**63-1)),file('b')]);add('manifest',changed)
    # Certificate parsing and draft commitments are deliberately separate from finality verification.
    c=checkpoint();h=checkpoint_hash(c);m=manifest([file(p) for p in ['HEAD.json','ledger.dat','ready_roots','state_root']]);m.update(checkpoint_hash=h,snapshot_id=h)
    draft=dict(version='octra-state-sync',checkpoint=c,checkpoint_hash=h,manifest=m,manifest_hash=manifest_hash(m));add('draft',draft)
    dummy=dict(signer=address,signature=b64(bytes(64)))
    for finality in [False,True]:
        cert=copy.deepcopy(draft)
        cert.update(dict(finality='',exporter_signatures=[]) if finality else dict(checkpoint_signatures=[],exporter_signature=dummy))
        for now in ['699','700','1000','2000','2001',str(2**63-1)]:add('certificate',cert,now=now)
        for name in cert:
            for value in [None,True,[],{},'',0,'bad']:
                changed=copy.deepcopy(cert);changed[name]=value;add('certificate',changed,now='1000')
            changed=copy.deepcopy(cert);del changed[name];add('certificate',changed,now='1000')
            raw=json.dumps(cert)[:-1]+','+json.dumps(name)+':null}'
            out.append(dict(op='certificate',raw=b64(raw.encode()),now='1000'))
        for name in ['checkpoint_hash','manifest_hash']:
            changed=copy.deepcopy(cert);changed[name]='aa'*32;add('certificate',changed,now='1000')
        changed=copy.deepcopy(cert);changed['manifest']['checkpoint_hash']='aa'*32;add('certificate',changed,now='1000')
        if finality:
            changed=copy.deepcopy(cert);changed['exporter_signatures']=[dummy]*1025;add('certificate',changed,now='1000')
        else:
            changed=copy.deepcopy(cert);changed['checkpoint_signatures']=[dummy]*1025;add('certificate',changed,now='1000')
    for name in draft:
        changed=copy.deepcopy(draft);changed[name]=None;add('draft',changed)
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/state-sync-oracle.ml',cases(),'octra_bootstrap octra_core octra_consensus octra_net yojson base64 mirage-crypto-ec')
    report['generator_sha256']=sha(Path(__file__).read_bytes());report['scope']='Snapshot checkpoint and manifest commitments, file layout and checkpoint signature quorum; finalized snapshot authority and state import remain separate.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native state-sync vectors')
if __name__=='__main__':main()
