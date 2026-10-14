"""Native complete validator epoch advancement and committed Circle roots."""
import argparse,base64,importlib.util,itertools,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v.encode() if isinstance(v,str) else v).decode()
CHAIN=b64('local-validator-epoch')
def parent(epoch,**kw):
    v=dict(chain=CHAIN,epoch=str(epoch-1),round=1,members=4,signers=[1,2,3]);v.update(kw);return v
def step(epoch,**kw):
    v=dict(epoch=epoch,parent=parent(epoch),start='0',members=[1,2,3,4],legacy=[1,2,3,4],writes=[],queries=[str(max(0,epoch-1))],previous=b64(bytes([4])*32));v.update(kw);return v
def case(rounds,**kw):
    v=dict(chain=CHAIN,count=7,rounds=rounds);v.update(kw);return v
def write(path,value):return dict(path=path,value=b64(value))
def pending(source=0,activate=64,members=None,**kw):
    return dict(source=str(source),activate=str(activate),members=members or [1,2,3,4],**kw)
def head(epoch,entries=None):return dict(epoch=str(epoch) if epoch is not None else None,entries=entries or [])
def fixtures():
    out=[]
    for count,inactive in itertools.product([0,3,4,7,65],[False,True]):
        out.append(case([step(e) for e in [0,1,63,64,127,128,192]],count=count,inactive=inactive))
    for flags in itertools.product([False,True],repeat=5):
        modes=dict(zip(['live','seat','open','standard','plan'],flags),duty=True,prune=True)
        out.append(case([step(e,start='200',**modes) for e in [1,2,56,60,64,68,72,128,192,200,256]]))
    for standard,live,plan in itertools.product([False,True],repeat=3):
        out.append(case([step(e,duty=True,seat=True,prune=True,standard=standard,live=live,plan=plan) for e in range(1,146)]))
    for unready,exited in itertools.product([False,True],repeat=2):
        out.append(case([step(e) for e in [0,64,128]],unready=unready,exited=exited))
    for plan in [False,True]:
        out.append(case([step(0,pending=pending(0,128,noncanonical=True),plan=plan),step(64,plan=plan),step(128,plan=plan)]))
        out.append(case([step(64,pending=pending(0,64,[3,4,5,6],noncanonical=True),plan=plan,duty=True,live=True,seat=True,prune=True,start='200')]))
    for key in ['validator_registry','validator_set_pending','validator_set_fold']:
        # Resolve native metadata names in the oracle runner below.
        for epoch in [1,64]:
            out.append(case([step(epoch,duty=True,seat=True,prune=True,writes=[write(['meta',key],b'{')])]))
    for p in [None,parent(64,chain=b64('wrong')),parent(64,corrupt=True),parent(64,signers=[1])]:
        out.append(case([step(64,duty=True,parent=p)]))
    out.append(case([step(64,duty=True,seat=True,legacy=[])]))
    out.append(case([step(64,duty=True,fold_fail=True)]))
    out.append(case([step(64,duty=True),step(64,duty=True,parent=None),step(63,duty=True)]))
    # Committed snapshots deliberately differ from the working Circle tree.
    for entries in [[],[write(['circles'],'leaf')],[write(['circles','app','state','value'],b'\xff\x00'),write(['accounts','outside'],'ignored')]]:
        out.append(case([step(2,vm=True,head=head(1,entries),writes=[write(['circles','speculative'],'must not be captured')]),step(67,vm=True,head=head(66),queries=['1','66'])]))
    for h in [None,head(None),head(-1),head(0),head(2)]:
        out.append(case([step(2,vm=True,head=h)]))
    for previous in [b'bad',b'05'*32,b'04'*32]:
        out.append(case([step(2,vm=True,head=head(1),previous=b64(previous))]))
    out.append(case([step(0,vm=True,head=head(0))]))
    out.append(case([step(2,vm=True,parent=None,head=head(1))]))
    out.append(case([step(64,vm=True,duty=True,head=head(63,[write(['circles','app'],'published')]),writes=[write(['meta','validator_set_pending'],'{')])]))
    out.append(case([step(64,duty=True,seat=True,prune=True,start='200',members=list(range(1,70)),legacy=list(range(1,70)))],count=80))
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    cases=fixtures()
    # These names are source-pinned, never learned from Rust output.
    keys={}
    import re
    for filename,name in [('validator_registry.ml','validator_registry'),('validator_set_update.ml','validator_set_pending'),('set_fold.ml','validator_set_fold')]:
        source=(a.upstream/'lib/core'/filename).read_text()
        key='pending_meta_key' if name=='validator_set_pending' else 'meta_key'
        keys[name]=re.search(r'let '+key+r' = "([^"]+)"',source).group(1)
    for c in cases:
        for r in c['rounds']:
            for w in r['writes']:
                if w['path'][0]=='meta':w['path'][1]=keys.get(w['path'][1],w['path'][1])
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/validator-epoch-oracle.ml',cases,'octra_core octra_node_runtime octra_consensus yojson mirage-crypto-ec')
    report['scope']='Native Epoch_exec.advance_validator_set under epoch savepoints, signed parent fixtures, pending promotion/scheduling, duty transitions, committed Circle projection and ring replacement; fixture membership and published head are inputs.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native sequences',sum(len(c['rounds']) for c in cases))
if __name__=='__main__':main()
