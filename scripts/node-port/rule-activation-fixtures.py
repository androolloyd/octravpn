"""Native anchored rules and epoch-bound validator context."""
import argparse,base64,importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v.encode() if isinstance(v,str)else v).decode()
CHAIN='octra-devnet-9871-cluster'
EPOCHS=[1293376,1299000,1306321,1306547,1311424,1320000,1325398,1330000,1334000,1353962,1380000,1380960,1425040,1450000,1480000,1500000,1504440,1510000,1572000,1614500,1663000,1688734]
def parent(epoch,**kw):
    v=dict(chain=b64(CHAIN),epoch=str(max(0,epoch-1)),round=1,members=4,signers=[1,2,3]);v.update(kw);return v
def case(epoch,**kw):
    v=dict(kind='graph',chain=b64(CHAIN),epoch=epoch,config=b64('b'*64),default='good',roots={},floor=epoch,probes=EPOCHS,bind_chain=b64(CHAIN),parent=parent(epoch),target=epoch);v.update(kw);return v
def fixtures():
    values=[]
    for chain in [CHAIN,'octra-mainnet','local', '']:
        for epoch in sorted(set([-1,0,1,2**62-1]+[x+d for x in EPOCHS for d in [-1,0,1]]+[1572063,1572064])):
            values.append(case(epoch,chain=b64(chain),bind_chain=b64(chain),parent=parent(epoch,chain=b64(chain))))
    for root in ['missing','bad','unreadable']:
        for epoch in EPOCHS:values.append(case(epoch,default=root))
    for epoch in [1334000,1380000,1450000,1500000,1572000,1688734]:
        for p in [None,parent(epoch,chain=b64('wrong')),parent(epoch,corrupt=True),parent(epoch,signers=[1])]:values.append(case(epoch,parent=p))
        values.append(case(epoch,target=epoch+1))
    for plan in [None,dict(anchor=10,root=b64('custom'),activate=20),dict(anchor=-10,root=b64(b'\xff\x00'),activate=-1)]:
        for epoch in [-1,19,20,84,2**62-1]:
            for root in ['missing','bad','unreadable','good']:
                values.append(dict(kind='activation',plan=plan,epoch=epoch,default=root))
    for floor in [0,1293376,1298999,1299000,1380960,1504440]:values.append(case(1700000,floor=floor))
    return values
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/rule-activation-oracle.ml',fixtures(),'octra_core octra_node_runtime octra_consensus yojson mirage-crypto-ec')
    report['scope']='Anchored Rule_graph and Set_rule bind, native profiles/floors/fault priority, signed parent membership. Roots and parent selection are fixture inputs, not bootstrap authority.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native activation cases')
if __name__=='__main__':main()
