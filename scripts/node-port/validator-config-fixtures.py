"""Native boot configuration, durable membership and startup admission."""
import argparse,base64,importlib.util,itertools,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def b64(v):return base64.b64encode(v.encode() if isinstance(v,str)else v).decode()
def update(epoch=64,source=0,ids=None,**kw):return dict(epoch=str(epoch),source=str(source),ids=ids or [1,2,3,4],**kw)
def case(**kw):
    v=dict(chain=b64('local-config'),consensus=True,height='0',current=[1,2,3,4],next=[],chain_pending=[],activate=None,program=None,profile=None,active_raw=None,pending_raw=None,self=1,voting=True,role=b64('validator'),admission=None,unsafe=None);v.update(kw);return v
def fixtures():
    cases=[]
    for chain,count,height,next in itertools.product(['local-config','octra-devnet-9871-cluster'],[0,3,4,7],[0,63,64,65,1306547],[[],[7,6,5,4]]):
        cases.append(case(chain=b64(chain),current=list(range(count,0,-1)),height=str(height),next=next,activate='64'))
    for program,profile,consensus in itertools.product([None,b64(b'p'*32)],[None,b64(b'r'*32)],[False,True]):
        cases.append(case(program=program,profile=profile,consensus=consensus,next=[5,6,7,8],activate='64'))
    for active,pending,height in itertools.product([None,update(),update(weighted=False)],[None,update(),update(128,64,[3,4,5,6],weights=['1000000','1','1','1']),update(32,0),update(weighted=False),b64('{}'),b64('null')],[63,64,65,128,129]):
        cases.append(case(active_raw=active,pending_raw=pending,height=str(height),next=[5,6,7,8],activate='96'))
    for chain,epoch in itertools.product(['local-config','octra-devnet-9871-cluster'],[1306546,1306547,1306548]):
        cases.append(case(chain=b64(chain),height=str(epoch),active_raw=update(64,0,weights=['1000000','1','2','3']),pending_raw=update(1306547,64,[4,5,6,7],weights=['1','9000000','3','1'])))
    # Startup precedence, including observer/permissionless and unsafe-quorum knobs.
    for count,self_id,voting,admission,unsafe in itertools.product([0,3,4],[1,7],[False,True],[None,b64('64'),b64('63'),b64('garbage')],[None,b64('1')]):
        cases.append(case(current=list(range(1,count+1)),self=self_id,voting=voting,admission=admission,unsafe=unsafe))
    for height,self_id,voting in itertools.product([0,64],[1,7,9],[False,True]):
        cases.append(case(height=str(height),next=[5,6,7,8],activate='64',self=self_id,voting=voting))
        cases.append(case(height=str(height),next=[5,6,7,8],activate=None,self=self_id,voting=voting))
    bad=[b64('bad'),dict(id=1,address=b64('x')),dict(id=1,key=b64('wrong')),dict(id=1,address=b64(b'\xff\x00addr')),1,1,dict(id=1,address=b64('alias'))]
    for field in ['current','next','chain_pending']:
        cases.append(case(**{field:bad},activate='64',admission=b64('64')))
    for raw in [' {} ', '[]','null','{"weighted":true}', '{"activate_epoch":"64","validators":[]}']:
        cases.append(case(active_raw=b64(raw),pending_raw=update(weighted=False)))
    cases.append(case(self=b64(b'\xffunknown'),voting=False,role=b64(b'\xff\x00observer')))
    cases.append(case(current=[],next=[1,2,3,4],activate='0',height='0'))
    for primary,fallback in itertools.product([None,b64('bad'),b64(''),b64('0x40')],[None,b64('64'),b64('bad')]):
        cases.append(case(primary=primary,fallback=fallback,next=[5,6,7,8],height='64'))
    for relief in [None,'error',{},dict(future=True),dict(wrong=True),dict(bad_signature=True)]:
        cases.append(case(chain=b64('octra-devnet-9871-cluster'),height='1380000',current=list(range(1,8)),active_raw=update(1379900,1379836,list(range(1,8))),pending_raw=update(1380032,1379968,list(range(1,7))),relief=relief))
    return cases
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/validator-config-oracle.ml',fixtures(),'octra_core octra_node_runtime octra_consensus yojson mirage-crypto-ec')
    report['scope']='Unmodified native Validator_config build_full, bind_persistent_updates, dynamic pending loader and node startup admission, including capped consensus identity. Consensus_validator_anchor includes env fallback, signed relief and round-sensitive lock recovery. Generated entry/update/relief bytes are explicit inputs.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native configurations')
if __name__=='__main__':main()
