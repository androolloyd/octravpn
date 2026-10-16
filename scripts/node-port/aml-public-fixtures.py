"""Generate bounded differential vectors from the adopted native AML code."""
import argparse,base64,copy,hashlib,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
    rows=[]; rng=random.Random(2026101501)
    def vm(code,inputs=(),cap=1000,activate=None,epoch='0'):
        rows.append(dict(kind='vm',inputs=list(inputs),code=code,cap=cap,activate=activate,epoch=epoch))
    for cap in [1,2,3,4,5,6,50,51,52,1000]:
        vm([['load',1,['int','7']],['load',2,['int','3']],['plus',0,1,2],['stop']],cap=cap)
    for operation in ['plus','minus','times','quotient','remainder','same','different','less','greater']:
        for activate in [None,'0']:
            for a,b in [('7','3'),('-7','3'),('7','-3'),('0','0'),(str(1<<256),str((1<<127)-1))]:
                vm([[operation,0,1,2],['stop']],[['int',a],['int',b]],activate=activate)
        vm([[operation,0,1,2],['stop']],[['bool',True],['int','2']])
    vm([['close',3,1],['close',3,1],['stop']],[['cap',3,7]])
    vm([['close',4,1],['stop']],[['cap',3,7]])
    vm([['close',3,1],['close',3,2],['stop']],[['cap',3,7],['cap',3,8]])
    vm([['stop']],[['int','0']]*61)
    for code in [[],[['noop']],[['jump',99]],[['jump',0]],[['jump_if',1,0]],[['jump_if',1,2],['load',0,['int','9']],['stop']]]:
        vm(code,[['bool',True]],cap=25)
    for start,count in [(-1,2),(0,4),(2,100),(5,1),(1<<63,1),(0,1<<63)]:
        vm([['slice',0,1,2,3],['stop']],[['bytes',base64.b64encode(b'\xffab\x00').decode()],['int',str(start)],['int',str(count)]])
    for depth in [0,1,2,3,10,31,32,1000,999999,1000000]: rows.append(dict(kind='entropy',depth=depth))
    basic=dict(kind='graph',basis=4,slots=2,sigma=2,cap='3',layers=[[10,'base'],[11,'base'],[12,'prod',0,1]],edges=[])
    for i in range(96):
        row=copy.deepcopy(basic);row['cap']=str(rng.choice([1,2,3,20]))
        for _ in range(rng.randrange(9)):
            row['edges'].append([rng.randrange(3),rng.randrange(4),rng.choice(['+','-']),[str(rng.randrange(3)),str(rng.randrange(3))],[rng.choice([True,False]),rng.choice([True,False])]])
        rows.append(row)
    for change in [dict(basis=0),dict(cap='0'),dict(layers=[[0,'prod',0,0]]),dict(edges=[[4,0,'+',['1','2'],[True,False]]]),dict(edges=[[0,4,'+',['1','2'],[True,False]]]),dict(edges=[[0,0,'+',['-1','2'],[True,False]]]),dict(edges=[[0,0,'+',['1'],[True,False]]])]:
        row=copy.deepcopy(basic);row.update(change);rows.append(row)
    return rows
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/aml-public-oracle.ml',fixtures(),'octra_vm yojson zarith base64')
    report['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    report['scope']='Standalone AML VM state/error mutation and integer work modes, graph normalization/depth/field errors, production entropy planning. This does not qualify AML project/proof/certificate execution.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native AML public cases')
if __name__=='__main__':main()
