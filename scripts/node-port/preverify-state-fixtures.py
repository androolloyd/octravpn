"""Native static and committed-state preverification binding checks."""
import argparse, importlib.util, json, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def fixtures():
    cases=[]
    for op in ['key_switch','encrypt','decrypt','stealth','claim','circle_balance_cell_put','circle_register_cell_put']:
        for key in [None,'none','1'*64]:
            for sender in [True,False]:
                base=dict(op=op,key=key,sender=sender,cipher='hfhe_v1|YWJj',encrypted='YWJj',binding='private')
                cases.append(base)
                for fault in ['wrong_root','wrong_cipher','wrong_key','wrong_input','missing','duplicate']:
                    cases.append(base|{fault:True})
    for op in ['circle_balance_cell_put','circle_register_cell_put']:
        for data in [None,'','!invalid!','AA','AA==']:
            cases.append(dict(op=op,key='1'*64,sender=True,encrypted=data,binding='private'))
    for op in ['key_switch','encrypt','circle_call']:
        for binding in ['unbound','circle']:
            if op=='circle_call' and binding=='unbound': continue
            for wrong in [True,False]:
                cases.append(dict(op=op,key='1'*64,sender=True,binding=binding,wrong_root=wrong))
    for cipher in [None,'','0','hfhe_v1|YWJj']:
        cases.append(dict(op='encrypt',key='1'*64,sender=True,binding='private',cipher=cipher))
    return cases
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',required=True,type=pathlib.Path);p.add_argument('--builder-image',required=True);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/preverify-state-oracle.ml',fixtures(),'octra_core yojson lwt.unix digestif')
    report['scope']='Unmodified Preverify_commit.check_bound, real committed Irmin HEAD and speculative tree, static gate refusal precedence, private source/key and Circle snapshot bindings. Receipt construction is test supplied; cryptographic work and private transition execution are not claimed.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native receipt state bindings')
if __name__=='__main__':main()
