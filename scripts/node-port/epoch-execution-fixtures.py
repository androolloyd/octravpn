"""Qualify the BFT epoch runner using unchanged native Epoch_exec.run_core."""
import argparse, importlib.util, json, pathlib, random
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

def tx(**kw):
    value = dict(op='standard', to=2, amount='100', nonce=1, ou='7', time=1.0, **{'from':1})
    value.update(kw)
    return value

def case(transactions=(), **kw):
    value = dict(chain='epoch-execution-fixture', epoch=1, key_activation=0, packed=False,
                 vm=False, guard=True, bonded=False, transactions=list(transactions),
                 accounts=[dict(id=i, balance='10000000', nonce=0) for i in range(1,5)],
                 meta=[['total_supply','40000000'],['emission_remaining','0']])
    value.update(kw)
    return value

def fixtures():
    cases = [case(), case([tx()]), case([tx(to=5)]), case([tx(to=1)]),
             case([tx(nonce=2),tx(),tx(nonce=3)]),
             case([tx(amount='20000000'),tx(nonce=2)]),
             case([tx(nonce=3),tx(nonce=2)]),
             case([tx(amount='-1')]), case([tx(ou='-1')]),
             case([tx(amount='20'),tx(amount='30')]),
             case([tx(amount='30'),tx(amount='20')])]
    for activation in [None,0,1,2]:
        for key in [True,False]:
            cases.append(case([tx(key=key)],key_activation=activation))
    c = case([tx()]); c['accounts'][0]['key']='stored-key'; cases.append(c)
    for fault in ['reject','charged','abort']:
        cases.append(case([tx(fault=fault),tx(nonce=2)],packed=True))
        cases.append(case([tx(**{'from':2,'to':3}),tx(fault=fault)],packed=True))
        cases.append(case([tx(),tx(**{'from':2,'to':3},fault=fault)],packed=True))
    cases += [case([tx()],fold_fail=True), case([tx()],meta=[['total_supply','bad']]),
              case([tx()],meta=[['total_supply','40000000'],['emission_remaining','1']]),
              case([tx()],meta=[['total_supply','40000000'],['emission_remaining','20000']],guard=False),
              case([tx(op='validator_bond',to='oct111111111111111111111111111111111111111111111')],bonded=True),
              case([tx(op='validator_exit',to=1,amount='0')],bonded=True),
              case([tx(op='validator_bond',to='escrow',amount='1000000'),tx(op='validator_exit',to=1,amount='0',nonce=2)],bonded=True),
              case([tx(op='validator_bond',to='escrow',amount='1000000')],bonded=True,epoch=64)]
    # Native chain height gates, including charged computation and envelope refusal.
    for epoch in [1614499,1614500,1688733,1688734]:
        kw=dict(chain='octra-devnet-9871-cluster',epoch=epoch,vm=epoch>=1688734)
        cases += [case([tx(),tx(nonce=1,time=2.0)],**kw),
                  case([tx(op='compute_fund',fault='charged')],**kw),
                  case([tx(op='compute_settle',fault='charged')],**kw),
                  case([tx(key=False)],**kw)]
    rng=random.Random(2026101340)
    for i in range(36):
        transactions=[tx(**{'from':rng.randrange(1,5)},to=rng.randrange(1,7),nonce=rng.randrange(1,7),
                         amount=str(rng.choice([0,1,100,10000001])),time=float(k+1),
                         **({'fault':rng.choice(['reject','charged'])} if k%7==0 else {})) for k in range(16)]
        cases.append(case(transactions,packed=bool(i%2),key_activation=rng.choice([None,0,2])))
    return cases

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--upstream',type=pathlib.Path,required=True)
    parser.add_argument('--builder-image',required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    if args.out.exists(): raise SystemExit('Require fresh output')
    report=native.run(args.upstream,args.builder_image,ROOT/'scripts/node-port/epoch-execution-oracle.ml',fixtures(),
                      'octra_core octra_consensus yojson lwt.unix mirage-crypto-ec')
    report['scope']='Unmodified Epoch_exec.run_core with real Irmin commit, standard transfers, validator refusals, rewards, account flush and sender keys. Controlled operation faults test savepoints and charged rejection, not VM or compute implementation. Explicit trusted fold inputs; native chain height gates remain active. No cryptographic signature admission or network consensus is claimed.'
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(report['cases']),'native BFT epoch cases')
if __name__=='__main__': main()
