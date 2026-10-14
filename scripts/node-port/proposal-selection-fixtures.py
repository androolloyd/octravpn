#!/usr/bin/env python3
"""Compare native staging-order proposal limits, private slots and Circle turns."""
import argparse, hashlib, importlib.util, json, pathlib, random
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

def fixtures():
    cases = []
    def tx(op='standard', sender='a', nonce=1, message='payload', fee=1000):
        return dict(op=op, sender='oct_'+sender, nonce=nonce, message=message, fee=fee)
    def add(txs, **kwargs):
        value = dict(txs=txs, ready=list(range(len(txs))), ordinary=[], parent='none', epoch=12,
                     count=100, bytes=1000000, ou=1000000, fhe=8, stealth=4, ordered=True)
        value.update(kwargs)
        cases.append(value)
    add([])
    public = [tx(sender=s) for s in 'cba']
    # Caps are prefix-based and charge scheduled cost, not the offered fee.
    for count in [0,1,2,3,4]: add(public, count=count)
    for ou in [-1,0,999,1000,1999,2000,2999,3000,3001]: add(public, ou=ou)
    for fee in [1000,100000,999999999]: add([tx(fee=fee)], ou=1000)
    for size in [0,1023,1024,1100,1500,2048]:
        add([tx(message='x'*700),tx(sender='b'),tx(sender='c')], bytes=size)
    for offset in [-1,0,1]: add([tx(message='x'*1500),tx(sender='b')],byte_offset=offset)
    private = [tx('decrypt'),tx('stealth',nonce=2),tx(nonce=3),tx('encrypt','b'),tx('claim','c'),tx('key_switch','d')]
    for fhe in [0,1,2,8]:
        for stealth in [0,1,4]:
            add(private, fhe=fhe, stealth=stealth)
            add(private, fhe=fhe, stealth=stealth, ready=[1,2,3,4,5])
    for op in ['circle_call','circle_balance_cell_put','circle_register_cell_put','deploy_circle','circle_asset_put','circle_program_update','standard']:
        for ordered in [False,True]:
            for parent in ['none','empty','valid','missing','mismatch','hash','chain','epoch']:
                for head in [8,9,10,11,12]:
                    message=json.dumps(dict(consensus_pubkey='key', head_epoch=head, state_root='root'))
                    add([tx(op),tx('validator_ready','b',message=message),tx(nonce=2)],
                        ordinary=[1], parent=parent, ordered=ordered)
    add(public,parent='none',epoch=0)
    rng=random.Random(0x7f9be448)
    ops=['standard','encrypt','decrypt','stealth','claim','key_switch','circle_call','deploy_circle']
    for _ in range(350):
        nonces={}
        txs=[]
        for i in range(rng.randrange(12)):
            sender=rng.choice('abcd')
            nonces[sender]=nonces.get(sender,0)+1
            txs.append(tx(rng.choice(ops),sender,nonces[sender],str(i),rng.choice([1000,5000,100000])))
        add(txs,ready=[i for i in range(len(txs)) if rng.randrange(4)],
            count=rng.randrange(8),bytes=rng.choice([0,1024,2500,10000]),ou=rng.randrange(50000),
            fhe=rng.randrange(6),stealth=rng.randrange(3))
    return cases

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--upstream',type=pathlib.Path,required=True)
    p.add_argument('--builder-image',required=True)
    p.add_argument('--out',type=pathlib.Path,required=True)
    a=p.parse_args()
    if a.out.exists(): raise SystemExit('require fresh report')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/proposal-selection-oracle.ml',fixtures(),
                      'octra_node_runtime octra_core octra_consensus octra_net yojson')
    report['generator_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    report['scope']='Unmodified native proposal caps, private slots, Circle turns and parent bundle classification. Dummy signatures and unauthenticated parent records test selection only; canonical parent authentication remains a separate gate.'
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS',len(report['cases']),'native proposal selection cases')
if __name__=='__main__': main()
