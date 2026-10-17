#!/usr/bin/env python3
"""Qualify generated prepaid Circle code with unchanged native compiler/epochs.

Requires the local compile-circle-payments JSON from the exact candidate binary.
No production endpoint, funding or consensus activation is involved.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/node-port' / name)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def oracle():
    # Reuse the existing full native epoch harness, retaining its real store and
    # Ledger between epochs. No native runtime body or clock rule is changed.
    base = (ROOT / 'scripts/node-port/circle-code-oracle.ml').read_text()
    marker = 'let ()=let input=Yojson.Safe.from_channel stdin'
    assert base.count(marker) == 1, 'native epoch oracle entrypoint changed'
    body = base.split(marker)[0]
    head, run = body.split('let run index input=\n')
    initial, epoch = run.split(' let root=Lwt_main.run(S.state_hash store)in\n')
    assert epoch.count(' Lwt_main.run(S.close store);output') == 1
    epoch = epoch.replace(' Lwt_main.run(S.close store);output', ' output,(store,ledger)')
    retained = ('let run_saved index input saved=\n'
        ' let tx_inputs=member"transactions"input|>to_list in\n'
        ' let store,ledger=match saved with Some pair->pair|None->\n'
        + initial + ' (store,ledger) in\n'
        + ' let root=Lwt_main.run(S.state_hash store)in\n' + epoch)
    return head + retained + (ROOT / 'scripts/node-port/circle-prepaid-oracle-tail.ml').read_text()

def fixtures(build):
    calls = module('circle-octb-execution-fixtures.py')
    out = []
    app = calls.code.payload(runtime='octb', code_b64=build['bytecode'])
    factory = calls.code.payload(runtime='octb', code_b64=build['factory_bytecode'])
    def add(name, actions=None, *, spawned=True, proof=True, phases=None):
        phases = [(123_500, actions)] if phases is None else phases
        nonce = 1
        steps = []
        for index, (now, actions) in enumerate(phases):
            rows = []
            if index == 0:
                rows = [calls.tx('deploy', factory if spawned else app, nonce, to='$derive', ou=5_000_000)]
                nonce += 1
                if spawned:
                    payload = calls.b64(json.dumps(app, separators=(',', ':')))
                    rows += [calls.tx('call', [payload], nonce, method='deploy_payments', ou=5_000_000)]
                    nonce += 1
            for method, params, amount in actions:
                rows.append(calls.tx('call',params,nonce,method=method,amount=amount,
                    to='$child' if spawned else '$previous',ou=5_000_000))
                nonce += 1
            steps.append(dict(now=now/1000,transactions=rows))
        out.append(dict(name=name, phases=steps, spawned=spawned, entries=[],
            accounts=[dict(address=calls.b64(calls.SENDER), nonce=0, balance='1000000000000')],
            epoch=3, proof=proof, inspect=True, storage_proof=True,
            float=False, math=True, circle_policy=False, wasm_compute=True))
    init = ('initialize', [], 0)
    bond = ('bond_operator', [], 100_000_000)
    register = ('register', ['$REGISTER_KEY', '$REGISTER_SIGNATURE'], 0)
    fund = ('fund', [calls.SENDER], 5_000_000)
    quote = [('create_offer', ['b'*64], 0), ('append_class', [0,10], 0),
             ('seal_offer', [0], 0), ('open_plan', [0,1000], 0)]
    claim = ('claim', [0,0,1,1_048_576,'$CLAIM_SIGNATURE'], 0)
    add('parent-owned Circle prepaid custody', [init, init, bond, register, fund, *quote,
        claim, claim, ('withdraw_channel', [5_000_001],0), ('withdraw_remaining',[],0),
        ('request_operator_unstake',[],0), ('request_operator_unstake',[],0),
        ('withdraw_operator_stake',[],0)])
    add('uninitialized Circle rejects financial calls', [bond, register, fund,
        ('create_offer',['b'*64],0), ('request_exit',[],0), ('withdraw_remaining',[],0), init])
    add('prior proof rules cannot transfer custody out', [init,register,fund,
        ('withdraw_remaining',[],0)], proof=False)
    add('direct Circle deployment deterministic initialization', [init,init,bond,
        ('request_operator_unstake',[],0)], spawned=False)
    change = [('create_rate_change',[0,'c'*64],0),('append_class',[1,20],0),('seal_offer',[1],0)]
    day, week, start = 86_400_000, 604_800_000, 123_500
    add('rate activation and exact seven-day unstake',phases=[
        (start,[init,bond,register,fund,*quote,claim,*change]),
        (start+day-1,[('open_plan',[1,1],0),('open_plan',[0,1],0)]),
        (start+day,[('open_plan',[0,1],0),('open_plan',[1,1],0),('can_forward',[0],0),('request_operator_unstake',[],0)]),
        (start+day+week-1,[('request_operator_unstake',[],0),('withdraw_operator_stake',[],0)]),
        (start+day+week,[('withdraw_operator_stake',[],0)]),
    ])
    add('replacement cancellation and reschedule retain full notice',phases=[
        (start,[init,bond,register,fund,*quote,*change]),
        (start+1000,[('create_rate_change',[0,'d'*64],0),('append_class',[2,30],0),('seal_offer',[2],0)]),
        (start+day,[('open_plan',[1,1],0),('open_plan',[2,1],0),('cancel_rate_change',[2],0),('open_plan',[0,1],0)]),
        (start+1000+day,[('open_plan',[2,1],0),('open_plan',[0,1],0)]),
    ])
    return out

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', required=True, type=Path)
    parser.add_argument('--builder-image', required=True)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit('Require fresh output')
    build = json.loads(args.build.read_text())
    assert build['application'] == 'circle' and build['typed_admission'] is False
    assert build['terms'] == dict(domain=args.domain,custody_cap=200_000_000,minimum_stake=100_000_000)
    assert build['certificate']['source_hash'] == hashlib.sha256(build['source'].encode()).hexdigest()
    core = ROOT / 'program/octranet-payments.aml'
    init = ROOT / 'program/octranet-payments-circle-init.aml.in'
    factory = ROOT / 'program/octranet-payments-circle-factory.aml'
    assert build['core_source_sha256'] == digest(core)
    assert build['initializer_sha256'] == digest(init)
    assert build['factory_source_sha256'] == digest(factory)
    counter = json.loads((ROOT / 'crates/octra-node-runtime/tests/fixtures/circle-view.json').read_text())
    source = oracle()
    with tempfile.TemporaryDirectory(prefix='octra-circle-prepaid-oracle-') as directory:
        path = Path(directory) / 'oracle.ml'
        path.write_text(source)
        report = module('native-oracle.py').run(args.upstream, args.builder_image, path,
            dict(source=build['source'], bytecode=build['bytecode'], factory_source=factory.read_text(),
                factory_bytecode=build['factory_bytecode'], domain=args.domain,
                wasm_b64=counter['wasm_b64'], cases=fixtures(build)),
            'octra_core octra_node_runtime octra_circle_runtime octra_vm yojson lwt.unix str mirage-crypto-ec')
    report.update(wasm_b64=counter['wasm_b64'], wasm_sha256=counter['wasm_sha256'],
        generator_sha256=digest(Path(__file__)), build_sha256=digest(args.build),
        build=build, domain=args.domain,
        dependencies={name:digest(ROOT/name) for name in [
            'scripts/node-port/circle-code-oracle.ml','scripts/node-port/circle-prepaid-oracle-tail.ml',
            'scripts/node-port/circle-octb-execution-fixtures.py','scripts/node-port/circle-code-fixtures.py',
            'scripts/node-port/octb-execution-fixtures.py','program/octranet-payments.aml',
            'program/octranet-payments-circle-init.aml.in','program/octranet-payments-circle-factory.aml',
            'crates/octra-node/src/vpn/payments/build.rs']},
        scope='Unchanged native compiler and full epoch Circle host: source-derived immutable initialization, parent-owned deferred spawn, real value custody/withdrawal, Ed25519 advance purchase, repeated claim refusal, canonical epoch clock, retained multi-epoch exact day/week boundaries, rate cancellation/reschedule and rollback. No BFT admission, public deployment or delivery proof.')
    expected_refusals = [[12,13,17],list(range(2,8)),[5],[],
        [],[0],[0],[1],[],[],[],[0,1],[0]]
    assert len(report['cases']) == len(expected_refusals)
    for case, rejected in zip(report['cases'],expected_refusals,strict=True):
        result = case['expected']['result']
        assert 'error' not in result, case['input']['name']
        assert [row['index'] for row in result['rejected']] == rejected, (case['input']['name'],result)
        assert all(row['charged'] for row in result['rejected']), case['input']['name']
        assert len(result['confirmed']) + len(rejected) == len(case['input']['transactions'])
    # Actual receipt clock, not process wall time, determines day/week boundaries.
    import base64
    def events(case, name):
        receipts = [json.loads(base64.b64decode(row[1])) for row in case['expected']['receipts']]
        return [event['values'] for receipt in receipts for event in receipt['events'] if event['event']==name]
    assert {row[1] for row in events(report['cases'][0],'OperatorUnstakeRequested')} == {'604923500'}
    # First request and its retry near expiry have exactly the same deadline.
    deadlines = [row[1] for case in report['cases'][6:8] for row in events(case,'OperatorUnstakeRequested')]
    assert deadlines and set(deadlines) == {str(123_500+86_400_000+604_800_000)}
    assert events(report['cases'][4],'RateChangeScheduled')[0][2] == str(123_500+86_400_000)
    assert events(report['cases'][10],'RateChangeScheduled')[0][2] == str(123_500+1000+86_400_000)
    # Preserve complete real outputs; refusal counts must not be replaced by
    # generated expectations. Runtime replay compares roots/fees/receipts.
    args.out.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS unchanged native prepaid Circle epochs',len(report['cases']))

if __name__ == '__main__':
    main()
