#!/usr/bin/env python3
"""Qualify transaction identities and loaded-account transitions with pinned OCaml."""
import argparse, base64, hashlib, json, pathlib, random, shutil, struct, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCES = ['lib/core/transaction.ml', 'lib/core/tx_envelope.ml', 'lib/core/crypto.ml', 'lib/core/ledger.ml', 'lib/core/ledger_types.ml', 'lib/core/store_irmin.ml']
enc = lambda value: base64.b64encode(value).decode()
def b58(raw):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = int.from_bytes(raw, 'big'); out = ''
    while value: value, digit = divmod(value, 58); out = alphabet[digit] + out
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + out
SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
PUB = base64.b64encode(bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'))
ADDR = ('oct' + b58(hashlib.sha256(base64.b64decode(PUB)).digest()).rjust(44, '1')).encode()
def tx(**changes):
    value = dict(operation='transaction', **{'from': enc(ADDR), 'to': enc(b'oct' + b'1'*44)}, amount='17', nonce='1', ou='1000', timestamp_bits='41d954fc40000000', signature=enc(base64.b64encode(bytes(64))), public_key=enc(PUB), message=None, encrypted_data=None, op_type='standard')
    value.update(changes); return value
def account(address=b'a', balance='100000', nonce='0', **changes):
    value = dict(address=enc(address), balance=balance, nonce=nonce, public_key=None, encrypted_balance=None, decrypt_allowance='0'); value.update(changes); return value
def step(op, address=b'a', **changes):
    value = dict(op=op, address=enc(address)); value.update(changes); return value
def transfer(amount='7', fee='3', nonce='1', sender=b'a', receiver=b'b'):
    return dict(op='transfer', **{'from':enc(sender), 'to':enc(receiver)}, amount=amount, fee=fee, nonce=nonce)
def cases():
    rng = random.Random(20261013); result = []
    bits = [0,1,(1<<63),(1<<63)+1,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000000,0x7fefffffffffffff,0x0010000000000000]
    bits += [int.from_bytes(struct.pack('>d', v), 'big') for v in [1.0,-1.,1e-4,1e-5,1e15,1e16,1.234567890123456,1.2345678901234567,0.1,1700000000.1234567]]
    bits += [rng.getrandbits(64) for _ in range(5000)]
    result += [dict(operation='float', bits=f'{v:016x}') for v in bits]
    operations = ['standard','encrypt','decrypt','private','deploy','program_deploy','call','program_exec','multi_exec','upgrade','deploy_circle','circle_program_update','circle_asset_put','circle_asset_put_encrypted','circle_sealed_slot_put','circle_slot_policy_put','circle_state_descriptor_put','circle_balance_cell_put','circle_register_cell_put','circle_transport_policy_put','circle_hfhe_policy_put','circle_key_policy_put','circle_key_grant','circle_key_extend','circle_key_revoke','circle_key_erase','circle_outbox_open','circle_relay_claim','circle_relay_cancel','circle_ingress_commit','circle_call','validator_set_update','validator_ready','validator_bond','validator_exit','validator_withdraw','validator_evidence','stealth','claim','recrypt','key_switch','op01_burn','compute_fund','compute_return','compute_settle']
    result += [tx(op_type=op,seed=enc(SEED),message=enc(bytes(range(256))),encrypted_data=enc(b'hfhe_v1\0\xff')) for op in operations]
    for i in range(96):
        result.append(tx(amount=str(rng.randrange(-(1<<180),1<<180)), ou=str(rng.randrange(-(1<<80),1<<80)), nonce=str(rng.randrange(-(1<<62),1<<62)), timestamp_bits=f'{bits[i]:016x}', public_key=None if i%2 else enc(PUB), message=None if i%3 else enc(rng.randbytes(70)), encrypted_data=None if i%4 else enc(rng.randbytes(50))))
    values = [b'', b'Zg==',b'Zh==',b'Zg',b'Zg=',b'Zg===',b' Zg==',b'Zg==\n',b'Zg==AA==',b'Zm9v',b'Zm9v=',b'Zm9v\n',b'-_==',b'\xff',b'AA==',b'AB==',b'AA',b'AAA=',b'AAB=',b'AAA',b'AAAA']
    result += [dict(operation='base64',value=enc(v)) for v in values]
    for public in [PUB,b'',b'invalid',base64.b64encode(b''),base64.b64encode(b'\x00'),base64.b64encode(bytes(range(32)))]:
        for address in [ADDR,b'',b'oct'+b'1'*44,b'oct'+b'0'*44,b'oct'+b'z'*44]: result.append(dict(operation='address',key=enc(public),address=enc(address)))
    sig = base64.b64encode(bytes(64)); alphabet=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    aliases = [sig[:85]+bytes([alphabet[i]])+sig[86:] for i in range(16)]
    key_aliases = [PUB[:42]+bytes([PUB[42]+i])+PUB[43:] for i in range(4)]
    for signature in aliases + [sig[:-1], sig[:-2], sig+b'=',b'',b'invalid',base64.b64encode(bytes(31)),base64.b64encode(bytes(32)+bytes([255])*32)]:
        result.append(tx(operation='envelope',sender_key=enc(PUB),signature=enc(signature)))
    for op in ['standard','validator_bond']:
        for carried in [None,enc(b''),enc(b'invalid'),enc(b'x'*45),enc(base64.b64encode(bytes(32)))]+[enc(v) for v in key_aliases]:
            for sender in [None,enc(PUB),enc(b'invalid')]: result.append(tx(operation='envelope',op_type=op,sender_key=sender,public_key=carried))
    for cipher in [None,enc(b''),enc(b'0'),enc(b'hfhe_v1'),enc(b'hfhe_v1\xff'),enc(b'hfhe_v2'),enc(b'legacy')]:
        result.append(dict(operation='ledger',accounts=[account(encrypted_balance=cipher)],steps=[]))
    fixed = [step('freeze'),step('commit'),step('abort'),step('begin'),transfer(),step('begin'),transfer(nonce='2',receiver=b'a'),step('credit',address=b'new',amount='9'),step('commit'),step('abort'),step('freeze'),step('begin'),step('credit',amount='8'),step('begin'),step('debit',amount='2',nonce='1'),step('abort'),step('commit'),step('freeze'),step('flush'),step('freeze'),step('clear_spent')]
    result.append(dict(operation='ledger',accounts=[account()],steps=fixed))
    for amount,fee,nonce in [('-4','2','1'),('-1','3','1'),('3','-1','1'),('0','0','1'),('100001','0','1'),('1','0','0'),('1','0','2')]:
        result.append(dict(operation='ledger',accounts=[account()],steps=[transfer(amount,fee,nonce),transfer(amount,fee,nonce,sender=b'missing')]))
    result.append(dict(operation='ledger',accounts=[account(nonce=str((1<<62)-1))],steps=[transfer(nonce=str(-(1<<62))),transfer(nonce=str(-(1<<62)+1))]))
    result.append(dict(operation='ledger',accounts=[account(balance=str(10**15))],steps=[step('credit',amount='1'),step('credit',amount='-1'),step('add',amount='1'),step('add',amount='-1'),step('add',amount='0')]))
    result.append(dict(operation='ledger',accounts=[account()],steps=[step('debit',amount='1',nonce='1'),step('add',amount='10'),step('debit',amount='1',nonce='1'),step('clear_spent'),step('debit',amount='1',nonce='1')]))
    for _ in range(24):
        steps=[]
        for _ in range(80):
            op=rng.choice(['credit','debit','debit_only','transfer','begin','abort','commit','key','cipher','allowance','clear_spent'])
            address=rng.choice([b'a',b'b',b'c',b'\0\xff'])
            if op=='transfer': steps.append(transfer(str(rng.randrange(-3,1000)),str(rng.randrange(-2,10)),str(rng.randrange(-1,6)),address,rng.choice([b'a',b'b',address])))
            else:
                s=step(op,address,amount=str(rng.randrange(-3,1000)),nonce=str(rng.randrange(-1,6)),public_key=enc(rng.randbytes(4)),encrypted_balance=enc(b'hfhe_v1'+rng.randbytes(4)))
                steps.append(s)
        result.append(dict(operation='ledger',accounts=[account(),account(b'b',balance='4')],steps=steps))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True); args=p.parse_args()
    pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
    if subprocess.check_output(['git','-C',str(args.upstream),'rev-parse','HEAD'],text=True).strip()!=pin or args.out.exists(): raise SystemExit('require pinned pristine sources and a fresh output path')
    inputs=cases(); hashes={}
    with tempfile.TemporaryDirectory(prefix='octra-transaction-oracle-') as tmp:
        fixture=pathlib.Path(tmp); (fixture/'cases.json').write_text(json.dumps(inputs))
        checks=[]
        for index,path in enumerate(SOURCES):
            source=subprocess.check_output(['git','-C',str(args.upstream),'show',f'HEAD:{path}'])
            if (args.upstream/path).read_bytes()!=source: raise SystemExit('modified upstream source: '+path)
            (fixture/f'source-{index}').write_bytes(source);hashes[path]=hashlib.sha256(source).hexdigest();checks.append(f'cmp {path} /fixture/source-{index}')
        (fixture/'native_envelope.ml').write_bytes(b'open Octra_core\n' + (fixture/'source-1').read_bytes())
        shutil.copyfile(ROOT/'scripts/node-port/transaction-state-oracle.ml',fixture/'main.ml')
        (fixture/'dune').write_text('(executable (name main) (libraries octra_core yojson base64 lwt.unix))\n')
        command=' && '.join(checks+['mkdir vpn_transaction_oracle','cp /fixture/main.ml /fixture/native_envelope.ml /fixture/dune vpn_transaction_oracle/','opam exec -- dune exec ./vpn_transaction_oracle/main.exe -- /fixture/cases.json'])
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={fixture},target=/fixture,readonly',args.builder_image,'bash','-lc',command],text=True)
    payload=next(line.removeprefix('ORACLE_RESULT=') for line in output.splitlines() if line.startswith('ORACLE_RESULT='))
    report=dict(upstream_commit=pin,sources=hashes,oracle='pinned OCaml transaction/envelope/ledger, isolated builder, no network',cases=json.loads(payload))
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+'\n');print(f'Generated {len(inputs)} native cases: {args.out}')
if __name__=='__main__':main()
