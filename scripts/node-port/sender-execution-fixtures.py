#!/usr/bin/env python3
"""Native sender nonce loop, public execution and coupled savepoint fixtures."""
import argparse,base64,hashlib,json,pathlib,random,shutil,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2];enc=lambda v:base64.b64encode(v).decode();AUTH=b'oct7xCozDD9JEsbeVpo5C7HXp2BJbKqfmNUHmDDCCTtWcGb'
def tx(sender=b'a',receiver=b'b',nonce='1',amount='7',ou='3',op='standard',action='public'):return dict(**{'from':enc(sender),'to':enc(receiver)},nonce=nonce,amount=amount,ou=ou,op=op,action=action)
def case(txs,accounts=None):return dict(accounts=accounts or [dict(address=enc(a),balance=b,nonce='0')for a,b in [(b'a','1000'),(b'b','20'),(AUTH,'1000')]],transactions=txs)
def cases():
 result=[case([]),case([tx(),tx(nonce='2')]),case([tx(amount='8'),tx(amount='9'),tx(nonce='2')]),case([tx(nonce='2'),tx(),tx(nonce='3')]),case([tx(sender=b'unknown'),tx(sender=b'b',receiver=b'a')]),case([tx(receiver=b'a'),tx(nonce='2',amount='10000'),tx(nonce='2',amount='1')])]
 for op in ['private','recrypt','encrypt','decrypt','key_switch']:
  result.append(case([tx(op=op),tx(),tx(nonce='2')]))
 for action in ['confirm','reject','consume','persist','defer','error']:
  result.append(case([tx(op='circle_call',action=action),tx(),tx(nonce='2'),tx(op='circle_call',action='confirm',nonce='3')]))
 result +=[case([tx(sender=AUTH,receiver=AUTH,op='op01_burn',amount='10',ou='5'),tx(sender=AUTH,receiver=AUTH,op='op01_burn',nonce='2')]),case([tx(sender=AUTH,op='op01_burn'),tx(op='op01_burn')]),case([tx(sender=AUTH,receiver=AUTH,op='op01_burn',amount='0'),tx(sender=AUTH,receiver=AUTH,op='op01_burn',amount='1001')]),case([tx(),tx(sender=b'b',op='circle_call',action='error')])]
 result.append(case([tx(nonce=str(-(1<<62))),tx(nonce=str(-(1<<62)+1))],[dict(address=enc(b'a'),balance='1000',nonce=str((1<<62)-1))]))
 rng=random.Random(12991)
 for _ in range(40):
  txs=[]
  for _ in range(20):
   action=rng.choice(['public']*5+['confirm','reject','consume','persist','defer'])
   txs.append(tx(sender=rng.choice([b'a',b'b',b'\0\xff']),receiver=rng.choice([b'a',b'b',b'new']),nonce=str(rng.randrange(1,6)),amount=str(rng.randrange(-1,400)),ou=str(rng.randrange(-1,10)),op='standard'if action=='public'else'circle_call',action=action))
  result.append(case(txs))
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();pin=json.loads((ROOT/'docs/rust-node/upstream.json').read_text())['commit']
 if subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()!=pin or a.out.exists():raise SystemExit('require pristine pin and fresh output')
 sources=['node_runtime/consensus_epoch_apply_sender.ml','node_runtime/consensus_epoch_apply_sender_live.ml','lib/core/tx_savepoint.ml','lib/core/ledger_apply.ml','lib/core/ledger.ml','lib/core/store_irmin.ml'];hashes={};inputs=cases()
 with tempfile.TemporaryDirectory(prefix='octra-sender-oracle-')as temp:
  f=pathlib.Path(temp);(f/'cases.json').write_text(json.dumps(inputs));checks=[]
  for i,path in enumerate(sources):
   source=subprocess.check_output(['git','-C',str(a.upstream),'show',f'HEAD:{path}']);assert source==(a.upstream/path).read_bytes();hashes[path]=hashlib.sha256(source).hexdigest();(f/f'source-{i}').write_bytes(source);checks.append(f'cmp {path} /fixture/source-{i}')
  shutil.copyfile(ROOT/'scripts/node-port/sender-execution-oracle.ml',f/'main.ml');(f/'dune').write_text('(executable (name main) (libraries octra_core octra_node_runtime yojson base64 lwt.unix))\n')
  command=' && '.join(checks+['mkdir vpn_sender_oracle','cp /fixture/main.ml /fixture/dune vpn_sender_oracle/','opam exec -- dune exec ./vpn_sender_oracle/main.exe -- /fixture/cases.json'])
  output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={f},target=/fixture,readonly',a.builder_image,'bash','-lc',command],text=True)
 payload=next(line.removeprefix('ORACLE_RESULT=')for line in output.splitlines()if line.startswith('ORACLE_RESULT='));a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(dict(upstream_commit=pin,sources=hashes,oracle='native Sender, Ledger_apply and Tx_savepoint in isolated builder; controlled host leaf actions',cases=json.loads(payload)),indent=2)+'\n');print(f'Generated {len(inputs)} native cases: {a.out}')
if __name__=='__main__':main()
