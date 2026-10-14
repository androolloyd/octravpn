#!/usr/bin/env python3
"""Native pending-precommit records and restart journal traces."""
import argparse, copy, importlib.util, json, pathlib, random, struct
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def bits(f):return struct.pack('>d',f).hex()
def fixtures():
    def record(**kw):return dict(epoch=1,round=0,pid=(b'01'*32).hex(),root=(b'02'*32).hex(),txid='7',time=bits(1.),validator=b'v1'.hex(),proposal=None,vote=None,hashes=[],txs=[],receipts=[])|kw
    def action(op,**kw):return dict(op=op,epoch=1,round=0)|kw
    def keep(r):return action('keep',record=r)
    out=[]
    for f in [0.,-0.,1.,-1.,1e-300,1e-5,1e-4,1e16,1.2345678901234567,1.7976931348623157e308,float("nan"),float("inf"),float("-inf")]:
        for raw in [b'',b'v1',bytes(range(256))]:
            out.append(dict(kind='encode',record=record(time=bits(f),validator=raw.hex(),proposal=raw.hex(),vote=raw.hex(),hashes=[raw.hex()],txs=[raw.hex()],receipts=[raw.hex()])))
    for n in [-2**62,-1,0,2**62-1]:out.append(dict(kind='encode',record=record(epoch=n,round=n,txid=str(n))))
    base=dict(epoch_id=1,round=0,proposal_id='01'*32,proposed_state_root='02'*32,txid_hi='7',ts=1.,validator_addr='v1',proposal_b64=None,vote_b64=None,tx_hashes=[],txs_json=[],receipts_json=[])
    def wire(v):return json.dumps(v,separators=(',',':')).encode()
    mutations=[b'',b'{',b'[]',b'null',wire(base)+b'\n']
    for name in base:
        missing=copy.deepcopy(base);del missing[name];mutations.append(wire(missing))
        for value in [None,False,0,1.5,'',[],{},'0x7',2**63-1]:
            changed=copy.deepcopy(base);changed[name]=value;mutations.append(wire(changed))
    for encoded in mutations:out.append(dict(kind='parse',wire=encoded.hex()))
    out.append(dict(kind='trace',steps=[action('read'),action('delete'),keep(record()),action('wire'),keep(record(time=bits(2.))),action('wire'),keep(record(pid=(b'03'*32).hex())),keep(record(round=1)),keep(record(epoch=2)),action('read'),action('delete'),action('read'),action('delete_epoch'),action('read'),action('delete_epoch',epoch=2),action('read')]))
    for encoded in [b'',b'{}',b'[]',wire(base),wire(base).replace(b'"epoch_id":1',b'"epoch_id":2'),wire(base).replace(b'"round":0',b'"round":-1')]:
        out.append(dict(kind='trace',steps=[action('corrupt',data=encoded.hex()),action('read'),keep(record()),action('delete'),action('read')]))
    out.append(dict(kind='trace',steps=[action('oversize'),action('read'),keep(record()),action('delete'),action('read')]))
    for n in [-1,0,2**62-1]:out.append(dict(kind='trace',steps=[keep(record(epoch=n,round=n)),action('read'),action('delete',epoch=n,round=n),action('read')]))
    rng=random.Random(2026101315)
    for _ in range(40):
        steps=[]
        for _ in range(60):
            op=rng.choice(['keep']*5+['read','delete','delete_epoch']);epoch=rng.randrange(1,6);round=rng.randrange(4)
            steps.append(keep(record(epoch=epoch,round=round,txid=str(rng.randrange(1,4)),time=bits(rng.random())))if op=='keep'else action(op,epoch=epoch,round=round))
        out.append(dict(kind='trace',steps=steps))
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh report')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/pending-log-oracle.ml',fixtures(),'octra_core yojson')
    report['scope']='Unmodified native pending-precommit WAL encoding, decoding, idempotency, conflicts and restart reads. Local OS and parser diagnostics are normalized separately from acceptance. Authenticated bundle recovery is a separate gate.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native pending journal cases")
if __name__=='__main__':main()
