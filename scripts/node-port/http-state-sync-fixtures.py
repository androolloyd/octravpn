"""Offline byte/error vectors from the adopted native HTTP implementation."""
import argparse, base64, hashlib, importlib.util, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def encoded(raw): return base64.b64encode(raw).decode()
def cases():
    rows=[]
    rows.append(dict(op="query",query="from_epoch=2&from_epoch=999&path=a%2Fb%FF+z&bare"))
    rows.append(dict(op="query",query="from_epoch&from_epoch=2&path=a,b&bare="))
    rows.append(dict(op="query",query="from_epoch=2,3&path=a%2Cb;z&bare=a+b"))
    for current,head in [(0,None),(2,dict(epoch=1,root="a"*64,txid_hi="-1")),(3003,dict(epoch=3002,root="b"*64,txid_hi="9"))]:
        rows.append(dict(op="head",current_epoch=current,head=head))
    for raw in [b'{}',b'[]',b'{"phase":"first","phase":"second","file_size":12,"file_done":"7","eta_seconds":2.5}',b'{"peer":true,"total_done":9223372036854775807,"rate_bps":4,"eta_seconds":null}']:
        rows.append(dict(op="progress",raw=encoded(raw)))
    for op in ["range_missing","range_error"]:
        rows.append(dict(op=op,from_epoch="4",max_epochs=100,reason="read failure"))
    for kind,reason in [("state_sync_bad_range_request","invalid range parameters"),("state_sync_bad_progress","progress report must be a JSON object"),("unknown","DEPRECATED: REST compatibility endpoint removed; use POST /rpc.")]:
        rows.append(dict(op="error",type=kind,reason=reason))
    part='{"version":"octra-range-part-v1","status":"part","sha256":"'+'a'*64+'","index":1,"count":2,"data":"Zh=="}'
    for raw in [part,part.replace('"index":1','"index":"1"'),part.replace('"count":2','"count":2,"count":2'),part.replace('Zh==','Zg==')]:
        rows.append(dict(op="part_view",raw=encoded(raw.encode())))
    for size,index in [(4_500_000,None),(4_500_000,0),(4_500_001,None),(4_500_001,1),(4_500_001,2),(6_000_001,2),(33_554_433,None)]:
        rows.append(dict(op="multipart",size=size,index=index))
    return rows
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--upstream',type=Path,required=True);parser.add_argument('--builder-image',required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    if args.out.exists():raise SystemExit('Require fresh output')
    spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    report=native.run(args.upstream,args.builder_image,ROOT/'scripts/node-port/http-state-sync-oracle.ml',cases(),'octra_node_runtime octra_bootstrap octra_core octra_consensus octra_net yojson base64 digestif digestif.c lwt.unix cohttp-lwt-unix')
    report['generator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();report['scope']='Pure native HTTP/state-sync byte and refusal vectors, no stores opened, no network, no import authority inferred.'
    args.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native HTTP vectors')
if __name__=='__main__':main()
