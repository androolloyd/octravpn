#!/usr/bin/env python3
"""Pinned native flat and shared-reference ledger-image interchange vectors."""
import argparse,base64,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',type=pathlib.Path,required=True)
    parser.add_argument('--builder-image',required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    if args.out.exists():raise SystemExit('require a fresh fixture path')
    b64=lambda value:base64.b64encode(value).decode()
    cases=[[],[([b'a'],b'value')],
      [([b'a',b'x'],b'shared'),([b'b',b'x'],b'shared')],
      [([b'a'],b'old'),([b'a',b'child'],b'new')],
      [([b'\0binary',b'\xff'],b'\x00\xffpayload'),([b'zz'],b'')],
      [([b'pvac_hashes',b'account'],b'ab'*32),([b'pvac_hashes',b'no-key'],b'none')]]
    rng=random.Random(20261015)
    for width in [2,31,32,33,64,257]:
        cases.append([([b'rows',f'key-{n:04d}'.encode()],rng.randbytes(n%37)) for n in range(width)])
    inputs=[{'rows':[{'path':[b64(part) for part in path],'value':b64(value)} for path,value in rows]} for rows in cases]
    spec=importlib.util.spec_from_file_location('native_oracle',pathlib.Path(__file__).with_name('native-oracle.py'))
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    report=native.run(args.upstream,args.builder_image,pathlib.Path(__file__).with_name('ledger-image-oracle.ml'),inputs,'octra_core lwt.unix irmin yojson base64')
    report['inputs']=inputs
    report['scope']='Native ledger bytes/root interchange only; authenticated bootstrap and process recovery remain separate gates'
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'cases':len(inputs),'pin':report['upstream_commit']}))
if __name__=='__main__':main()
