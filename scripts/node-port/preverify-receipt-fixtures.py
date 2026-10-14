#!/usr/bin/env python3
"""Byte-exact native proof receipt schemas, binding commitments and refusals."""
import argparse,base64,copy,importlib.util,json,pathlib,random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
H='a'*64
def base(kind):
    value=dict(schema='octra_preverify_receipt_v1',tx_hash=H,lane='pvac',engine='pvac_preverify_v1',input_hash='b'*64,output_hash='c'*64,ok=True,reason='',cost=dict(txs=1,bytes=123,ou='5000',proof=1))
    if kind in ['bound','transition']:
        value.update(schema='octra_preverify_receipt_v2',engine='pvac_preverify_v2',pre_state_hash='d'*64,source_cipher_hash='e'*64,pvac_key_hash='f'*64)
        if kind=='transition':value.update(schema='octra_private_transition_receipt',engine='pvac_transition_preverify',transition_hash='0'*64)
    if kind=='circle':value.update(schema='octra_preverify_receipt_v3',lane='circle_compute',engine='circle_hfhe_preverify_v1',pre_state_hash='d'*64,circle_id='oct'+'1'*44,code_hash='e'*64,stable_root='f'*128,public_reads_hash='0'*64,context_hash='1'*64,transcript=[])
    return value
def case(raw,op='encrypt',ou='3000',minimum='5000'):
    if not isinstance(raw,bytes):raw=json.dumps(raw,separators=(',',':'),ensure_ascii=False).encode()
    return dict(raw=base64.b64encode(raw).decode(),op=op,ou=ou,minimum=minimum)
def fixtures():
    out=[];templates=[base(k) for k in ['v1','bound','transition','circle']]
    for template in templates:
        out.append(case(template))
        for field in template:
            missing=copy.deepcopy(template);del missing[field];out.append(case(missing))
            for replacement in [None,False,0,1.5,[],{},'',H.upper(),H[:-1],H+'a']:
                v=copy.deepcopy(template);v[field]=replacement;out.append(case(v))
            raw=json.dumps(template,separators=(',',':')).encode()
            key=json.dumps(field).encode();out.append(case(b'{'+key+b':null,'+raw[1:]));out.append(case(raw[:-1]+b','+key+b':null}'))
        for field in template['cost']:
            for value in [None,'',-1,0,1,2,(1<<62)-1,1<<62,-(1<<62),'-1','0x10','1_000','-+1','0o77','0b101',' 1','1.0','1e3']:
                v=copy.deepcopy(template);v['cost'][field]=value;out.append(case(v))
        for field in ['tx_hash','input_hash','output_hash','reason','pre_state_hash','circle_id']:
            if field not in template:continue
            for value in ['\0','é'*64,'x'*128,'x'*129,'\n','😀'*32]:
                v=copy.deepcopy(template);v[field]=value;out.append(case(v))
        for lane in ['standard','program','fhe','pvac','circle_compute']:
            for engine in ['pvac_preverify_v1','fhe_preverify_v1','pvac_preverify_v2','fhe_preverify_v2','pvac_transition_preverify','fhe_transition_preverify','circle_hfhe_preverify_v1','unsupported_preverify_lane']:
                out.append(case(dict(template,lane=lane,engine=engine)))
    entry=dict(method='fhe_verify_zero',request_hash=H,response_hash=H,result=True)
    for field in entry:
        for value in [None,0,False,True,'','x'*65,H.upper()]:
            e=dict(entry);e[field]=value;out.append(case(dict(base('circle'),transcript=[e])))
    for count in [0,1,2,3,16,17]:out.append(case(dict(base('circle'),transcript=[entry]*count)))
    for transcript in [None,{},[None],[dict(entry,method='fhe_add',result=None)]*16]:out.append(case(dict(base('circle'),transcript=transcript)))
    for raw in [b'',b'{',b'[]',b'null',b'NaN',b'{}',b'/* comment */'+json.dumps(base('v1')).encode(),json.dumps(base('v1')).encode().replace(b'"reason": ""',b'"reason": "\xff"')]:out.append(case(raw))
    ops='standard encrypt decrypt stealth claim key_switch private recrypt circle_call circle_balance_cell_put circle_register_cell_put program_exec'.split()
    for op in ops:
        for v in templates:
            for ou in ['0','-1','3000','20000001']:out.append(case(v,op=op,ou=ou))
    rng=random.Random(14013)
    for _ in range(150):
        v=copy.deepcopy(rng.choice(templates));v['ok']=rng.choice([True,False]);v['reason']=rng.choice(['','invalid proof','x'*128,'x'*129]);v['cost']['ou']=rng.choice(['0','-1','0x10',str(1<<200)]);out.append(case(v,op=rng.choice(ops)))
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/preverify-receipt-oracle.ml',fixtures(),'octra_core yojson base64')
    report['scope']='Native receipt parsing, ordered validation, canonical bytes, receipt hashes and transaction/state/Circle commitments. No proof verification or canonical state execution.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native proof receipt cases: {a.out}")
if __name__=='__main__':main()
