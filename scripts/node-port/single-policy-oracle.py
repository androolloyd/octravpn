#!/usr/bin/env python3
"""Replay pristine Single role/timer/proposer/preverification cache policies."""
from pathlib import Path
import argparse,json,base64,importlib.util
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--upstream',required=True,type=Path)
parser.add_argument('--builder-image',required=True)
parser.add_argument('--out',required=True,type=Path)
args=parser.parse_args()
d=Path(__file__).resolve().parent
def b(v):return None if v is None else base64.b64encode(v if isinstance(v,bytes)else v.encode()).decode()
c=[]
for cli in [False,True]:
 for mode in [None,'','single','bft','BFT','observer',' Observer ','\vbft\v','\fbft\f','not-a-role']:c.append(dict(kind='role',cli=cli,mode=b(mode)))
for elapsed in ['-inf','-1','-0.','0.','9.999','10.','10.001','inf','nan']:c.append(dict(kind='tick',elapsed=elapsed))
for epoch in [-1,0,1,2,3,4611686018427387903]:
 for vals in [[],['octA'],['octA','octB']]:
  for fee,override in [(None,None),('bad',None),('octFEE','octOVERRIDE'),(None,'octOVERRIDE')]:c.append(dict(kind='proposer',epoch=epoch,validators=list(map(b,vals)),fee=b(fee),override=b(override)))
for current in [None,'','abc','octZ:k2,octA:k1',' octZ:k2 , octA:k1 ','octA:bad:key,octB:','octA:k1,octA:k2','\voctA:k\v','\foctA:k\f']:
 for next_,activation,epoch in [(None,None,1),('octX:next','2',1),('octX:next','2',2),('octX:next','0x2',3),('octX:next','bad',3)]:c.append(dict(kind='validators',current=b(current),next=b(next_),activation=b(activation),epoch=epoch))
for state in ['missing','pending','ready','failed','unavailable']:
 for count,maximum in [(0,3),(2,3),(3,3),(-1,0),(4611686018427387903,4611686018427387903)]:c.append(dict(kind='gate',state=state,count=count,maximum=maximum,reason=b('deterministic reason')))
for maximum in [0,1,2,64]:
 for count in [0,1,2,3,76,80,300]:
  for table in [False,True]:
   entries=[dict(key=b('cache-key-'+str(i)),time=['0.','5.','9.','nan'][i%4],pending=i%3==0)for i in range(count)]
   c.append(dict(kind='cache-table' if table else 'cache',entries=entries,maximum=maximum,now='10.',ttl='5.'))
spec=importlib.util.spec_from_file_location('oracle',d/'resource-native-oracle.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
x=m.run(args.upstream,args.builder_image,d/'single-policy-oracle.ml',c,'octra_core octra_node_runtime octra_consensus yojson lwt.unix');(args.out).write_text(json.dumps(x,indent=2)+'\n');print('native policy cases',len(x['cases']))
