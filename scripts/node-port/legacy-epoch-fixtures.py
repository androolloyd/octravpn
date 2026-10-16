#!/usr/bin/env python3
"""Pristine native legacy epoch announcement codec/diagnostic oracle."""
import argparse, importlib.util, json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--upstream',type=Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('oracle',here/'resource-native-oracle.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def case(name,**kw):return dict(dict(name=name,epoch=1,root='ab'*32,declared=0,producer='oct-producer-longer-than14',transactions=0),**kw)
cases=[case('empty'),case('one',declared=1,transactions=1),case('mismatch',declared=7,transactions=1),case('negative-declared',declared=-1),case('short-root',root='short',producer='tiny'),case('negative-epoch',epoch=-1),case('int63-epoch',epoch=(1<<62)-1),case('trailing'),case('truncated'),case('negative-count'),case('bad-tx',declared=1,transactions=1)]
x=m.run(a.upstream,a.builder_image,here/'legacy-epoch-oracle.ml',cases,'octra_core octra_node_runtime octra_net yojson lwt.unix');a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(x,indent=2)+'\n');print('native legacy epoch cases',len(x['cases']))
