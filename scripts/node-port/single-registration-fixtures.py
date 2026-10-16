#!/usr/bin/env python3
"""Fresh pinned-native local registration oracle, no public effects."""
import argparse, importlib.util, json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--upstream',type=Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('oracle',here/'resource-native-oracle.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
names=['good','null','missing-key','missing-signature','bad-address','short-key','short-signature','mismatch-short-signature','bad-key-base64','mismatch-key','wrong-domain','bad-signature','bad-signature-type']
cases=[dict(name=name,bft=False)for name in names]+[dict(name=name,bft=True)for name in ['bft-good','bft-null']]
x=m.run(a.upstream,a.builder_image,here/'single-registration-oracle.ml',cases,'octra_core octra_node_runtime yojson lwt.unix')
a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(x,indent=2)+'\n');print('native registration cases',len(x['cases']))
