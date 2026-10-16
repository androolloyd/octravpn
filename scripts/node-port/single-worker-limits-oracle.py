#!/usr/bin/env python3
"""Compare exact pristine worker environment capture; no time/crypto injection."""
from pathlib import Path
import argparse,importlib.util,json
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--upstream',required=True,type=Path)
parser.add_argument('--builder-image',required=True)
parser.add_argument('--out',required=True,type=Path)
args=parser.parse_args();d=Path(__file__).resolve().parent
values=[None,'','0','1','2','3','64','600','1800','1800.1','32768','32769','-1','nan','infinity','1_0','0x2','0x1p1','0x1.fp4','0x1.00000000000008p0','0x100000000000008p-56',' 1','1 ','1\t','_1','1_','+1','0b10','0o10','4611686018427387903','4611686018427387904','0.9999999999999999','1.0000000000000002','1e3']
cases=[dict(name=name,value=value)for name in ['OCTRA_PVAC_VERIFY_WORKERS','OCTRA_PVAC_VERIFY_TIMEOUT_SEC','OCTRA_PVAC_VERIFY_MAX_RSS_MB']for value in values]
spec=importlib.util.spec_from_file_location('oracle',d/'resource-native-oracle.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
report=m.run(args.upstream,args.builder_image,d/'single-worker-limits-oracle.ml',cases,'octra_core yojson lwt.unix')
args.out.write_text(json.dumps(report,indent=2)+'\n');print('native worker limit cases',len(report['cases']))
