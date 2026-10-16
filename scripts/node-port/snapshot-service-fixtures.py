"""Pinned native cycle, lease and disabled resource-gossip oracle vectors."""
import argparse, base64, hashlib, importlib.util, json, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def blob(raw):return base64.b64encode(raw).decode()
def wire(raw):return struct.pack('>I',len(raw))+raw
def cases():
    rows=[]
    for interval,retain in [(360,2),(1,8),(0,2),(360,1),(-1,2)]:
        rows.append(dict(op='policy',interval=interval,retain=retain))
    for published,events in [
        (None,[['head',0],['complete',0,['failed']],['head',359],['head',720],['complete',0,['published',359]],['head',720]]),
        (360,[['head',800],['head',1200],['complete',720,['published',800]],['head',900],['head',1200],['complete',1080,['failed']],['head',1200]]),
        (None,[['after',10,7],['complete',7,['published',10]],['head',9],['head',360]]),
        (None,[['head',-1]]),(None,[['after',10,11]]),(None,[['after',10,-1]]),
        (None,[['complete',1,['failed']]]),(None,[['head',20],['complete',1,['failed']]]),
        (None,[['head',400],['complete',360,['published',359]]]),
    ]:rows.append(dict(op='cycle',published=published,events=events))
    for value in [None,'','0','1','true',' 1','01','yes']:rows.append(dict(op='override',value=value))
    for retain,current,items in [(2,'c',[['a',4],['b',2],['c',1],['d',4]]),(2,'b',[['a',4],['b',2],['c',1]]),(3,'z',[])]:
        rows.append(dict(op='retention',retain=retain,current=current,items=items))
    for now,published,last in [(1000,0,100),(1000,0,99),(1000,1060,1060),(1000,1061,1000),(1000,0,1061),(100000,0,100000),(1000,0,1000),(1000,0,1000.5)]:
        rows.append(dict(op='lease',now=now,published=published,last_seen=last))
    rows.append(dict(op='leases',items=[[str(i),1000+i//2] for i in range(11)]))
    inner=wire(b'inner')+struct.pack('>Q',0)+wire(b'node')+b'\x01'+wire(b'x')+bytes(32)+struct.pack('>Q',0)+bytes(32)+bytes(64)
    same=wire(b'fixture')+struct.pack('>Q',1)+wire(inner)
    other=wire(b'other')+struct.pack('>Q',1)+wire(inner)
    bad_kind=inner[:4+5+8+4+4]+b'\x09'+inner[4+5+8+4+4+1:]
    for raw in [same,other,same+b'\0',b'',wire(b'other')+struct.pack('>Q',1)+wire(bad_kind)]:
        rows.append(dict(op='disabled_gossip',chain='fixture',raw=blob(raw)))
    return rows
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('Require fresh output')
    spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    report=module.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/snapshot-service-oracle.ml',cases(),'octra_node_runtime octra_bootstrap octra_core octra_consensus octra_net yojson base64 digestif digestif.c lwt.unix cohttp-lwt-unix')
    report['generator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['scope']='Native scheduling, exporter override, retention, fresh temporary lease markers and disabled resource gossip decode/refusal. No active stores/network or optional resource model.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(report['cases']),'native snapshot-service vectors')
if __name__=='__main__':main()
