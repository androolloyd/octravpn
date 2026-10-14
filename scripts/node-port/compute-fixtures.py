#!/usr/bin/env python3
"""Native compute priority, bounded queues and claimed-job cancellation oracle."""
import argparse, importlib.util, json, pathlib, random
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('native',ROOT/'scripts/node-port/native-oracle.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
def step(kind,id=0,priority='required',fail=False):return dict(kind=kind,id=id,priority=priority,fail=fail)
def case(steps,capacity=1,required=4,speculative=2,burst=2):return dict(capacity=capacity,required=required,speculative=speculative,burst=burst,steps=steps)
def fixtures():
    out=[case([step('start',0),step('cancel',0),step('start',1),step('try',2),step('resolve',0),step('resolve',1)]),
      case([step('start',0),step('start',1),step('cancel',1),step('start',2),step('resolve',0),step('resolve',2)]),
      case([step('start',0),step('start',1),step('start',2,'speculative'),step('start',3),step('start',4),step('start',5,'speculative')]+[step('resolve',i) for i in [0,1,3,2,4,5]]),
      case([step('start',i,'required' if i%2==0 else 'speculative') for i in range(8)]+[step('cancel',1),step('resolve',0,fail=True),step('resolve',2),step('try',10)],required=1,speculative=1)]
    rng=random.Random(13217)
    for _ in range(160):
        steps=[]
        for j in range(80):
            kind=rng.choice(['start','start','resolve','resolve','cancel','try'])
            steps.append(step(kind,j if kind=='start' else rng.randrange(j+1),rng.choice(['required','speculative']),rng.randrange(4)==0))
        # Drain surviving workers, including jobs scheduled by earlier completions.
        for _ in range(3):steps.extend(step('resolve',j) for j in range(80))
        out.append(case(steps,capacity=rng.randrange(1,5),required=rng.randrange(1,6),speculative=rng.randrange(1,5),burst=rng.randrange(1,5)))
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/compute-oracle.ml',fixtures(),'octra_core yojson lwt.unix')
    report['scope']='Unchanged native compute pool with controlled asynchronous jobs and nonblocking synchronous probes. Covers required burst fairness, queue saturation, cancellation and failure; operating-system thread scheduling and cryptographic workers are separate qualification boundaries.'
    a.out.write_text(json.dumps(report,indent=2)+'\n');print(f"PASS: {len(report['cases'])} native compute traces: {a.out}")
if __name__=='__main__':main()
