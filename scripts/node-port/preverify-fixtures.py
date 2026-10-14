#!/usr/bin/env python3
"""Qualify the native asynchronous shared-job pool with controlled workers."""
import argparse, importlib.util, json, pathlib, random
ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native', ROOT/'scripts/node-port/native-oracle.py')
native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
def step(kind, index=0, **kw):
    return dict(kind=kind, index=index, time=0, **kw)
def case(steps, running=1, queued=3, complete=2):
    return dict(running=running, queued=queued, complete=complete, steps=steps)
def fixtures():
    out=[]
    out.append(case([step('admit'),step('admit'),step('wait',id='a'),step('wait',id='b'),step('cancel',id='a'),step('retain',indices=[]),step('resolve',mode='ready'),step('observe'),step('collect',indices=[0,7],id='c')]))
    out.append(case([step('admit',i) for i in range(4)]+[step('collect',indices=[3,2,7],id='c'),step('resolve',mode='ready'),step('resolve',2,mode='ready'),step('resolve',3,mode='ready'),step('resolve',1,mode='ready')],complete=1))
    out.append(case([step('admit',0),step('admit',1),step('collect',indices=[0,1],id='c'),step('resolve',1,mode='ready'),step('resolve',0,mode='ready')],running=2,complete=1))
    out.append(case([step('admit',i) for i in range(4)]+[step('wait',4,id='a'),step('wait',5,id='b'),step('wait',6,id='c'),step('wait',1,id='d'),step('retain',indices=[]),step('resolve',mode='ready'),step('resolve',4,mode='ready'),step('resolve',5,mode='ready'),step('resolve',6,mode='ready')]))
    for mode in ['ready','rejected','stale','error','panic']:
        out.append(case([step('admit'),step('collect',indices=[0],id='c'),step('wait',id='w'),step('resolve',mode=mode),step('resolve',mode=mode),step('observe')]))
        out.append(case([step('admit'),step('resolve',mode=mode),step('bind',mode='invalid'),step('observe'),step('admit'),step('source',value=2),step('bind',mode='source'),step('wait',id='w'),step('resolve',mode='ready')]))
    for mode in ['source','changed','error']:
        out.append(case([step('admit'),step('source',value=2),step('bind',mode=mode),step('wait',id='w'),step('resolve',mode='ready'),step('resolve',mode='ready')]))
    for mode in ['source','changed','invalid','error']:
        out.append(case([step('admit'),step('resolve',mode='ready'),step('bind',mode=mode),step('source',value=2),step('observe'),step('wait',id='w'),step('resolve',mode='ready'),step('resolve',mode='ready')]))
    out.append(case([step('admit',7),step('observe',7),step('wait',7,id='w'),step('collect',indices=[7],id='c')]))
    rng=random.Random(12903)
    for trace in range(180):
        steps=[]
        for j in range(60):
            kind=rng.choice(['admit','admit','observe','wait','collect','cancel','source','bind','retain','resolve','resolve','resolve'])
            kw={}
            if kind in ['wait','collect']:kw['id']=f'w{j}'
            if kind=='cancel':kw['id']=f'w{rng.randrange(j+1)}'
            if kind in ['collect','retain']:kw['indices']=rng.sample(range(8),rng.randrange(9))
            if kind=='source':kw['value']=rng.randrange(4)
            if kind=='bind':kw['mode']=rng.choice(['source','source','invalid','changed','error'])
            if kind=='resolve':kw['mode']=rng.choice(['ready','ready','rejected','stale','error','panic'])
            action=step(kind,rng.randrange(8),**kw);action['time']=j//3;steps.append(action)
        out.append(case(steps,running=rng.randrange(1,4),queued=rng.randrange(1,5),complete=rng.randrange(1,4)))
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=pathlib.Path,required=True);p.add_argument('--builder-image',required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    if a.out.exists():raise SystemExit('require fresh output')
    report=native.run(a.upstream,a.builder_image,ROOT/'scripts/node-port/preverify-oracle.ml',fixtures(),'octra_core octra_node_runtime yojson lwt.unix')
    report['scope']='Unchanged native shared preverification scheduler with controlled workers and explicit clock. Every action settles runnable tasks before observation. Does not qualify cryptographic workers, CPU scheduling, concurrent head mutation or full-node consensus.'
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f"PASS: {len(report['cases'])} native preverification traces: {a.out}")
if __name__=='__main__':main()
