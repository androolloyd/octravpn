"""Offline native oracle runner shared by new port qualification scripts."""
import hashlib,json,pathlib,shutil,subprocess,tempfile
ROOT=next(p for p in pathlib.Path(__file__).resolve().parents if (p/'docs/rust-node/source-map.json').is_file())
def run(upstream,builder,oracle,inputs,libraries,*,prefixes=None,replacements=None):
    inventory=json.loads((ROOT/'docs/rust-node/source-map.json').read_text())
    pin=subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip()
    if pin!=inventory['upstream_commit']:raise RuntimeError('upstream pin differs')
    for name,digest in inventory['files'].items():
        if hashlib.sha256((upstream/name).read_bytes()).hexdigest()!=digest:raise RuntimeError(f'modified upstream: {name}')
    instrumentation={}
    for name in sorted(set(prefixes or {})|set(replacements or {})):
        if name not in inventory['files']:raise RuntimeError(f'unpinned instrumentation target: {name}')
        prefix=(prefixes or {}).get(name,'');edits=(replacements or {}).get(name,[])
        compiled=prefix.encode()+(upstream/name).read_bytes()
        for edit in edits:
            before,after=edit['before'].encode(),edit['after'].encode()
            if compiled.count(before)!=1:raise RuntimeError(f'candidate patch drift: {name}')
            compiled=compiled.replace(before,after)
        instrumentation[name]={'kind':'candidate source patch with oracle prefix' if edits else 'test-only source prefix','prefix':prefix,'prefix_sha256':hashlib.sha256(prefix.encode()).hexdigest(),'replacements':edits,'original_sha256':inventory['files'][name],'compiled_sha256':hashlib.sha256(compiled).hexdigest()}
    with tempfile.TemporaryDirectory(prefix='octra-native-oracle-') as directory:
        work=pathlib.Path(directory);shutil.copyfile(oracle,work/'main.ml')
        (work/'dune').write_text(f'(executable (name main) (libraries {libraries}))\n')
        (work/'input.json').write_text(json.dumps(inputs))
        (work/'runtime.sha256').write_text(''.join(f'{h}  {p}\n' for p,h in inventory['files'].items()))
        (work/'instrumentation.json').write_text(json.dumps(instrumentation))
        (work/'instrument.py').write_text("import pathlib,hashlib,json\nfor name,entry in json.loads(pathlib.Path('/oracle/instrumentation.json').read_text()).items():\n path=pathlib.Path(name);original=path.read_bytes()\n assert hashlib.sha256(original).hexdigest()==entry['original_sha256']\n compiled=entry['prefix'].encode()+original\n for edit in entry['replacements']:\n  before,after=edit['before'].encode(),edit['after'].encode()\n  assert compiled.count(before)==1\n  compiled=compiled.replace(before,after)\n assert hashlib.sha256(compiled).hexdigest()==entry['compiled_sha256']\n path.write_bytes(compiled)\n")
        (work/'restore.py').write_text("import pathlib,hashlib,shutil\nfor line in pathlib.Path('/oracle/runtime.sha256').read_text().splitlines():\n digest,name=line.split('  ',1);path=pathlib.Path(name)\n if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:\n  path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(pathlib.Path('/native')/name,path)\n")
        output=subprocess.check_output(['docker','run','--rm','--network','none','--mount',f'type=bind,source={work},target=/oracle,readonly','--mount',f'type=bind,source={upstream.resolve()},target=/native,readonly',builder,'bash','-lc','python3 /oracle/restore.py && sha256sum --check --quiet /oracle/runtime.sha256 && python3 /oracle/instrument.py && mkdir vpn_port_oracle && cp /oracle/main.ml /oracle/dune vpn_port_oracle/ && opam exec -- dune exec ./vpn_port_oracle/main.exe < /oracle/input.json'])
    return dict(upstream_commit=pin,source_sha256=inventory['files'],oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),runner_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),builder_image=builder,instrumentation=instrumentation,stdout_sha256=hashlib.sha256(output).hexdigest(),cases=json.loads(output.splitlines()[-1].decode('utf-8')))
