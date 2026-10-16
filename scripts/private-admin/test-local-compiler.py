#!/usr/bin/env python3
"""Offline native-fixture controls; no real process, socket, wallet or prover."""
import argparse,base64,contextlib,copy,hashlib,importlib.util,io,json,pathlib,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/ceremony'))
import local_compiler as local

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

prepare=load('prepare',ROOT/'scripts/ceremony/prepare-candidate.py')
probe=load('probe',ROOT/'scripts/ceremony/probe-mainnet.py')
deploy=load('deploy',ROOT/'scripts/ceremony/deploy-canary.py')
fixture_raw=(ROOT/'crates/octra-node-protocol/tests/fixtures/vpn-compiler.json').read_bytes();native=json.loads(fixture_raw)
names=('main-v5.aml','private-admin-factory.aml')
sources={name:(ROOT/'program'/name).read_bytes() for name in names}
results={name:base64.b64decode(next(case['expected']['rpc'] for case in native['cases'] if case['path']=='program/'+name and case['syntax']=='source' and case['loops'])) for name in names}
runtime={'schema':'octra-runtime-release-v1','chain_id':'fixture-chain','consensus_standard_hash':'a'*64,'activation_graph_hash':'b'*64,'consensus_profile':16,'consensus_rules_id':'finalized_rejection_commitment','runtime_profile_hash':'a'*64,'config_hash':'c'*64}
head={'runtime':runtime,'runtime_response_sha256':'1'*64,'status_response_sha256':'2'*64,'head_epoch':200,'state_root':'d'*64}
target={'rpc_url':'https://example.invalid/rpc','chain_id':'fixture-chain','origin':{'kind':'checkpoint','epoch':100},'authority':{'upstream_commit':native['upstream_commit']}}
observation={'kind':'verified_local_rust_node','endpoint':'http://127.0.0.1:20801/rpc','binding_sha256':'a'*64,'binary_sha256':'b'*64,'source_manifest_sha256':'c'*64,'native_fixture_sha256':local.sha(fixture_raw),'native_profiles':[{'syntax':'source','loops':True}],'before':head,'after':head}
checks=[]

for url in ['https://127.0.0.1:20801/rpc','http://localhost:20801/rpc','http://127.1:20801/rpc','http://127.0.0.2:20801/rpc','http://example.invalid:20801/rpc','http://127.0.0.1/rpc','http://user@127.0.0.1:20801/rpc','http://127.0.0.1:20801/rpc?x=1','http://127.0.0.1:20801/other','http://[::ffff:127.0.0.1]:20801/rpc']:
    try:local.loopback(url);raise AssertionError(url)
    except ValueError:checks.append('refuse_'+url)
for url in ['http://127.0.0.1:20801/rpc','http://[::1]:20801/rpc']:assert local.loopback(url)==20801;checks.append('allow_'+url)

for name,raw in results.items():
    code,profiles=local.validate_result(name,sources[name],json.loads(raw),raw,native)
    assert {'syntax':'source','loops':True} in profiles
    for mode in ('source','code','certificate','verification','labels','raw_profile'):
        item=json.loads(raw);changed=raw;source=sources[name]
        if mode=='source':source+=b'changed'
        if mode=='code':item['bytecode']=base64.b64encode(b'OCTBchanged').decode()
        if mode=='certificate':item['certificate']['source_hash']='0'*64
        if mode=='verification':item['verification']['errors']=1
        if mode=='labels':item['disasm']='JDEST 1\nJDEST 1\n'
        if mode=='raw_profile':changed=local.encoded(item)
        try:local.validate_result(name,source,item,changed,native);raise AssertionError(mode)
        except ValueError:checks.append(name+'_'+mode)

real_validate=local.validate_saved
for case in ['valid','target','public','kind','source','artifact','octb','verification','native_fixture','native_profile','deployment','deployment_hash','compiler_binding','candidate_compiler','head_regression','runtime_change']:
    with tempfile.TemporaryDirectory() as raw_dir:
        root=pathlib.Path(raw_dir);candidate=root/'candidate';preflight=root/'preflight';candidate.mkdir();preflight.mkdir()
        (candidate/'compiler-native-fixture.json').write_bytes(fixture_raw)
        report={'rpc_url':target['rpc_url'],'target':target,'target_binding_sha256':local.digest(target),'compiler':copy.deepcopy(observation),'public_target_preflight':False,'checks':{}}
        for name,raw in results.items():
            result=json.loads(raw);item={'result':result,'result_raw':raw};code=base64.b64decode(result['bytecode'])
            (candidate/name).write_bytes(sources[name]);(candidate/(name.removesuffix('.aml')+'.octb')).write_bytes(code)
            envelope=b'{"jsonrpc":"2.0","id":1,"result":'+raw+b'}'
            (preflight/(name+'.compile.json')).write_bytes(envelope)
            deployment=local.encoded(local.artifact(target,report['compiler'],item))+b'\n'
            (preflight/(name+'.artifact.json')).write_bytes(deployment)
            report['checks'][name]={'source_sha256':local.sha(sources[name]),'artifact_sha256':local.sha(envelope),'bytecode_sha256':local.sha(code),'deployment_artifact_sha256':local.sha(deployment)}
        manifest={'payload':{'compiler':copy.deepcopy(observation)}}
        name=names[0]
        if case=='target':report['target_binding_sha256']='0'*64
        if case=='public':report['public_target_preflight']=True
        if case=='kind':report['compiler']['kind']='remote'
        if case=='source':(candidate/name).write_bytes(sources[name]+b'changed')
        if case=='artifact':(preflight/(name+'.compile.json')).write_bytes(b'{}')
        if case=='octb':(candidate/'main-v5.octb').write_bytes(b'OCTBchanged')
        if case=='native_fixture':(candidate/'compiler-native-fixture.json').write_bytes(b'{}')
        if case=='verification':
            path=preflight/(name+'.compile.json');value=json.loads(path.read_bytes());value['result']['verification']['errors']=1;path.write_bytes(local.encoded(value));report['checks'][name]['artifact_sha256']=local.sha(path.read_bytes())
        if case=='native_profile':report['compiler']['native_profiles']=[{'syntax':'forms','loops':False}];manifest['payload']['compiler']=copy.deepcopy(report['compiler'])
        if case=='deployment':(preflight/(name+'.artifact.json')).write_bytes(b'{}')
        if case=='deployment_hash':report['checks'][name]['deployment_artifact_sha256']='0'*64
        if case=='compiler_binding':report['compiler']['binary_sha256']='bad';manifest['payload']['compiler']=copy.deepcopy(report['compiler'])
        if case=='candidate_compiler':manifest['payload']['compiler']['binary_sha256']='0'*64
        if case=='head_regression':report['compiler']['after']=copy.deepcopy(head);report['compiler']['after']['head_epoch']=199;manifest['payload']['compiler']=copy.deepcopy(report['compiler'])
        if case=='runtime_change':report['compiler']['after']=copy.deepcopy(head);report['compiler']['after']['runtime']['consensus_profile']=17;manifest['payload']['compiler']=copy.deepcopy(report['compiler'])
        (candidate/'manifest.json').write_bytes(local.encoded(manifest));(preflight/'report.json').write_bytes(local.encoded(report))
        try:real_validate(candidate,preflight,target);assert case=='valid',case
        except (ValueError,KeyError):assert case!='valid',case
        checks.append('saved_'+case)

# Provenance records are hash-bound; their captured source may intentionally be
# older than the current checkout. Only that historical binary owns this socket.
with tempfile.TemporaryDirectory() as raw_dir:
    root=pathlib.Path(raw_dir);binary=root/'public-binary';binary.write_bytes(b'public executable fixture')
    def evidence(name,value):
        path=root/name;path.write_bytes(local.encoded(value));return {'path':str(path),'sha256':local.sha(path.read_bytes())}
    fixture_entry=evidence('native.json',native);source_entry=evidence('sources.json',{'crates/octra-node-protocol/tests/fixtures/vpn-compiler.json':fixture_entry['sha256']})
    binary_hash=local.sha(binary.read_bytes())
    build=evidence('build.json',{'exit_code':0,'source_drift':[],'binary_sha256':binary_hash,'source_manifest_sha256':source_entry['sha256']})
    launch=evidence('launch.json',{'pid':42,'binary_sha256':binary_hash,'source_manifest_sha256':source_entry['sha256']})
    declaration={'schema':'octra-local-compiler-binding-v1','endpoint':observation['endpoint'],'binary':{'path':str(binary),'sha256':binary_hash},'launch':{'pid':42},'build_record':build,'source_manifest':source_entry,'launch_record':launch,'native_fixture':fixture_entry,'expected_runtime':runtime}
    for case in ['valid','endpoint','binary','build','source','launch','fixture','profile']:
        value=copy.deepcopy(declaration)
        if case=='endpoint':value['endpoint']='http://127.0.0.1:1/rpc'
        if case=='binary':value['binary']['sha256']='0'*64
        if case in ['build','source','launch','fixture']:value[{'build':'build_record','source':'source_manifest','launch':'launch_record','fixture':'native_fixture'}[case]]['sha256']='0'*64
        if case=='profile':value['expected_runtime']={}
        path=root/'binding.json';path.write_bytes(local.encoded(value))
        try:local.binding(path,observation['endpoint']);assert case=='valid',case
        except ValueError:assert case!='valid',case
        checks.append('binding_'+case)

# Recompilation stays local, consumes only the verified bundle, and preserves
# the compiler result through the pinned artifact. Epoch/validator config may
# advance between separate compile windows without changing the compiler profile.
real_bundle=local.compile_bundle
for case in ['valid','remote_endpoint','rpc_override','changed_main','changed_factory','wrong_binary','wrong_profile','wrong_code','old_cli']:
    with tempfile.TemporaryDirectory() as raw_dir:
        root=pathlib.Path(raw_dir);candidate=root/'candidate';candidate.mkdir();out=root/'preflight'
        compiler=copy.deepcopy(observation);files={}
        (candidate/'compiler-native-fixture.json').write_bytes(fixture_raw)
        for name,raw in results.items():
            (candidate/name).write_bytes(sources[name]);files[name]=local.sha(sources[name])
            (candidate/(name.removesuffix('.aml')+'.octb')).write_bytes(base64.b64decode(json.loads(raw)['bytecode']))
            (candidate/(name+'.compile.json')).write_bytes(b'{"jsonrpc":"2.0","id":1,"result":'+raw+b'}')
        if case=='old_cli':compiler={'version':'old CLI'}
        manifest={'payload':{'files':files,'compiler':compiler}};(candidate/'manifest.json').write_bytes(local.encoded(manifest))
        (candidate/'intent.json').write_bytes(local.encoded({'target':target,'target_binding_sha256':local.digest(target)}))
        def verify(*args,**kwargs):
            if case in ['changed_main','changed_factory']:
                name=names[0] if case=='changed_main' else names[1];(candidate/name).write_bytes(sources[name]+b'changed')
        probe.subprocess.run=verify;probe.targets.select=lambda *args:target
        contacted=[]
        def compile_fixture(endpoint,binding,selected,provided):
            contacted.append(endpoint);assert selected==target and provided==sources
            items={name:{'result':json.loads(raw),'result_raw':raw,'response':b'{"jsonrpc":"2.0","id":1,"result":'+raw+b'}','code':base64.b64decode(json.loads(raw)['bytecode'])} for name,raw in results.items()}
            now=copy.deepcopy(observation)
            # Derived config may change between calls; each captured window is stable.
            now['before']['runtime']['config_hash']='e'*64;now['after']['runtime']['config_hash']='e'*64
            if case=='wrong_binary':now['binary_sha256']='0'*64
            if case=='wrong_profile':now['before']['runtime']['consensus_profile']=17
            if case=='wrong_code':items[names[0]]['code']=b'OCTBchanged'
            return items,now
        local.compile_bundle=compile_fixture
        sys.argv=['probe-mainnet.py','--candidate',str(candidate),'--compiler-rpc-url','https://example.invalid/rpc' if case=='remote_endpoint' else observation['endpoint'],'--compiler-binding',str(root/'binding.json'),'--out',str(out)]
        if case=='rpc_override':sys.argv+=['--rpc-url','https://wrong.invalid/rpc']
        try:
            with contextlib.redirect_stdout(io.StringIO()):probe.main()
            assert case=='valid',case
            report=json.loads((out/'report.json').read_text());assert report['source_uploaded'] is False and report['public_target_preflight'] is False
            real_validate(candidate,out,target)
        except ValueError:assert case!='valid',case
        if case in ['remote_endpoint','rpc_override','changed_main','changed_factory','old_cli']:assert not contacted,case
        checks.append('probe_'+case)
local.compile_bundle=real_bundle

# Portable process ownership path: mocked ps/lsof output only, no real process.
with tempfile.TemporaryDirectory() as raw_dir:
    binary=pathlib.Path(raw_dir)/'node';binary.write_bytes(b'public binary fixture')
    declaration={'binary':{'path':str(binary),'sha256':local.sha(binary.read_bytes())},'launch':{'pid':2147483647},'endpoint':observation['endpoint']}
    original_run=local.subprocess.run;original_which=local.shutil.which
    for case in ['valid','wrong_executable','missing_socket','wrong_pid','changed_binary','missing_lsof']:
        value=copy.deepcopy(declaration)
        if case=='changed_binary':value['binary']['sha256']='0'*64
        local.shutil.which=lambda name:'/fixture/'+name if not (case=='missing_lsof' and name=='lsof') else None
        def run(parts,**kwargs):
            assert 'args=' not in parts
            output=(str(binary) if case!='wrong_executable' else '/wrong/executable') if parts[0].endswith('/ps') else ('p2147483647\n' if case not in ['missing_socket','wrong_pid'] else 'p1\n')
            return argparse.Namespace(returncode=1 if case=='missing_socket' and parts[0].endswith('/lsof') else 0,stdout=output)
        local.subprocess.run=run
        try:local.ownership(value);assert case=='valid',case
        except ValueError:assert case!='valid',case
        checks.append('ownership_'+case)
    local.subprocess.run=original_run;local.shutil.which=original_which

# The source transport explicitly disables environment proxies and redirects;
# native result bytes are recovered without canonicalizing field order.
original_opener=local.urllib.request.build_opener
for case in ['valid','duplicate','error','oversize']:
    result=results[names[1]]
    raw=b'{"jsonrpc":"2.0", "id":1, "result": '+result+b'}'
    if case=='duplicate':raw=b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}'
    if case=='error':raw=b'{"jsonrpc":"2.0","id":1,"error":{}}'
    if case=='oversize':raw=b' '*(local.MAX_RESPONSE+1)
    class Response:
        status=200
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,limit):assert limit==local.MAX_RESPONSE+1;return raw
    class Opener:
        def open(self,request,timeout):assert request.full_url==observation['endpoint'] and timeout==30;return Response()
    def opener(proxy,redirect):
        assert proxy.proxies=={}
        try:redirect.redirect_request(None,None,None,None,None,None);raise AssertionError('redirect followed')
        except ValueError:pass
        return Opener()
    local.urllib.request.build_opener=opener
    try:
        _,_,actual=local.rpc(observation['endpoint'],'octra_compileAml',['public fixture source',True]);assert case=='valid';assert actual==result
    except ValueError:assert case!='valid'
    checks.append('transport_'+case)
local.urllib.request.build_opener=original_opener

# Keep failures before wallet/prover/RPC. This does not mock away load validation;
# the negative local artifact validation happens at main's explicit boundary.
for case in ['missing_local','bad_local_artifact']:
    with tempfile.TemporaryDirectory() as raw_dir:
        root=pathlib.Path(raw_dir);preflight=root/'preflight';preflight.mkdir()
        if case=='bad_local_artifact':(preflight/'report.json').write_text(json.dumps({'compiler':{'kind':'verified_local_rust_node'}}))
        deploy.load=lambda *args:({'constructor_args':[0]*9},{},target)
        deploy.local_compiler.validate_saved=lambda *args:(_ for _ in ()).throw(ValueError('fixture rejected before wallet'))
        deploy.command=lambda *args:(_ for _ in ()).throw(AssertionError('wallet/subprocess called'))
        deploy.rpc=lambda *args:(_ for _ in ()).throw(AssertionError('network called'))
        sys.argv=['deploy-canary.py','--candidate',str(root),'--preflight',str(preflight),'--broadcast','--key','missing-key','--credential','missing-credential','--setup','missing-setup','--out',str(root/'out')]
        try:deploy.main();raise AssertionError(case)
        except ValueError:checks.append('early_'+case)

print(json.dumps({'status':'PASS','controls':len(checks),'cases':checks,'scope':'Offline pinned-native-result and mocked ordering controls only; no process/socket/wallet/prover/signing/network activity.'},indent=2))
