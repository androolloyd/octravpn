"""Local Rust compiler provenance and exact native-profile artifact validation."""
import base64,hashlib,ipaddress,json,pathlib,re,shutil,subprocess,urllib.parse,urllib.request

MAX_RESPONSE=4*1024*1024
PROFILE_FIELDS={'consensus_standard_hash','activation_graph_hash','consensus_profile','consensus_rules_id','runtime_profile_hash','chain_id'}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(value):return sha(encoded(value))
def hash_file(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda:stream.read(1048576),b''):value.update(part)
    return value.hexdigest()

def read(path,limit=MAX_RESPONSE):
    if path.is_symlink() or not path.is_file():raise ValueError('compiler evidence must be a regular public file')
    with path.open('rb') as stream:raw=stream.read(limit+1)
    if len(raw)>limit:raise ValueError('compiler evidence exceeds size bound')
    return raw

def loopback(url):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='http' or parsed.path!='/rpc' or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError('compiler RPC must be literal HTTP loopback /rpc with an explicit port')
    try:address=ipaddress.ip_address(parsed.hostname or '');port=parsed.port
    except ValueError as error:raise ValueError('compiler RPC requires a literal loopback address') from error
    if str(address) not in ('127.0.0.1','::1') or port is None:
        raise ValueError('compiler RPC requires 127.0.0.1 or ::1 and an explicit port')
    return port

def checked_json(entry):
    path=pathlib.Path(entry['path']);raw=read(path)
    if sha(raw)!=entry['sha256']:raise ValueError('compiler evidence hash differs')
    return json.loads(raw)

def ownership(binding):
    pid=binding['launch']['pid'];binary=pathlib.Path(binding['binary']['path']).resolve()
    if type(pid) is not int or pid<=0:raise ValueError('invalid compiler process identity')
    proc=pathlib.Path('/proc')/str(pid)/'exe'
    if proc.exists():actual=proc.resolve()
    else:
        ps=shutil.which('ps')
        if not ps:raise ValueError('cannot verify local compiler executable ownership: ps unavailable')
        result=subprocess.run([ps,'-p',str(pid),'-o','comm='],capture_output=True,text=True)
        if result.returncode or not result.stdout.strip():raise ValueError('local compiler process unavailable')
        actual=pathlib.Path(result.stdout.strip()).resolve()
    if actual!=binary:raise ValueError('local compiler executable differs from launch binding')
    lsof=shutil.which('lsof')
    if not lsof:raise ValueError('cannot verify local compiler listening socket: lsof unavailable')
    result=subprocess.run([lsof,'-nP','-a','-p',str(pid),'-iTCP:'+str(loopback(binding['endpoint'])),'-sTCP:LISTEN','-Fp'],capture_output=True,text=True)
    if result.returncode or ('p'+str(pid)) not in result.stdout.splitlines():
        raise ValueError('local compiler process does not own the selected listening port')
    if hash_file(binary)!=binding['binary']['sha256']:raise ValueError('local compiler binary changed')


def binding(path,endpoint):
    loopback(endpoint);raw=read(path);value=json.loads(raw)
    if value.get('schema')!='octra-local-compiler-binding-v1' or value.get('endpoint')!=endpoint:
        raise ValueError('local compiler binding endpoint/schema differs')
    build=checked_json(value['build_record']);sources=checked_json(value['source_manifest']);launch=checked_json(value['launch_record'])
    binary=value['binary'];binary_path=pathlib.Path(binary['path'])
    if not binary_path.is_file() or binary_path.is_symlink() or hash_file(binary_path)!=binary['sha256']:
        raise ValueError('local compiler physical binary hash differs')
    if build.get('exit_code')!=0 or build.get('source_drift')!=[] or build.get('binary_sha256')!=binary['sha256']:
        raise ValueError('local compiler build record is not a successful bound build')
    if launch.get('binary_sha256')!=binary['sha256'] or build.get('source_manifest_sha256')!=value['source_manifest']['sha256'] or launch.get('source_manifest_sha256')!=value['source_manifest']['sha256']:
        raise ValueError('local compiler source/build/launch records disagree')
    if launch.get('pid')!=value['launch']['pid']:raise ValueError('local compiler launch process differs')
    fixture=checked_json(value['native_fixture'])
    if sources.get('crates/octra-node-protocol/tests/fixtures/vpn-compiler.json')!=value['native_fixture']['sha256']:
        raise ValueError('native compiler fixture is not bound to the actual build source capture')
    if not PROFILE_FIELDS.issubset(value.get('expected_runtime',{})):
        raise ValueError('compiler binding must declare the complete runtime/profile identity')
    return {'declaration':value,'declaration_sha256':sha(raw),'build_record':build,'source_manifest_sha256':value['source_manifest']['sha256'],'native_fixture':fixture}


def rpc(endpoint,method,params):
    loopback(endpoint)
    request=urllib.request.Request(endpoint,data=encoded({'jsonrpc':'2.0','id':1,'method':method,'params':params}),headers={'Content-Type':'application/json'})
    # Explicit no-proxy/no-redirect transport: source must stay on this socket.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):raise ValueError('local compiler redirect refused')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(request,timeout=30) as response:
        if response.status!=200:raise ValueError('local compiler HTTP status differs')
        raw=response.read(MAX_RESPONSE+1)
    if len(raw)>MAX_RESPONSE:raise ValueError('local compiler response exceeds bound')
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out:raise ValueError('duplicate local compiler JSON member')
            out[key]=value
        return out
    value=json.loads(raw,object_pairs_hook=unique)
    if value.get('jsonrpc')!='2.0' or value.get('id')!=1 or 'error' in value or 'result' not in value:
        raise ValueError('local compiler RPC refused or returned an invalid envelope')
    return value['result'],raw,member(raw,'result')


def member(raw,name):
    """Return a top-level member's actual UTF-8 JSON bytes, without reordering."""
    text=raw.decode('utf-8');decoder=json.JSONDecoder();offset=0
    def space(i):
        while i<len(text) and text[i].isspace():i+=1
        return i
    offset=space(offset)
    if offset>=len(text) or text[offset]!='{':raise ValueError('invalid compiler JSON object')
    offset+=1
    while True:
        offset=space(offset)
        if offset>=len(text) or text[offset]=='}':raise ValueError('compiler JSON member unavailable: '+name)
        key,offset=decoder.raw_decode(text,offset);offset=space(offset)
        if offset>=len(text) or text[offset]!=':':raise ValueError('invalid compiler JSON member')
        start=space(offset+1);_,offset=decoder.raw_decode(text,start)
        if key==name:return text[start:offset].encode()
        offset=space(offset)
        if offset<len(text) and text[offset]==',':offset+=1
        elif offset>=len(text) or text[offset]!='}':raise ValueError('invalid compiler JSON delimiter')


def runtime(endpoint,target,expected):
    value,raw,_=rpc(endpoint,'octra_runtimeVersion',[])
    if value.get('schema')!='octra-runtime-release-v1':raise ValueError('unknown local compiler runtime schema')
    if target.get('chain_id') and value.get('chain_id')!=target['chain_id']:raise ValueError('local compiler chain differs from independent target')
    for key,entry in expected.items():
        if value.get(key)!=entry:raise ValueError('local compiler runtime/profile changed: '+key)
    status,status_raw,_=rpc(endpoint,'node_status',[])
    epoch=status.get('head_epoch');root=status.get('state_root')
    if type(epoch) is not int or epoch<0 or not isinstance(root,str) or not re.fullmatch('[0-9a-f]{64}',root):raise ValueError('local compiler canonical head unavailable')
    if target.get('origin',{}).get('kind')=='checkpoint' and epoch<target['origin']['epoch']:raise ValueError('local compiler head precedes independent checkpoint origin')
    return {'runtime':value,'runtime_response_sha256':sha(raw),'head_epoch':epoch,'state_root':root,'status_response_sha256':sha(status_raw)}


def validate_result(name,source,result,result_raw,fixture):
    code=base64.b64decode(result['bytecode'],validate=True)
    if not code.startswith(b'OCTB') or base64.b64encode(code).decode()!=result['bytecode']:raise ValueError('local compiler OCTB encoding differs')
    certificate=result['certificate']
    if certificate.get('source_hash')!=sha(source) or certificate.get('bytecode_hash')!=sha(code) or result.get('verification',{}).get('errors')!=0:
        raise ValueError('local compiler source/code/safety certificate mismatch')
    if certificate.get('verification_hash')!=sha(member(result_raw,'verification')):
        raise ValueError('local compiler verification certificate mismatch')
    labels=re.findall(r'^JDEST (\d+)$',result['disasm'],re.M)
    if len(set(labels))!=len(labels):raise ValueError('local compiler duplicate jump label')
    if fixture['vpn_source_sha256'].get('program/'+name)!=sha(source):raise ValueError('native fixture source differs')
    matches=[{'syntax':case['syntax'],'loops':case['loops']} for case in fixture['cases'] if case['path']=='program/'+name and base64.b64decode(case['expected'].get('rpc',''))==result_raw]
    if not matches:raise ValueError('local compiler complete result bytes differ from pinned native profiles')
    return code,matches


def compile_bundle(endpoint,binding_path,target,sources):
    bound=binding(binding_path,endpoint);declaration=bound['declaration'];ownership(declaration)
    fixture=bound['native_fixture']
    if target.get('authority',{}).get('upstream_commit') not in (None,fixture['upstream_commit']):raise ValueError('native fixture pin differs from independently adopted target')
    before=runtime(endpoint,target,declaration['expected_runtime']);artifacts={};profiles=None
    for name,source in sources.items():
        result,raw,result_raw=rpc(endpoint,'octra_compileAml',[source.decode('utf-8'),True])
        code,matches=validate_result(name,source,result,result_raw,fixture)
        selected={(m['syntax'],m['loops']) for m in matches};profiles=selected if profiles is None else profiles&selected
        artifacts[name]={'result':result,'response':raw,'result_raw':result_raw,'code':code,'native_profiles':matches}
    if not profiles:raise ValueError('sources did not compile under one consistent native profile')
    after=runtime(endpoint,target,declaration['expected_runtime']);ownership(declaration)
    if after['runtime']!=before['runtime'] or after['head_epoch']<before['head_epoch']:raise ValueError('local compiler context changed during compilation')
    observation={'kind':'verified_local_rust_node','endpoint':endpoint,'binding_sha256':bound['declaration_sha256'],'binary_sha256':declaration['binary']['sha256'],'source_manifest_sha256':bound['source_manifest_sha256'],'native_fixture_sha256':declaration['native_fixture']['sha256'],'upstream_commit':fixture['upstream_commit'],'native_profiles':[{'syntax':s,'loops':l} for s,l in sorted(profiles)],'before':before,'after':after,'network_authority_scope':'Runtime fields are selfreported observations; independent target/env/config/checkpoint remains separate. Runtime derived config_hash is not the network consensus config_hash.','target_execution_qualified':False}
    return artifacts,observation


def artifact(target,observation,item):
    """Public, caller-hash-pinned deployment input; it contains no signing material."""
    return {'schema':'octra-compiled-artifact-v1','rpc_url':target['rpc_url'],
            'target_binding_sha256':digest(target),'compiler':observation,
            'verification_json_b64':base64.b64encode(member(item['result_raw'],'verification')).decode(),
            'result':item['result']}


def validate_saved(candidate,preflight,target):
    """Revalidate all public compiler artifacts offline before wallet/prover access."""
    report=json.loads(read(preflight/'report.json'))
    observation=report.get('compiler',{})
    if observation.get('kind')!='verified_local_rust_node' or report.get('public_target_preflight') is not False:
        raise ValueError('preflight must use a verified local Rust compiler; public source upload is disabled')
    loopback(observation['endpoint'])
    if report.get('target')!=target or report.get('target_binding_sha256')!=digest(target) or report.get('rpc_url')!=target['rpc_url']:
        raise ValueError('local compiler preflight target differs from independently pinned candidate')
    fixture_raw=read(candidate/'compiler-native-fixture.json')
    if sha(fixture_raw)!=observation['native_fixture_sha256']:raise ValueError('pinned native compiler fixture changed')
    fixture=json.loads(fixture_raw)
    if target.get('authority',{}).get('upstream_commit') not in (None,fixture['upstream_commit']):raise ValueError('local compiler fixture pin differs from target')
    manifest=json.loads(read(candidate/'manifest.json'))
    if manifest['payload'].get('compiler')!=observation:raise ValueError('candidate/preflight local compiler observations differ')
    before=observation['before'];after=observation['after']
    if before['runtime']!=after['runtime'] or after['head_epoch']<before['head_epoch']:raise ValueError('compiler profile/head window changed')
    if target.get('chain_id') and before['runtime'].get('chain_id')!=target['chain_id']:raise ValueError('local compiler chain differs from target')
    for key in ('binding_sha256','binary_sha256','source_manifest_sha256','native_fixture_sha256'):
        if not re.fullmatch('[0-9a-f]{64}',observation.get(key,'')):raise ValueError('local compiler provenance digest missing: '+key)
    for name in ('main-v5.aml','private-admin-factory.aml'):
        source=read(candidate/name);check=report['checks'][name];raw=read(preflight/(name+'.compile.json'))
        if check['source_sha256']!=sha(source) or check['artifact_sha256']!=sha(raw):raise ValueError('local compile source/artifact hash changed: '+name)
        envelope=json.loads(raw)
        if envelope.get('jsonrpc')!='2.0' or envelope.get('id')!=1 or 'error' in envelope:raise ValueError('saved local compile envelope differs')
        result=envelope['result'];result_raw=member(raw,'result');code,matches=validate_result(name,source,result,result_raw,fixture)
        if not all(profile in matches for profile in observation['native_profiles']) or not observation['native_profiles']:raise ValueError('local compiler native profile changed')
        if code!=read(candidate/(name.removesuffix('.aml')+'.octb')) or check['bytecode_sha256']!=sha(code):raise ValueError('candidate and local preflight OCTB differ: '+name)
        saved_raw=read(preflight/(name+'.artifact.json'));saved=json.loads(saved_raw)
        expected=artifact(target,observation,{'result':result,'result_raw':result_raw})
        if saved!=expected or check['deployment_artifact_sha256']!=sha(saved_raw):raise ValueError('verified deployment artifact changed: '+name)
    return report
