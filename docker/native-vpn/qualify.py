#!/usr/bin/env python3
"""Fresh-process native chain + production AML + paid authenticated VPN gate."""
import base64, hashlib, json, os, pathlib, re, shutil, signal, socket
import subprocess, threading, time, traceback, urllib.error, urllib.request

ROOT=pathlib.Path('/tmp/native-vpn'); EVIDENCE=pathlib.Path('/evidence')
RPC='http://127.0.0.1:19871/rpc'; BASE=19870; FEE=200_000
PUBLIC='93.184.216.34'; RECEIPT_CHAIN=9871
PROCESSES={}; FILES={}; JOURNAL={'qualified':False,'scope':'isolated activated application genesis; no public-chain parity claim','steps':[]}
def save():
    (EVIDENCE/'journal.json').write_text(json.dumps(JOURNAL,indent=2)+'\n')
def step(name, **details):
    JOURNAL['steps'].append({'step':name,**details});save();print(json.dumps({'step':name,**details}),flush=True)
def command(args, timeout=120):
    result=subprocess.run([str(v) for v in args],capture_output=True,text=True,timeout=timeout,cwd=ROOT if ROOT.exists() else '/tmp')
    if result.returncode: raise RuntimeError(f'{args[0]} {args[1]} exited {result.returncode}: {result.stderr[-4000:]}')
    return result.stdout.strip()
def cli(*args):return json.loads(command(['octra',*args]))
def rpc(method,params,endpoint=RPC):
    request=urllib.request.Request(endpoint,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=10) as response: raw=response.read(4_500_001)
    if len(raw)>4_500_000:raise ValueError('RPC response byte bound')
    result=json.loads(raw)
    if result.get('id')!=1 or 'error' in result or 'result' not in result:raise RuntimeError(f'{method}: {result}')
    return result['result']
def get(url,host=None):
    request=urllib.request.Request(url,headers={'Host':host} if host else {})
    with urllib.request.urlopen(request,timeout=10) as response:return response.read(4_500_001),dict(response.headers)
def until(fn,seconds=90,label='condition'):
    deadline=time.monotonic()+seconds; last=None
    while time.monotonic()<deadline:
        stopped=[name for name,process in PROCESSES.items() if process.poll() is not None]
        if stopped:raise RuntimeError(f'qualification processes stopped unexpectedly: {stopped}; inspect retained public logs')
        try:
            value=fn()
            if value:return value
        except (OSError,RuntimeError,ValueError,KeyError,TypeError) as error:last=str(error)
        time.sleep(.2)
    raise TimeoutError(f'{label} timed out: {last}')
def find_hash(value):
    if isinstance(value,dict):
        if isinstance(value.get('tx_hash'),str):return value['tx_hash']
        for child in value.values():
            found=find_hash(child)
            if found:return found
    return None
def receipt(hash_,expected=True,vm=True):
    if not hash_:raise ValueError('submission lacks transaction hash')
    def poll():
        tx=rpc('octra_transaction',[hash_]); status=tx.get('status')
        if status in ['rejected','dropped']:
            if not expected and status=='rejected':return {'success':False,'transaction':tx}
            raise ValueError(f'{hash_}: terminal transaction: {tx}')
        if status=='confirmed':return rpc('contract_receipt',[hash_]) if vm else {'success':True,'transaction':tx}
        return None
    result=until(poll,120,'transaction '+hash_)
    if result.get('success') is not expected:raise ValueError(f'wrong execution outcome: {result}')
    return result
def record(label,result,expected=True,vm=True):
    hash_=find_hash(result)
    JOURNAL['in_flight']={'step':label,'tx_hash':hash_};save()
    value=receipt(hash_,expected,vm)
    JOURNAL.pop('in_flight',None)
    step(label,tx_hash=hash_,receipt=value)
    return value
def send(label,key,program,method,params,value=0,expected=True):
    result=cli('cast','send',program,method,*[json.dumps(v,separators=(',',':')) for v in params],
        '--key',key,'--rpc-url',RPC,'--fee',FEE,'--value',value)
    return record(label,result,expected)
def view(program,method,params=None):
    result=rpc('contract_call',[program,method,params or []])
    if not isinstance(result,dict) or 'result' not in result:raise ValueError(f'{method}: invalid view {result}')
    return result['result']
def start(index):
    path=ROOT/'chain'/f'node-{index}'/'config.json'
    logfile=EVIDENCE/f'node-{index}.log';stream=logfile.open('a')
    process=subprocess.Popen(['octra-node','run','--config',str(path)],stdout=stream,stderr=subprocess.STDOUT,cwd=ROOT,env={**os.environ,'RUST_LOG':'info'})
    PROCESSES[index]=process;FILES[index]=stream
def stop(index):
    process=PROCESSES.pop(index);process.send_signal(signal.SIGTERM)
    try: process.wait(timeout=20)
    except subprocess.TimeoutExpired:process.kill();process.wait();raise RuntimeError('node failed graceful shutdown')
    FILES.pop(index).close()
    if process.returncode:raise RuntimeError(f'node {index} exited {process.returncode}')
def epoch(index=0):
    body,_=get(f'http://127.0.0.1:{BASE+index*10+1}/operator/status')
    return json.loads(body)['epoch']
def recover_active(program,session,logfile,after_start=None):
    """Restart the real funded operator without restarting/funding the client."""
    state_url='http://127.0.0.1:19873/session/'+(session.to_bytes(8,'big')+bytes(24)).hex()
    before=json.loads(get(state_url)[0]);count=view(program,'get_session_count')
    previous_resumes=logfile.read_text().count('existing VPN session authenticated and resumed without new escrow')
    previous_pauses=logfile.read_text().count('pausing existing VPN session for authenticated recovery')
    open_hashes=re.findall(r'v3 open_session submitted.*?tx_hash[^=]*=\s*([0-9a-f]{64})',re.sub(r'\x1b\[[0-9;]*m','',logfile.read_text()))
    assert len(open_hashes)==1,'client must have exactly one funded opening before reconnect'
    stop(0)
    until(lambda:logfile.read_text().count('pausing existing VPN session for authenticated recovery')>previous_pauses,25,'fail-closed session recovery pause')
    start(0)
    if after_start:after_start()
    until(lambda:logfile.read_text().count('existing VPN session authenticated and resumed without new escrow')>previous_resumes,65,'same-session canonical admission and new WireGuard handshake')
    after=json.loads(get(state_url)[0])
    assert after['last_seq']>before['last_seq'] and after['bytes_served']>=before['bytes_served']
    assert view(program,'get_session_count')==count and int(view(program,'get_session_status',[session]))==0
    current_hashes=re.findall(r'v3 open_session submitted.*?tx_hash[^=]*=\s*([0-9a-f]{64})',re.sub(r'\x1b\[[0-9;]*m','',logfile.read_text()))
    assert current_hashes==open_hashes,'reconnect must never fund another escrow'
    step('active session survives native operator restart without new escrow',session=session,opening_hash=open_hashes[0],session_count=count,previous_seq=before['last_seq'],recovered_seq=after['last_seq'],previous_bytes=before['bytes_served'],recovered_bytes=after['bytes_served'])
def secret_hex(raw,name):
    value=pathlib.Path(raw).read_bytes();assert len(value)==32
    path=ROOT/name;path.write_text(value.hex()+'\n');path.chmod(0o600);return path
def credential(name):
    path=ROOT/f'{name}.credential';result=json.loads(command(['octravpn-private-admin','credential','--out',path]));return path,result['commitment']
def authorize(program,credential_,domain,method,params,label):
    request=ROOT/f'{label}.request.json';request.write_text(json.dumps({'method':method,'params':params})+'\n')
    output=ROOT/f'{label}.authorization.json'
    command(['octravpn-private-admin','authorize','--credential',credential_,'--proving-key',ROOT/'setup/proving-key.bin',
        '--request',request,'--domain',domain,'--program',program,'--nonce',int(view(program,'get_admin_nonce')),'--out',output],300)
    return json.loads(output.read_text())
def admin(label,program,key,credential_,domain,method,params):
    authorization=authorize(program,credential_,domain,method,params,label)
    return send(label,key,program,authorization['method'],authorization['params']),authorization
def native_guard():
    assert pathlib.Path('/.dockerenv').exists(),'requires a disposable Linux container'
    links=json.loads(command(['ip','-j','link','show']))
    assert [link['ifname'] for link in links]==['lo'],'container must have only loopback'
    assert not json.loads(command(['ip','-j','route','show','default'])),'external default route forbidden'
    command(['ip','link','set','lo','up'])
    command(['ip','address','add',PUBLIC+'/32','dev','lo'])
def udp_diagnostic(program,session,index,received,payload,reflector,echo_stats,started,local):
    value={'event':'initial paid UDP timeout','utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns(),'start_monotonic_ns':started,'index':index,'sent_datagrams':index+1,'received_payload_bytes':received,'current_payload_b64':base64.b64encode(payload).decode(),'reflector_alive':reflector.is_alive(),'echo_counters':dict(echo_stats),'processes':{str(name):process.poll() for name,process in PROCESSES.items()},'socket_timeout_seconds':.5,'required_received_payload_bytes':1_200_000}
    def read(url,body=None):
        request=urllib.request.Request(url,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json'} if body is not None else {})
        with urllib.request.urlopen(request,timeout=2) as response:raw=response.read(1_000_001)
        if len(raw)>1_000_000:raise ValueError('diagnostic byte bound')
        return json.loads(raw)
    value['observations']={}
    def capture(name,fn):
        began=time.monotonic_ns()
        try:result={'value':fn()}
        except Exception as error:result={'error':repr(error)}
        result.update({'began_monotonic_ns':began,'completed_monotonic_ns':time.monotonic_ns()});value['observations'][name]=result
        (EVIDENCE/'udp-failure.json').write_text(json.dumps(value,indent=2)+'\n')
    for path in ['/proc/loadavg','/proc/pressure/cpu','/proc/pressure/io','/proc/pressure/memory','/proc/net/snmp','/proc/net/udp','/proc/stat']:
        capture(path,lambda path=path:pathlib.Path(path).read_text()[:65536])
    state='http://127.0.0.1:19873/session/'+(session.to_bytes(8,'big')+bytes(24)).hex()
    capture('signed_control_state',lambda:read(state))
    for method,params in [('get_session_status',[session]),('get_session_count',[]),('get_session_policy_root',[session]),('get_claim_net_set',[session]),('get_circle_receipt_pubkey',[JOURNAL['operator_circle']])]:
        capture('canonical_'+method,lambda method=method,params=params:read(RPC,{'jsonrpc':'2.0','id':1,'method':'contract_call','params':[program,method,params]}))
    capture('native_operator_status',lambda:read('http://127.0.0.1:19871/operator/status'))
    value['same_session_followup_probes']=[]
    for attempt in range(3):
        probe=b'diagnostic-followup-after-original-timeout:'+index.to_bytes(4,'big')+bytes([attempt]);event={'attempt':attempt,'began_monotonic_ns':time.monotonic_ns()}
        try:
            local.sendto(probe,('127.0.0.1',20002));data,peer=local.recvfrom(2048);event.update({'matched':data==probe,'reply_bytes':len(data),'reply_b64':base64.b64encode(data).decode()})
        except Exception as error:event['error']=repr(error)
        event['completed_monotonic_ns']=time.monotonic_ns();value['same_session_followup_probes'].append(event)
        time.sleep(.2)
    capture('signed_control_state_after_probe',lambda:read(state))
    value['log_tails']={path.name:path.read_text()[-12000:] for path in EVIDENCE.glob('*.log')}
    value['receipt_signature_scope']='Signed control proposal and independent on-chain receipt key retained verbatim for verification; this Python diagnostic does not itself verify Ed25519.'
    (EVIDENCE/'udp-failure.json').write_text(json.dumps(value,indent=2)+'\n')

def main():
    native_guard();ROOT.mkdir(mode=0o700);EVIDENCE.chmod(0o700)
    shutil.copyfile('/usr/local/share/native-source.json',EVIDENCE/'source.json');save()
    command(['octravpn-private-admin','setup','--development','--out',ROOT/'setup'],300)
    setup=json.loads((ROOT/'setup/manifest.json').read_text());assert setup['development_only'] and not setup['production_ready']
    owner,commitment=credential('owner');next_owner,next_commitment=credential('next-owner');rotated,rotated_commitment=credential('rotated')
    command(['octra-node','init-devnet','--directory',ROOT/'chain','--base-port',BASE,'--activated-applications'])
    configs=[json.loads((ROOT/'chain'/f'node-{i}'/'config.json').read_text()) for i in range(4)]
    for i,cfg in enumerate(configs):
        assert cfg['genesis']['activated_applications'] is True
        cfg['gateway']={'listen':f'127.0.0.1:{BASE+i*10+5}','origin':'https://circles.example.ts.net'}
        (ROOT/'chain'/f'node-{i}'/'config.json').write_text(json.dumps(cfg))
    JOURNAL['genesis']=configs[0]['genesis'];save()
    faucet=secret_hex(ROOT/'chain/faucet.key','faucet.hex')
    operator=secret_hex(ROOT/'chain/node-0/validator.key','operator.hex')
    operator_addr=command(['octra','cast','wallet','addr','--key',operator])
    for i in range(4):start(i)
    for i in range(4):until(lambda i=i:epoch(i)>=2,120,f'validator {i} finalized')
    step('four native validator processes finalized',epoch=epoch())
    record('fund native operator',cli('cast','transfer',operator_addr,300_000_000,'--key',faucet,'--rpc-url',RPC,'--ou',1000),vm=False)

    domain=hashlib.sha256(b'isolated-native-paid-vpn-v1'+json.dumps(configs[0]['genesis'],sort_keys=True).encode()).hexdigest()
    artifacts={}
    for name in ['main-v5.aml','private-admin-factory.aml']:
        source=pathlib.Path('/usr/local/share/aml')/name;artifact=rpc('octra_compileAml',[source.read_text()])
        raw=base64.b64decode(artifact['bytecode'],validate=True)
        assert artifact['certificate']['bytecode_hash']==hashlib.sha256(raw).hexdigest()
        assert artifact['certificate']['source_hash']==hashlib.sha256(source.read_bytes()).hexdigest()
        artifacts[name]=artifact;(EVIDENCE/(name+'.compile.json')).write_text(json.dumps(artifact,indent=2))
    before=epoch();assert before<64,'deployments must be inside explicitly qualified native ProgramSource overlap'
    deployed=record('deploy unchanged private-admin factory',cli('forge','create','/usr/local/share/aml/private-admin-factory.aml','--key',faucet,'--rpc-url',RPC,'--ou',FEE,'--no-wait'))
    factory=deployed['contract'];assert rpc('vm_contract',[factory])['code_hash']==artifacts['private-admin-factory.aml']['certificate']['bytecode_hash']
    values=[1_000_000,1_000_000,100_000_000,10_000,1_000,commitment,setup['verification_key_b64'],domain,200_000_000]
    spawned=send('factory deploy unchanged VPN',faucet,factory,'deploy_vpn',[artifacts['main-v5.aml']['bytecode'],*values])
    children=[event['values'][0] for event in spawned.get('events',[]) if event.get('event')=='VPNDeployed'];assert len(children)==1
    program=children[0];code_hash=artifacts['main-v5.aml']['certificate']['bytecode_hash']
    info=rpc('vm_contract',[program]);assert info['code_hash']==code_hash and info['owner']==factory
    assert int(view(program,'get_settlement_version'))==2
    assert epoch()<64,'binary deployment overlap elapsed'
    step('factory child code and non-upgradeable owner pinned',program=program,factory=factory,code_hash=code_hash,deployment_epoch=epoch())

    _,pause=admin('private pause',program,faucet,owner,domain,'set_paused',[1])
    nonce=view(program,'get_admin_nonce')
    send('private authorization replay rejected',faucet,program,pause['method'],pause['params'],expected=False)
    assert view(program,'get_admin_nonce')==nonce
    admin('private handoff proposed',program,faucet,owner,domain,'propose_admin',[next_commitment,0])
    handoff=view(program,'get_admin_handoff_id')
    admin('private recipient accepts handoff',program,faucet,next_owner,domain,'accept_admin',[next_commitment,handoff])
    assert view(program,'get_admin_commitment')==next_commitment
    rejected=authorize(program,owner,domain,'set_paused',[1],'retired-owner')
    retired_nonce=view(program,'get_admin_nonce')
    send('retired private admin rejected after handoff',faucet,program,rejected['method'],rejected['params'],expected=False)
    assert view(program,'get_admin_nonce')==retired_nonce
    admin('private credential rotation proposed',program,faucet,next_owner,domain,'propose_admin',[rotated_commitment,1])
    admin('private rotated credential accepted',program,faucet,rotated,domain,'accept_admin',[rotated_commitment,view(program,'get_admin_handoff_id')])
    admin('private unpause',program,faucet,rotated,domain,'set_paused',[0])
    assert view(program,'get_admin_commitment')==rotated_commitment

    payload={'runtime':'octb','privacy_class':'public','browser_mode':'gateway_allowed','resource_mode':'public_resources',
        'code_b64':None,'policy_hash':None,'members_root':None,'export_policy':None,
        'limits':{'max_stable_bytes':'33554432','max_assets_bytes':'33554432','max_inline_value':'65536','max_wasm_bytes':'33554432'}}
    payload_path=ROOT/'circle.json';payload_path.write_text(json.dumps(payload))
    circle_submit=cli('cast','circle','deploy','--key',operator,'--rpc-url',RPC,'--payload',payload_path,'--ou',FEE)
    circle=circle_submit['circle_id'];record('deploy native operator public Circle',circle_submit,vm=False)
    admin('private approve native operator',program,faucet,rotated,domain,'approve_circle_registration',[circle,operator_addr])
    descriptor=json.loads(command(['octra-node','vpn-identity','--key',ROOT/'chain/node-0/validator.key']))
    assert descriptor['operator']==operator_addr
    descriptor_path=ROOT/'native-identity.json';descriptor_path.write_text(json.dumps(descriptor))
    operator_config=ROOT/'operator.toml';operator_config.write_text(f'''[chain]
rpc_url = "{RPC}"
program_addr = "{program}"
validator_addr = "{operator_addr}"
wallet_secret_path = "{operator}"
protocol_version = "v3"
application = "program"
chain_id = {RECEIPT_CHAIN}
circle_id = "{circle}"
circle_v3_state_path = "{ROOT}/circle-v3.toml"
v3_initial_stake = 100000000
[tunnel]
public_endpoint = "127.0.0.1:19874"
listen = "127.0.0.1:19874"
wg_secret_path = "{operator}"
[control]
listen = "127.0.0.1:19873"
public_endpoint = "http://127.0.0.1:19873"
[pricing]
price_per_mb = 1000
price_per_mb_shared = 1000
price_per_mb_internal = 0
region = "isolated"
''')
    command(['octravpn-node','--config',operator_config,'circle','bootstrap','--circle',circle,'--native-identity',descriptor_path,'--commit'],180)
    assert view(program,'get_circle_active',[circle]) is True
    assert view(program,'get_circle_receipt_pubkey',[circle])==descriptor['receipt_pubkey_b64']
    step('immutable discovery and native receipt identity registered',circle=circle,anchor=view(program,'get_circle_state_root',[circle]),native_identity=descriptor)
    html=ROOT/'index.html';html.write_text('<!doctype html><title>Native paid VPN</title><p>canonical paid VPN gateway</p>')
    asset=record('publish committed gateway asset',cli('cast','circle','put','--circle',circle,'--path','/index.html','--file',html,'--content-type','text/html','--key',operator,'--rpc-url',RPC,'--ou',FEE),vm=False)
    tailnet=send('fund real tailnet treasury',faucet,program,'create_tailnet',['0'*64],value=1_000_000)
    tids=[event['values'][0] for event in tailnet.get('events',[]) if event.get('event')=='TailnetCreated'];assert len(tids)==1;tid=int(tids[0])
    stop(0)
    config=configs[0];config['vpn']={'chain':config['genesis']['chain']['chain_id'],'receipt_chain_id':RECEIPT_CHAIN,'application':'program','program':program,'code_hash':code_hash,'operator_circle':circle,'layout':'source'}
    (ROOT/'chain/node-0/config.json').write_text(json.dumps(config));start(0)
    until(lambda:epoch()>=epoch(1),120,'native VPN restart synchronized')
    client_config=ROOT/'client.toml';faucet_addr=command(['octra','cast','wallet','addr','--key',faucet])
    client_config.write_text(f'''[chain]
rpc_url = "{RPC}"
program_addr = "{program}"
protocol_version = "v3"
chain_id = {RECEIPT_CHAIN}
[wallet]
addr = "{faucet_addr}"
secret_path = "{faucet}"
[v3]
application = "program"
circle_id = "{circle}"
tailnet_id = {tid}
max_pay = 1000000
[v3.relay]
state_dir = "{ROOT}/client-state"
''')
    JOURNAL['operator_circle']=circle;save()
    echo_stats={'received':0,'sent':0,'last_received_index':None,'last_sent_index':None};udp_started=time.monotonic_ns()
    echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo.bind((PUBLIC,20001));echo.settimeout(.2)
    stop_echo=threading.Event()
    def reflect():
        while not stop_echo.is_set():
            try:
                data,peer=echo.recvfrom(2048);echo_stats['received']+=1;echo_stats['last_received_index']=int.from_bytes(data[:4],'big');echo_stats['last_received_monotonic_ns']=time.monotonic_ns()
                echo.sendto(data,peer);echo_stats['sent']+=1;echo_stats['last_sent_index']=int.from_bytes(data[:4],'big');echo_stats['last_sent_monotonic_ns']=time.monotonic_ns()
            except socket.timeout:pass
    reflector=threading.Thread(target=reflect,daemon=True);reflector.start()
    client_log=EVIDENCE/'client.log';stream=client_log.open('w')
    client=subprocess.Popen(['octravpn','--config',str(client_config),'connect-v3','--udp-target',PUBLIC+':20001','--udp-bind','127.0.0.1:20002'],stdout=stream,stderr=subprocess.STDOUT,cwd=ROOT,env={**os.environ,'RUST_LOG':'info'})
    PROCESSES['client']=client;FILES['client']=stream
    until(lambda:re.search(r'v3 session opened: id=(\d+)',client_log.read_text()),120,'real client escrow opening')
    session=int(re.search(r'v3 session opened: id=(\d+)',client_log.read_text()).group(1))
    local=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);local.bind(('127.0.0.1',0));local.settimeout(.5)
    received=0
    lost_datagrams=0
    for index in range(1500):
        if client.poll() is not None:raise RuntimeError('real client exited before forwarding: '+client_log.read_text()[-3000:])
        payload=index.to_bytes(4,'big')+b'paid-native-vpn'*80
        local.sendto(payload,('127.0.0.1',20002))
        try:
            data,_=local.recvfrom(2048)
            if data==payload:received+=len(data)
        except socket.timeout:
            # UDP can lose an isolated datagram even when the authenticated
            # session remains healthy. Bound loss and still require the full
            # paid-byte threshold before proceeding.
            lost_datagrams+=1
            if lost_datagrams>5:
                udp_diagnostic(program,session,index,received,payload,reflector,echo_stats,udp_started,local)
                raise
        if received>=1_200_000:break
        time.sleep(.002)
    assert received>=1_200_000,'real paid traffic threshold not reached'
    recover_active(program,session,client_log)
    payload=b'actual-paid-udp-after-operator-restart';local.settimeout(5)
    local.sendto(payload,('127.0.0.1',20002));data,_=local.recvfrom(2048)
    assert data==payload,'same-session UDP forwarding did not recover';received+=len(data)
    quoted_anchor=view(program,'get_session_policy_root',[session])
    assert quoted_anchor==view(program,'get_circle_state_root',[circle])
    operator_config.write_text(operator_config.read_text().replace('price_per_mb = 1000','price_per_mb = 2000').replace('price_per_mb_shared = 1000','price_per_mb_shared = 2000'))
    command(['octravpn-node','--config',operator_config,'circle','bootstrap','--circle',circle,'--native-identity',descriptor_path,'--force','--commit'],180)
    assert view(program,'get_circle_state_root',[circle])!=quoted_anchor
    assert view(program,'get_session_policy_root',[session])==quoted_anchor
    step('active session keeps its original authenticated tariff across policy rotation',session=session,opening_anchor=quoted_anchor,current_anchor=view(program,'get_circle_state_root',[circle]))
    local.close();stop_echo.set();reflector.join(timeout=2);echo.close()
    client.send_signal(signal.SIGINT);client.wait(timeout=180);stream.close();PROCESSES.pop('client');FILES.pop('client')
    assert client.returncode==0,'client settlement failed: '+client_log.read_text()[-5000:]
    until(lambda:int(view(program,'get_session_status',[session]))==1,120,'real on-chain session settlement')
    earnings=int(view(program,'get_earnings_total',[circle]));assert earnings>0
    matches=re.findall(r'v3 settlement submitted: id=\d+ net=(\d+) bytes_used=(\d+) hash=([0-9a-f]{64})',client_log.read_text());assert len(matches)==1
    net,byte_count,settle_hash=matches[0];settled=receipt(settle_hash);assert earnings==int(net)>0 and int(byte_count)>=received
    step('paid native Pinned WireGuard traffic and both settlement legs',session=session,echo_payload_bytes=received,receipt_bytes=int(byte_count),operator_net=earnings,settle_hash=settle_hash,settlement_receipt=settled)
    assert int(view(program,'get_claim_net',[session]))==earnings

    # This financial negative fixture uses actual signed escrow and an explicit
    # operator claim. Its declared byte count is not transport test evidence.
    negative=send('financial negative fixture: fund a real escrow',faucet,program,'open_session',[tid,circle,1_000_000],value=1_000_000)
    negative_sid=int([event['values'][0] for event in negative['events'] if event['event']=='SessionOpened'][0])
    send('financial negative fixture: operator fixes bytes and amount',operator,program,'settle_claim',[negative_sid,1_048_576,2_000])
    before_attack_earnings=view(program,'get_earnings_total',[circle]);before_attack_escrow=rpc('octra_balance',[program])['balance_raw']
    send('malicious zero-net confirmation rejected',faucet,program,'settle_confirm',[negative_sid,1_048_576,0,'underpayment'],expected=False)
    assert int(view(program,'get_session_status',[negative_sid]))==0
    assert int(view(program,'get_claim_net',[negative_sid]))==2_000
    assert view(program,'get_earnings_total',[circle])==before_attack_earnings and rpc('octra_balance',[program])['balance_raw']==before_attack_escrow
    send('malicious different-net confirmation rejected',faucet,program,'settle_confirm',[negative_sid,1_048_576,1_999,'underpayment'],expected=False)
    assert int(view(program,'get_session_status',[negative_sid]))==0
    assert view(program,'get_earnings_total',[circle])==before_attack_earnings and rpc('octra_balance',[program])['balance_raw']==before_attack_escrow
    send('matching mutually agreed amount settles',faucet,program,'settle_confirm',[negative_sid,1_048_576,2_000,'matching'])
    assert int(view(program,'get_session_status',[negative_sid]))==1

    # A real authenticated client may connect and leave without application data.
    # Both chain legs must agree on zero and refund that actual session escrow.
    zero_log=EVIDENCE/'client-zero.log';zero_stream=zero_log.open('w')
    zero=subprocess.Popen(['octravpn','--config',str(client_config),'connect-v3','--udp-target',PUBLIC+':20001','--udp-bind','127.0.0.1:20002'],stdout=zero_stream,stderr=subprocess.STDOUT,cwd=ROOT,env={**os.environ,'RUST_LOG':'info'})
    PROCESSES['zero']=zero;FILES['zero']=zero_stream
    until(lambda:'authenticated UDP forward ready' in zero_log.read_text(),120,'authenticated zero-byte client')
    zero_sid=int(re.search(r'v3 session opened: id=(\d+)',zero_log.read_text()).group(1))
    zero.send_signal(signal.SIGINT);zero.wait(timeout=180);zero_stream.close();PROCESSES.pop('zero');FILES.pop('zero')
    assert zero.returncode==0,'zero-byte close failed: '+zero_log.read_text()[-4000:]
    assert int(view(program,'get_session_status',[zero_sid]))==1 and int(view(program,'get_claim_net',[zero_sid]))==0
    step('real zero-byte client closes and refunds escrow',session=zero_sid,net=0)
    # This boundary executes only after genuine paid UDP, amount negative
    # controls and zero-byte settlement have all succeeded on the same app.
    import sys,tun_gate
    tun=tun_gate.run(sys.modules[__name__],operator_config=operator_config,descriptor_path=descriptor_path,program=program,circle=circle,client_config=client_config,config=config)
    earnings=int(view(program,'get_earnings_total',[circle]))
    body,headers=until(lambda:get(f'http://127.0.0.1:19875/circles/{circle}/index.html','circles.example.ts.net'),30,'committed HTTPS gateway backend')
    assert b'canonical paid VPN gateway' in body
    assert headers.get('x-octra-chain')==config['genesis']['chain']['chain_id']
    step('gateway reads canonical application asset',body_sha256=hashlib.sha256(body).hexdigest(),headers=headers)
    def archived(hash_):
        for path in (ROOT/'chain/node-0/exex').glob('*.json'):
            event=json.loads(path.read_text())
            if any(tx.get('hash')==hash_ for tx in event.get('events',[])):return path.name,event
    for hash_,evidence_name in [(settle_hash,'settlement-exex.json'),(tun['settlement'],'tun-settlement-exex.json')]:
        name,event=until(lambda:archived(hash_),30,'settlement ExEx archive')
        for i in range(1,4):
            until(lambda i=i: (ROOT/f'chain/node-{i}/exex'/name).exists(),60,'peer ExEx archive')
            assert json.loads((ROOT/f'chain/node-{i}/exex'/name).read_text())==event
        (EVIDENCE/evidence_name).write_text(json.dumps(event,indent=2))
        step('canonical ExEx settlement identical on four validators',epoch=event['cursor']['epoch'],settlement_hash=hash_)
    stop(0);before=epoch(1);until(lambda:epoch(1)>=before+2,90,'quorum during VPN node restart');start(0)
    until(lambda:epoch()>=epoch(1),120,'restarted native Pinned node catches up')
    assert int(view(program,'get_session_status',[session]))==1 and int(view(program,'get_session_status',[tun['session']]))==1 and int(view(program,'get_earnings_total',[circle]))==earnings
    step('native node restart retains settled state and keys',epoch=epoch())
    for i in list(PROCESSES):stop(i)
    JOURNAL['qualified']=True;save();print('NATIVE_PAID_VPN_GATE_PASS',flush=True)

if __name__=='__main__':
    try:main()
    except Exception:
        if EVIDENCE.exists():
            JOURNAL['failure']=traceback.format_exc();save()
        traceback.print_exc()
        for process in PROCESSES.values():
            if process.poll() is None:process.terminate()
        for process in PROCESSES.values():
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        raise SystemExit(1)
