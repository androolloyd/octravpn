#!/usr/bin/env python3
"""Separate genuine private Single paid gate; the four-validator gate is unchanged.
All applications/proofs/escrows are ordinary signed native RPC transactions.
"""
import qualify as shared
from qualify import *
JOURNAL['scope']='isolated explicitly activated private Single genesis; signed local history, no BFT QC/public-network qualification'
def start(index):
    assert index==0,'Single gate has exactly one producer'
    path=ROOT/'chain/node-0'
    config=json.loads((path/'single-base.json').read_text())
    adapter=json.loads((path/'config.json').read_text())
    assert config['chain']==adapter['genesis']['chain']
    assert config['execution']['activated_applications'] is True
    services={'browser':'127.0.0.1:19872','gateway':adapter['gateway']}
    if adapter.get('vpn') is not None:
        services['vpn']={'control':'127.0.0.1:19873','tunnel':'127.0.0.1:19874','settlement':adapter['vpn']}
    config['services']=services
    target=path/'single.json';target.write_text(json.dumps(config));target.chmod(0o600)
    stream=(EVIDENCE/'node-0.log').open('a')
    process=subprocess.Popen(['octra-node','run-single','--config',str(target)],stdout=stream,stderr=subprocess.STDOUT,cwd=ROOT,env={**os.environ,'RUST_LOG':'info'})
    PROCESSES[index]=process;FILES[index]=stream
shared.start=start
# The controlled initializer writes private fixture keys only below /tmp, never
# evidence or source. Its ignored test is an actual executable input to this gate.
os.environ['OCTRA_SINGLE_FIXTURE_DIRECTORY']=str(ROOT/'chain')

def main():
    native_guard();ROOT.mkdir(mode=0o700);EVIDENCE.chmod(0o700)
    shutil.copyfile('/usr/local/share/native-source.json',EVIDENCE/'source.json');save()
    command(['octravpn-private-admin','setup','--development','--out',ROOT/'setup'],300)
    setup=json.loads((ROOT/'setup/manifest.json').read_text());assert setup['development_only'] and not setup['production_ready']
    owner,commitment=credential('owner');next_owner,next_commitment=credential('next-owner');rotated,rotated_commitment=credential('rotated')
    command(['octra-single-fixture','--ignored','--exact','facade::initialize_private_single_paid_fixture'],120)
    configs=[json.loads((ROOT/'chain'/f'node-{i}'/'config.json').read_text()) for i in range(1)]
    for i,cfg in enumerate(configs):
        assert cfg['genesis']['activated_applications'] is True
        cfg['gateway']={'listen':f'127.0.0.1:{BASE+i*10+5}','origin':'https://circles.example.ts.net'}
        (ROOT/'chain'/f'node-{i}'/'config.json').write_text(json.dumps(cfg))
    JOURNAL['genesis']=configs[0]['genesis'];save()
    faucet=secret_hex(ROOT/'chain/faucet.key','faucet.hex')
    operator=secret_hex(ROOT/'chain/node-0/validator.key','operator.hex')
    operator_addr=command(['octra','cast','wallet','addr','--key',operator])
    for i in range(1):start(i)
    for i in range(1):until(lambda i=i:epoch(i)>=2,120,f'validator {i} finalized')
    step('real private Single producer committed signed local epochs',epoch=epoch())
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
    restart_epoch=epoch();stop(0)
    config=configs[0];config['vpn']={'chain':config['genesis']['chain']['chain_id'],'receipt_chain_id':RECEIPT_CHAIN,'application':'program','program':program,'code_hash':code_hash,'operator_circle':circle,'layout':'source'}
    (ROOT/'chain/node-0/config.json').write_text(json.dumps(config));start(0)
    until(lambda:epoch()>=restart_epoch,120,'private Single VPN restart retains canonical prefix')
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
    for index in range(1500):
        if client.poll() is not None:raise RuntimeError('real client exited before forwarding: '+client_log.read_text()[-3000:])
        payload=index.to_bytes(4,'big')+b'paid-native-vpn'*80
        local.sendto(payload,('127.0.0.1',20002))
        try:
            data,_=local.recvfrom(2048)
            if data==payload:received+=len(data)
        except socket.timeout:
            if received:
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
    tun=tun_gate.run(sys.modules[__name__],operator_config=operator_config,descriptor_path=descriptor_path,program=program,circle=circle,client_config=client_config,config=config,epoch_peer=None)
    earnings=int(view(program,'get_earnings_total',[circle]))
    body,headers=until(lambda:get(f'http://127.0.0.1:19875/circles/{circle}/index.html','circles.example.ts.net'),30,'committed HTTPS gateway backend')
    assert b'canonical paid VPN gateway' in body
    assert headers.get('x-octra-chain')==config['genesis']['chain']['chain_id']
    step('gateway reads canonical application asset',body_sha256=hashlib.sha256(body).hexdigest(),headers=headers)
    def archived(hash_):
        for path in (ROOT/'chain/node-0/data/single-archive').glob('*.json'):
            event=json.loads(path.read_text())
            if any(tx.get('hash')==hash_ for tx in event.get('events',[])):return path.name,event
    for hash_,evidence_name in [(settle_hash,'settlement-exex.json'),(tun['settlement'],'tun-settlement-exex.json')]:
        name,event=until(lambda:archived(hash_),30,'settlement ExEx archive')
        (EVIDENCE/evidence_name).write_text(json.dumps(event,indent=2))
        step('actual private Single canonical ExEx settlement',epoch=event['cursor']['epoch'],settlement_hash=hash_)
    before=epoch();stop(0);start(0)
    until(lambda:epoch()>=before,120,'private Single restart retains committed local prefix')
    assert int(view(program,'get_session_status',[session]))==1 and int(view(program,'get_session_status',[tun['session']]))==1 and int(view(program,'get_earnings_total',[circle]))==earnings
    step('native node restart retains settled state and keys',epoch=epoch())
    for i in list(PROCESSES):stop(i)
    JOURNAL['qualified']=True;save();print('PRIVATE_SINGLE_PAID_VPN_GATE_PASS',flush=True)
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
