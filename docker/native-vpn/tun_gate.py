"""Real VPN TUNs and kernel NAT to a second network-disabled target kernel."""
import ipaddress,json,os,pathlib,re,signal,socket,struct,subprocess
from packet_target import Hop
from json_snapshot import read_object

CLIENT='vpn-client'
SERVER='vpn-node'
NODE_LINK='vpn-egress'
SNAT='192.0.2.1'

def run(g,*,operator_config,descriptor_path,program,circle,client_config,config,epoch_peer=1):
    hop=Hop(pathlib.Path('/hop'),public=g.PUBLIC,role='node',name=NODE_LINK)
    try:
        return _run(g,hop,operator_config,descriptor_path,program,circle,client_config,config,epoch_peer)
    finally:
        hop.close()

def _run(g,hop,operator_config,descriptor_path,program,circle,client_config,config,epoch_peer):
    command=g.command
    def ip(*args):return command(['ip',*args])
    def target():
        return read_object(g.EVIDENCE/'target.json')
    assert open('/proc/sys/net/ipv4/ip_forward').read().strip()=='1'
    assert open('/proc/sys/net/ipv4/conf/all/rp_filter').read().strip()=='0'
    ip('address','del',g.PUBLIC+'/32','dev','lo')
    # The target lives in its own kernel. The bounded Unix packet hop only
    # replaces the physical egress link; all TCP, NAT and routing remain real.
    ip('link','set',NODE_LINK,'mtu','1280')
    # Decrypted returns must reach the server TUN before the client's local
    # address entry, since these two test VPN endpoints share this namespace.
    ip('rule','del','priority','0')
    ip('rule','add','priority','2000','lookup','local')
    ip('route','add',g.PUBLIC+'/32','via','192.0.2.2','dev',NODE_LINK)
    command(['iptables','-t','nat','-A','POSTROUTING','-s','198.18.0.0/15','-d',g.PUBLIC+'/32','-o',NODE_LINK,'-j','SNAT','--to-source',SNAT])

    # Capability is committed before this new session opens escrow. The native
    # node is then restarted with the matching actual kernel TUN configuration.
    operator_config.write_text(operator_config.read_text()+f'\n[tun.ip_tunnel]\nname = "{SERVER}"\n')
    command(['octravpn-node','--config',operator_config,'circle','bootstrap','--circle',circle,'--native-identity',descriptor_path,'--force','--commit'],180)
    prior_epoch=g.epoch()
    g.stop(0);config['vpn']['ip_tunnel']={'name':SERVER}
    (g.ROOT/'chain/node-0/config.json').write_text(json.dumps(config));g.start(0)
    g.until(lambda:g.epoch() >= (g.epoch(epoch_peer) if epoch_peer is not None else prior_epoch),
            120,'native IP tunnel restart synchronized')
    g.until(lambda:SERVER in ip('-j','link','show'),30,'actual native server TUN')
    ip('route','add','198.18.0.0/15','dev',SERVER,'table','402')
    ip('rule','add','priority','5','iif',NODE_LINK,'to','198.18.0.0/15','lookup','402')

    logfile=g.EVIDENCE/'client-tun.log';stream=logfile.open('w')
    process=subprocess.Popen(['octravpn','--config',str(client_config),'connect-v3','--tun-name',CLIENT],stdout=stream,stderr=subprocess.STDOUT,cwd=g.ROOT,env={**os.environ,'RUST_LOG':'info'})
    g.PROCESSES['tun-client']=process;g.FILES['tun-client']=stream
    try:
        g.until(lambda:'authenticated IPv4 tunnel ready' in logfile.read_text(),120,'actual authenticated client TUN')
        sid=int(re.search(r'v3 session opened: id=(\d+)',logfile.read_text()).group(1))
        addresses=json.loads(ip('-j','address','show','dev',CLIENT))[0]['addr_info']
        assigned=[item['local'] for item in addresses if item['family']=='inet'];assert len(assigned)==1
        assigned=assigned[0];assert ipaddress.ip_address(assigned) in ipaddress.ip_network('198.18.0.0/15')
        assert assigned!='198.18.0.1'
        ip('route','add',g.PUBLIC+'/32','dev',CLIENT,'src',assigned,'table','401')
        ip('rule','add','priority','10','iif','lo','to',g.PUBLIC+'/32','lookup','401')
        # Both simulated hosts share this namespace. Keep the local encrypted
        # leg out of conntrack so it cannot pre-confirm the server's identical
        # inner5tuple before the actual server-side SNAT hook sees that flow.
        command(['iptables','-t','raw','-A','OUTPUT','-o',CLIENT,'-s',assigned+'/32','-d',g.PUBLIC+'/32','-j','NOTRACK'])
        command(['iptables','-t','raw','-A','PREROUTING','-i',CLIENT,'-s',g.PUBLIC+'/32','-d',assigned+'/32','-j','NOTRACK'])
        route=json.loads(ip('-j','route','get',g.PUBLIC,'from',assigned,'iif','lo'))[0]
        assert route['dev']==CLIENT,'application route bypassed client TUN'

        local=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);local.bind((assigned,0));local.settimeout(3)
        udp_bytes=0
        for index in range(1000):
            payload=struct.pack('!I',index)+b'real-os-tun-udp'*70
            local.sendto(payload,(g.PUBLIC,20001));data,peer=local.recvfrom(2048)
            assert data==payload and peer==(g.PUBLIC,20001);udp_bytes+=len(data)
        local.close()
        tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM);tcp.bind((assigned,0));tcp.settimeout(5)
        tcp.connect((g.PUBLIC,20003));tcp_bytes=0
        for index in range(64):
            payload=struct.pack('!I',index)+b'real-os-tun-tcp'*70;tcp.sendall(payload)
            response=b''
            while len(response)<len(payload):
                data=tcp.recv(len(payload)-len(response));assert data,'TCP echo closed early';response+=data
            assert response==payload;tcp_bytes+=len(response)
        # Linux ping socket emits a real kernel IPv4 ICMP packet with the TUN
        # source address; the kernel target replies through conntrack/NAT.
        ping=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_ICMP)
        ping.bind((assigned,0));ping.settimeout(5)
        payload=b'real-os-tun-icmp';message=bytearray(struct.pack('!BBHHH',8,0,0,7,1)+payload)
        if len(message)%2:message.append(0)
        checksum=sum(struct.unpack('!'+str(len(message)//2)+'H',message))
        while checksum>>16:checksum=(checksum&65535)+(checksum>>16)
        struct.pack_into('!H',message,2,(~checksum)&65535)
        ping.sendto(message,(g.PUBLIC,0));response,peer=ping.recvfrom(2048);ping.close()
        assert response[0]==0 and response[8:8+len(payload)]==payload and peer[0]==g.PUBLIC
        def restore_route():
            g.until(lambda:SERVER in ip('-j','link','show'),60,'restarted native server TUN')
            ip('route','replace','198.18.0.0/15','dev',SERVER,'table','402')
        g.recover_active(program,sid,logfile,restore_route)
        # Keep the actual TCP socket and both endpoint kernels alive while the
        # VPN operator process restarts; no replacement TCP connection is used.
        for index in range(8):
            payload=struct.pack('!I',index)+b'real-tcp-on-original-socket-after-restart';tcp.sendall(payload)
            response=b''
            while len(response)<len(payload):
                data=tcp.recv(len(payload)-len(response));assert data,'original TCP connection failed recovery';response+=data
            assert response==payload;tcp_bytes+=len(response)
        tcp.close()
        addresses_after=json.loads(ip('-j','address','show','dev',CLIENT))[0]['addr_info']
        assert [item['local'] for item in addresses_after if item['family']=='inet']==[assigned]
        local=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);local.bind((assigned,0));local.settimeout(5)
        for index in range(16):
            payload=struct.pack('!I',index)+b'real-tun-after-operator-restart'
            local.sendto(payload,(g.PUBLIC,20001));data,peer=local.recvfrom(2048)
            assert data==payload and peer==(g.PUBLIC,20001);udp_bytes+=len(data)
        local.close()
        rules=command(['iptables','-t','nat','-L','POSTROUTING','-v','-n','-x'])
        links={name:json.loads(ip('-j','-s','link','show','dev',name))[0] for name in [CLIENT,SERVER]}
        def completed_target():
            value=target()
            return value if value.get('udp_payload_bytes',0)>=udp_bytes and value.get('tcp_payload_bytes',0)>=tcp_bytes else None
        observed=g.until(completed_target,5,'separate target kernel packet evidence')
        seen=observed['observed_sources']
        evidence={'session':sid,'assigned':assigned,'target':g.PUBLIC,'udp_payload_bytes':udp_bytes,'tcp_payload_bytes':tcp_bytes,'icmp_echo':True,'target_observed_sources':seen,'target_kernel':observed,'packet_hop':hop.metrics(),'nat_rules':rules,'raw_rules':command(['iptables','-t','raw','-L','-v','-n','-x']),'application_route':route,'rules':json.loads(ip('-j','rule','show')),'tun_links':links}
        (g.EVIDENCE/'tun-network.json').write_text(json.dumps(evidence,indent=2))
        assert set(seen)=={'udp','tcp'} and all(set(sources)=={SNAT} for sources in seen.values()),evidence
        assert not observed.get('errors'),observed
        for bridge in [evidence['packet_hop'],observed['hop']]:
            assert not bridge['errors'] and bridge['rejected_packets']==0,bridge
            assert bridge['sent_packets']>0 and bridge['received_packets']>0,bridge
        assert 'SNAT' in rules and SNAT in rules and any('SNAT' in line and int(line.split()[0])>0 for line in rules.splitlines())
        for link in links.values():
            stats=link.get('stats64',link.get('stats'))
            assert stats and stats['rx']['packets']>0 and stats['tx']['packets']>0,'real TUN packet counters missing'
        g.step('real client and native OS TUN kernel NAT TCP UDP ICMP return',**evidence)
    except Exception as error:
        diagnostic={'error':repr(error),'target_kernel':target(),'packet_hop':hop.metrics(),'nat_rules':command(['iptables','-t','nat','-L','POSTROUTING','-v','-n','-x']),'raw_rules':command(['iptables','-t','raw','-L','-v','-n','-x']),'links':json.loads(ip('-j','-s','link','show')),'rules':json.loads(ip('-j','rule','show'))}
        (g.EVIDENCE/'tun-failure.json').write_text(json.dumps(diagnostic,indent=2));raise
    process.send_signal(signal.SIGINT);process.wait(timeout=180);stream.close()
    g.PROCESSES.pop('tun-client');g.FILES.pop('tun-client')
    assert process.returncode==0,'TUN client settlement failed: '+logfile.read_text()[-5000:]
    assert int(g.view(program,'get_session_status',[sid]))==1
    matches=re.findall(r'v3 settlement submitted: id=\d+ net=(\d+) bytes_used=(\d+) hash=([0-9a-f]{64})',logfile.read_text());assert len(matches)==1
    net,byte_count,settlement=matches[0]
    assert int(net)>0 and int(byte_count)>=2*(udp_bytes+tcp_bytes)
    assert int(g.view(program,'get_claim_net',[sid]))==int(net)
    g.step('actual OS TUN receipt and exact on-chain amount settled',session=sid,net=int(net),receipt_bytes=int(byte_count),settlement_hash=settlement,receipt=g.receipt(settlement))
    return {'session':sid,'settlement':settlement,'net':int(net)}
