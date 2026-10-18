#!/usr/bin/env python3
"""Three real paid operators; move retained validators1/2 into distinct kernels.

The fourth validator remains with entry0. Opaque links preserve native signed
consensus bytes, keys, canonical stores, WAL/floors and all four ExEx sinks.
"""
import argparse,base64,hashlib,json,pathlib,shutil,subprocess,traceback
import payments_qualify as p
import qualify as g
from packet_target import Hop
from payment_control import ControlProxy
from stock_operator import atomic,internal_guard
from base_multi_fixture import A as BaseA,ready

ROLES=['A','B','C']; IPS=['93.184.216.11','93.184.216.21','93.184.216.31']
UNDERLAY=['172.31.237.2','172.31.237.4','172.31.237.5']; NAMES=['hop-entry','hop-middle','hop-exit']
PORTS=[19874,19884,19894]; CONTROLS=[19879,19889,19899]

def links(index):
    mapping=[]
    # Every original loopback peer socket reaches the exact same remote key.
    # Entry owns native0 and3; native1/2 are stopped+relocated, never duplicated.
    for peer in range(4):
        owner=peer if peer<3 else 0; port=19870+peer*10
        if owner!=index:
            mapping.append({'listen':['127.0.0.1',port],'target':[UNDERLAY[owner],port+1000]})
        elif peer==index or peer==3:
            mapping.append({'listen':[UNDERLAY[index],port+1000],'target':['127.0.0.1',port]})
    mapping.append({'listen':[UNDERLAY[index],CONTROLS[index]+1000],
                    'target':['127.0.0.1',CONTROLS[index]]})
    if index==0:
        for peer in range(3):
            mapping.append({'listen':[IPS[0],CONTROLS[peer]+1000],
                            'target':[UNDERLAY[peer],CONTROLS[peer]+1000]})
    path=g.ROOT/f'links-{ROLES[index]}.json';path.write_text(json.dumps(mapping))
    logfile=g.EVIDENCE/f'links-{ROLES[index]}.log';stream=logfile.open('x')
    process=subprocess.Popen(['python3','-u','/usr/local/bin/multi_link.py',str(path)],stdout=stream,stderr=stream)
    g.until(lambda:'"ready": true' in logfile.read_text(),20,'opaque three-hop native links')
    return process,stream,mapping

def carrier(index):
    p.ip('route','replace',IPS[index+1]+'/32','via',UNDERLAY[index+1],'dev','eth0')
    g.command(['iptables','-t','nat','-A','POSTROUTING','-s','198.18.0.0/15','-d',IPS[index+1]+'/32',
        '-p','udp','--dport',str(PORTS[index+1]),'-o','eth0','-j','SNAT','--to-source',UNDERLAY[index]])
    g.command(['iptables','-A','FORWARD','-i',NAMES[index],'-d',IPS[index+1]+'/32','-p','udp',
        '--dport',str(PORTS[index+1]),'-j','ACCEPT'])
    g.command(['iptables','-A','FORWARD','-i',NAMES[index],'-j','DROP'])

def ingress(index):
    p.ip('address','add',IPS[index]+'/32','dev','lo')
    g.command(['iptables','-t','nat','-A','PREROUTING','-i','eth0','-d',IPS[index]+'/32','-p','udp',
        '--dport',str(PORTS[index]),'-j','DNAT','--to-destination',f'127.0.0.1:{PORTS[index]}'])

class A(BaseA):
    def __init__(self):
        self.fixture=p.prepare(internal_guard,custody_cap=600_000_000)
        self.program=self.fixture['program'];self.faucet=self.fixture['faucet'];self.circle=self.fixture['circle']
        g.JOURNAL['scope']='Three-operator Program custody, original four native validators and three real kernel tunnels; no public/mainnet claim'
        self.operator_keys=[self.fixture['operator_key']];self.operators=[self.fixture['operator']]
        self.payer_keys=[self.faucet]
        domain=self.fixture['application']['domain']
        for index in [1,2]:
            operator_key=g.secret_hex(g.ROOT/f'chain/node-{index}/validator.key',f'operator-{ROLES[index]}.hex')
            operator=g.command(['octra','cast','wallet','addr','--key',operator_key]);self.operator_keys.append(operator_key);self.operators.append(operator)
            payer_key=g.ROOT/f'payer-{ROLES[index]}.hex';payer=g.cli('cast','wallet','new','--out',payer_key)['address'];self.payer_keys.append(payer_key)
            for label,address,amount in [('operator',operator,300_000_000),('payer',payer,30_000_000)]:
                g.record('fund separate '+ROLES[index]+' '+label,g.cli('cast','transfer',address,amount,'--key',self.faucet,'--rpc-url',g.RPC,'--ou',1000),vm=False)
            g.send('bond separate '+ROLES[index]+' stake',operator_key,self.program,'bond_operator',[],p.STAKE)
            message=f'Octranet register v1|{domain}|{self.program}|{payer}|1'
            signature=g.command(['octra','cast','wallet','sign','--key',payer_key,message])
            public=g.command(['octra','cast','wallet','pubkey','--key',payer_key])
            g.send('register independent '+ROLES[index]+' receipt key',payer_key,self.program,'register',[public,signature])
            g.send('fund separate '+ROLES[index]+' payer',payer_key,self.program,'fund',[payer],p.FUND)
        self.plans=[];self.withdrawn=[0,0,0]
        for index in range(3):
            if index<2:
                tariff={'version':1,'operator':self.operators[index],
                    'classes':[{'name':'default','rate_ou_per_mib':1000},{'name':'encrypted-carrier','rate_ou_per_mib':2000}],
                    'selectors':[{'prefix':{'network':IPS[index+1],'prefix_len':32},'protocol':'udp','port':PORTS[index+1],'traffic_class':1}]}
                caps=[0,65_536 if index==1 else 1_048_576]
            else:
                tariff={**self.fixture['tariff'],'operator':self.operators[index]};caps=[131_072,1_048_576,4096]
            self.plans.append(self.offer(tariff,self.operator_keys[index],self.payer_keys[index],self.operators[index],caps,
                                         CONTROLS[index],IPS[index],PORTS[index]))
        assert len({plan['binding']['payer'] for plan in self.plans})==3
        configs=self.fixture['configs']
        for index in range(3):
            configs[index]['payments']={'application':{**self.fixture['application'],'offer':self.plans[index]['binding']['offer']},
                'ip_tunnel':{'name':NAMES[index]},'max_claim_fees_ou':100_000}
        minimum=g.epoch();self.minimum=minimum
        for index in [2,1,0]:g.stop(index)
        continuity={str(index):self.continuity(index) for index in [1,2]}
        for index in range(3):(g.ROOT/f'chain/node-{index}/config.json').write_text(json.dumps(configs[index]))
        ingress(0);carrier(0);self.control=ControlProxy();self.link,self.link_stream,mapping=links(0)
        g.start(0)  # Both relocated peers must join before source-attested serving.
        for index,key in enumerate(self.payer_keys):
            path=pathlib.Path('/commands')/f'receipt-{ROLES[index]}.hex';shutil.copyfile(key,path);path.chmod(0o600)
        atomic(g.EVIDENCE/'triple-ready.json',{'program':self.program,'plans':self.plans,'minimum_epoch':minimum,
            'stopped_continuity':continuity,'opaque_links_A':mapping,
            'management_exceptions':{'controls':[f'127.0.0.1:{x}' for x in CONTROLS],
                'physical_entry_ip':IPS[0],'scope':'explicit destination-IP exceptions, not per-socket isolation'}})

    def command(self,request):
        action=request['action']
        if action=='ready':ready(0,NAMES[0],self.minimum);return {'serving':True}
        if action=='revoke':
            index=request['hop'];plan=self.plans[index]
            g.send('canonical independent hop withdrawal',self.payer_keys[index],self.program,'withdraw_channel',[1]);self.withdrawn[index]+=1
            assert g.view(self.program,'can_forward',[plan['binding']['plan']]) is False
            return self.state()
        if action=='reset':
            for index,key in enumerate(self.payer_keys):
                plan=self.plans[index]
                g.send('explicit new generation before new three-hop consent',key,self.program,'withdraw_channel',[1]);self.withdrawn[index]+=1
                opened=g.send('explicit replacement plan, never automatic topup',key,self.program,'open_plan',[plan['binding']['offer'],p.BUDGET])
                plan['binding']['plan']=int(next(row['values'][0] for row in opened['events'] if row['event']=='PlanOpened'))
                plan['binding']['generation']=int(g.view(self.program,'get_generation',[plan['binding']['payer']]))
            return {'plans':self.plans}
        if action=='claims':
            charges=[0,0,0];counts=[0,0,0]
            for path in sorted((g.ROOT/'chain/node-0/exex').glob('*.json')):
                event=json.loads(path.read_text())
                for tx in event.get('events',[]):
                    envelope=json.loads(base64.b64decode(tx['transaction'],validate=True))
                    if envelope.get('to_')!=self.program or envelope.get('encrypted_data')!='claim':continue
                    receipt=json.loads(base64.b64decode(tx['receipt'],validate=True))
                    assert receipt['success'] is True and receipt['contract']==self.program and receipt['error'] is None
                    assert tx['proof']=='exact' and hashlib.sha256(base64.b64decode(tx['identity'],validate=True)).hexdigest()==tx['hash']
                    index=self.operators.index(envelope['from']);counts[index]+=1
                    for row in receipt['events']:
                        if row['event']=='UsageCharged':charges[index]+=int(row['values'][4])
                    for peer in range(1,4):
                        saved=g.ROOT/f'chain/node-{peer}/exex'/path.name
                        g.until(saved.exists,60,'four retained native ExEx agree');assert json.loads(saved.read_text())==event
            assert all(counts)
            for index,operator in enumerate(self.operators):
                assert charges[index]==int(g.view(self.program,'get_earnings',[operator]))>0
                assert int(g.view(self.program,'get_funds',[self.plans[index]['binding']['payer']]))+charges[index]+self.withdrawn[index]==p.FUND
            assert int(g.view(self.program,'get_locked_value'))==3*p.STAKE+3*p.FUND-sum(self.withdrawn)
            return {'per_operator_claims':counts,'per_operator_earnings':charges,'payer_withdrawals':self.withdrawn}
        return super().command(request)

class Peer:
    def __init__(self,index):
        self.index=index;value=json.loads((g.EVIDENCE/'triple-ready.json').read_text())
        assert BaseA.continuity(self,index)==value['stopped_continuity'][str(index)]
        self.link,self.link_stream,mapping=links(index);ingress(index)
        self.control=ControlProxy(port=CONTROLS[index],upstream_port=19873+10*index)
        g.start(index);ready(index,NAMES[index],value['minimum_epoch'])
        self.hop=None
        if index<2:carrier(index)
        else:
            self.hop=Hop(pathlib.Path('/hop'),role='node',name=p.LINK)
            p.ip('route','replace',g.PUBLIC+'/32','via','192.0.2.2','dev',p.LINK)
            g.command(['iptables','-t','nat','-A','POSTROUTING','-s','198.18.0.0/15','-d',g.PUBLIC+'/32','-o',p.LINK,'-j','SNAT','--to-source',p.SNAT])
            p.ip('rule','add','priority','5','iif',p.LINK,'to','198.18.0.0/15','lookup','402')
        atomic(g.EVIDENCE/f'triple-{ROLES[index]}-ready.json',{'retained_state_verified':True,'opaque_links':mapping})
    def command(self,request):
        action=request['action']
        if action=='release':self.control.release();return {'released':True}
        if action=='hold_status':
            self.control.hold_status();g.until(lambda:self.control.metrics()['status_waiting']>=1,20,'real status held');return {'held':True}
        if action=='release_status':self.control.release_status();return {'released':True}
        if action=='restart':
            before=g.epoch(self.index);process=g.PROCESSES.pop(self.index);process.kill();process.wait(timeout=15);g.FILES.pop(self.index).close()
            g.start(self.index);ready(self.index,NAMES[self.index],before);return {'epoch':g.epoch(self.index)}
        if action=='state':return {'nat':g.command(['iptables','-t','nat','-L','-v','-n','-x'])}
        if action=='stop':return {'stopped':True}
        raise ValueError('unknown fixed three-hop peer action')
    def close(self):
        self.control.close()
        if self.hop:self.hop.close()
        self.link.terminate();self.link.wait(timeout=15);self.link_stream.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--role',choices=ROLES,required=True);args=parser.parse_args()
    g.ROOT=pathlib.Path('/state/native-vpn');fixture=None
    try:
        fixture=A() if args.role=='A' else Peer(ROLES.index(args.role))
        directory=pathlib.Path('/commands')/args.role;index=1
        while True:
            path=directory/f'{index}.json';g.until(path.exists,300,'three-hop native fixture command');request=json.loads(path.read_text())
            try:atomic(directory/f'{index}.result.json',{'ok':fixture.command(request)})
            except BaseException:atomic(directory/f'{index}.result.json',{'error':traceback.format_exc()});raise
            index+=1
            if request['action']=='stop':break
    finally:
        if fixture:fixture.close()
        for index in list(g.PROCESSES):g.stop(index)
if __name__=='__main__':main()
