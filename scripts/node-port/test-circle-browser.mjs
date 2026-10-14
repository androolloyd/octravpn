#!/usr/bin/env node
// Real Chromium navigation against immutable canonical-state test fixtures.
import {spawn,execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';
const temp=await mkdtemp(join(tmpdir(),'octra-browser-'));
const report=join(temp,'fixture.json');
let server,chrome,socket;
let diagnostics='';
const pending=new Map();const contexts=new Map();let serial=0;
async function until(fn,label,milliseconds=30000) {
  const deadline=Date.now()+milliseconds;let last;
  while(Date.now()<deadline) {
    try {const value=await fn();if(value)return value;}catch(error){last=error;}
    if(server?.exitCode!==null && server?.exitCode!==undefined)throw new Error(`Fixture exited: ${server.exitCode}\n${diagnostics}`);
    await delay(100);
  }
  throw new Error(`Timeout: ${label}${last?`: ${last.message}`:''}\n${diagnostics.slice(-4000)}`);
}
function call(method,params={},sessionId) {
  return new Promise((resolve,reject)=>{
    const id=++serial;const timeout=setTimeout(()=>{pending.delete(id);reject(new Error(`CDP timeout: ${method}`));},10000);
    pending.set(id,{resolve,reject,timeout});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
}
async function stop(child) {
  if(!child||child.exitCode!==null)return;
  const exited=new Promise(resolve=>child.once('exit',resolve));
  try{process.kill(-child.pid,'SIGTERM');}catch{child.kill('SIGTERM');}
  await Promise.race([exited,delay(3000)]);
  if(child.exitCode===null){try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}await exited;}
}
try {
  const sourcePaths=['Cargo.lock','crates/octra-node-protocol/Cargo.toml','crates/octra-node-protocol/src/circles.rs','crates/octra-node-protocol/src/native_base64.rs','crates/octra-node-protocol/src/transaction.rs','crates/octra-node-runtime/src/circle_assets.rs','crates/octra-node-runtime/src/canonical.rs','crates/octra-node-runtime/src/state_batch.rs','crates/octra-node-runtime/tests/canonical_assets.rs','crates/octra-node-runtime/tests/common/browser_host.rs','crates/octra-browser/src/lib.rs','crates/octra-browser/src/http.rs','crates/octra-browser/src/render.rs','crates/octra-browser/src/url.rs','crates/octra-browser/src/shell.js','crates/octra-browser/src/sdk.js','crates/octra-browser/src/application.rs','crates/octra-browser/src/bridge.rs','scripts/node-port/test-circle-browser.mjs'];
  sourcePaths.push('crates/octra-node-runtime/Cargo.toml','crates/octra-node-runtime/src/circle.rs','crates/octra-node-runtime/src/circle_application.rs','crates/octra-node-runtime/src/circle_store.rs','crates/octra-node-runtime/src/circle_reads.rs','crates/octra-node-protocol/src/circle_wasm/public_read.rs','crates/octra-node-runtime/tests/common/circle_host.rs','crates/octra-node-runtime/tests/fixtures/circle-view.json');
  sourcePaths.push('crates/octra-node-protocol/src/circle_storage.rs','crates/octra-node-protocol/src/circle_wasm/mod.rs','crates/octra-node-protocol/src/circle_wasm/codec.rs','crates/octra-node-protocol/src/circle_wasm/receipt.rs','crates/octra-node-protocol/src/circle_wasm/transcript.rs');
  sourcePaths.push('crates/octra-node-runtime/src/finality.rs','crates/octra-node-runtime/tests/common/finality_host.rs','crates/octra-node-protocol/src/transaction_outcome.rs','crates/octra-node-protocol/src/native_json.rs');
  sourcePaths.push('crates/octra-node-protocol/src/preverify_commit.rs','crates/octra-node-protocol/src/preverify_receipt.rs','crates/octra-node-protocol/src/circle_wasm/transcript.rs');
  sourcePaths.push('crates/octra-node-runtime/src/browser_wallet.rs','crates/octra-node-runtime/src/browser_wallet_tests.rs','crates/octra-node-runtime/src/admission.rs','crates/octra-node-runtime/src/crypto_payload.rs','crates/octra-node-runtime/src/circle_call.rs','crates/octra-node-runtime/src/circle_transaction.rs','crates/octra-node-runtime/src/circle_receipt.rs','crates/octra-node-runtime/src/execution.rs','crates/octra-node-runtime/src/account_store.rs','crates/octra-node-protocol/src/state.rs','crates/octra-node-protocol/src/transaction_policy.rs','crates/octra-node-protocol/src/transaction_payload.rs');
  sourcePaths.push('crates/octra-node-runtime/src/epoch_footer.rs','crates/octra-node-protocol/src/epoch_rewards.rs','crates/octra-node-protocol/src/emission.rs');
  sourcePaths.push('crates/octra-node-runtime/src/epoch_execution.rs','crates/octra-node-runtime/src/preverify_state.rs','crates/octra-node-runtime/src/validator_epoch/mod.rs','crates/octra-node-runtime/src/validator_epoch/context.rs','crates/octra-node-runtime/src/validator_epoch/advance.rs');
  sourcePaths.push('crates/octra-node-runtime/src/circle_view.rs','crates/octra-node-runtime/src/canonical/reader.rs','crates/octra-node-runtime/src/finality/history.rs','crates/octra-node-protocol/src/rules.rs');
  sourcePaths.push('crates/octra-node-protocol/src/resource_lanes.rs','crates/octra-node-runtime/src/staging/mod.rs','crates/octra-node-runtime/src/staging/index.rs','crates/octra-node-runtime/src/staging/preview.rs','crates/octra-node-runtime/src/staging/intake.rs');
  sourcePaths.push('crates/octra-node-runtime/src/circle.rs','crates/octra-node-runtime/src/circle_code.rs','crates/octra-node-runtime/src/circle_journal.rs','crates/octra-node-runtime/src/circle_effects.rs','crates/octra-node-protocol/src/circle_program.rs','vendor/octra-circle-wasm-host/src/rust_api.rs','vendor/octra-circle-wasm-host/src/call_step.rs');
  sourcePaths.push('crates/octra-node-runtime/src/circle_query.rs','crates/octra-node-runtime/src/circle_octb.rs','crates/octra-node-runtime/src/circle_call/octb.rs','crates/octra-node-runtime/src/octb/mod.rs','crates/octra-node-runtime/src/octb/value.rs','crates/octra-node-runtime/src/octb/data.rs','crates/octra-node-runtime/src/octb/meter.rs','crates/octra-node-runtime/src/octb/spawn.rs','crates/octra-node-runtime/tests/fixtures/circle-octb-view.json');
  const startedSource=Object.fromEntries(await Promise.all(sourcePaths.map(async path=>[path,createHash('sha256').update(await readFile(path)).digest('hex')])));
  let nativeSite, nativeEvidence;
  if (process.argv[3]) {
    const upstream=resolve(process.argv[3]);
    const {commit}=JSON.parse(await readFile('docs/rust-node/upstream.json','utf8'));
    const site={},source_sha256={};
    for(const name of ['index.html','app.js','style.css']) {
      const path=`contracts/examples/rust_circle_counter/site/${name}`;
      const bytes=execFileSync('git',['-C',upstream,'show',`${commit}:${path}`]);
      site[name]=bytes.toString('base64');source_sha256[path]=createHash('sha256').update(bytes).digest('hex');
    }
    nativeSite=join(temp,'native-site.json');await writeFile(nativeSite,JSON.stringify(site));
    const execution=JSON.parse(await readFile('crates/octra-node-runtime/tests/fixtures/circle-view.json','utf8'));
    assert.equal(execution.upstream_commit,commit);
    nativeEvidence={commit,source_sha256,wasm_sha256:execution.wasm_sha256,guest_source_sha256:execution.guest_source_sha256};
  }
  server=spawn('cargo',['test','--offline','--locked','-p','octra-node-runtime','--test','canonical_assets','--','browser_fixture','--ignored','--nocapture'],{env:{...process.env,OCTRA_BROWSER_FIXTURE_FILE:report,...(nativeSite?{OCTRA_BROWSER_NATIVE_SITE_FILE:nativeSite}:{})},detached:true,stdio:['ignore','pipe','pipe']});
  for(const stream of [server.stdout,server.stderr])stream.on('data',chunk=>{diagnostics+=chunk.toString();});
  const fixture=await until(async()=>JSON.parse(await readFile(report,'utf8')),'canonical fixture ready',120000);
  chrome=spawn(process.env.OCTRA_CHROME_PATH??'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',[
    '--headless=new','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-sync','--disable-breakpad','--disable-features=OptimizationHints,MediaRouter','--metrics-recording-only','--password-store=basic','--use-mock-keychain','--remote-debugging-port=0',`--user-data-dir=${join(temp,'chrome')}`,'about:blank'
  ],{detached:true,stdio:['ignore','pipe','pipe']});
  for(const stream of [chrome.stdout,chrome.stderr])stream.on('data',chunk=>{diagnostics+=chunk.toString();});
  const info=await until(async()=>(await readFile(join(temp,'chrome','DevToolsActivePort'),'utf8')).trim().split('\n'),'Chromium DevTools ready');
  socket=new WebSocket(`ws://127.0.0.1:${info[0]}${info[1]}`);
  await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
  socket.addEventListener('message',event=>{
    const reply=JSON.parse(event.data);
    if(!reply.id){
      if(reply.method==='Target.attachedToTarget' && reply.params.targetInfo.type==='iframe') {
        Promise.all([call('Runtime.enable',{},reply.params.sessionId),call('Network.enable',{},reply.params.sessionId)])
          .catch(error=>{diagnostics+='\nIframe attach: '+error.message;});
      }
      if(reply.method==='Runtime.executionContextCreated') {
        const context=reply.params.context;
        if(context.auxData?.isDefault)contexts.set(`${reply.sessionId}:${context.id}`,{id:context.id,sessionId:reply.sessionId,frameId:context.auxData.frameId});
      }
      if(reply.method==='Runtime.executionContextDestroyed')contexts.delete(`${reply.sessionId}:${reply.params.executionContextId}`);
      if(reply.method==='Runtime.executionContextsCleared')for(const [key,context]of contexts)if(context.sessionId===reply.sessionId)contexts.delete(key);
      if(reply.method==='Network.loadingFailed')diagnostics+=`\nNetwork failure: ${JSON.stringify(reply.params)}`;
      return;
    }
    const item=pending.get(reply.id);if(!item)return;pending.delete(reply.id);clearTimeout(item.timeout);
    reply.error?item.reject(new Error(JSON.stringify(reply.error))):item.resolve(reply.result);
  });
  const target=await call('Target.createTarget',{url:'about:blank'});const {sessionId}=await call('Target.attachToTarget',{targetId:target.targetId,flatten:true});
  await call('Page.enable',{},sessionId);
  await call('Runtime.enable',{},sessionId);
  await call('Emulation.setDeviceMetricsOverride',{width:1200,height:900,deviceScaleFactor:1,mobile:false},sessionId);
  await call('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:false,flatten:true},sessionId);
  const evaluate=async(expression,context)=>{
    const result=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,...(context?{contextId:context.id}:{})},context?.sessionId??sessionId);
    if(result.exceptionDetails)throw new Error(JSON.stringify(result.exceptionDetails));return result.result.value;
  };
  let lastDocument='';
  async function content(expected) {
    return until(async()=>{
      const tree=(await call('Page.getFrameTree',{},sessionId)).frameTree;
      const targets=(await call('Target.getTargets')).targetInfos;
      const child=targets.find(t=>t.type==='iframe'&&t.parentFrameId===tree.frame.id);
      const frameId=child?.targetId??tree.childFrames?.[0]?.frame.id;
      const context=[...contexts.values()].find(c=>c.frameId===frameId);
      if(!context)return;
      const value=await evaluate(`({title:document.querySelector('h1')?.textContent,color:document.querySelector('h1')?getComputedStyle(document.querySelector('h1')).color:null,image:document.querySelector('img')?.naturalWidth,hacked:document.body?.dataset.hacked??null,hash:location.hash,scripts:document.scripts.length,document:location.href,text:document.body?.textContent?.slice(0,250)})`,context);
      const documentState=JSON.stringify(value);if(documentState!==lastDocument){console.log(documentState);lastDocument=documentState;}
      if(value.title!==expected)return;
      return {...value,contextId:context,url:await evaluate('location.href')};
    },`Circle content: ${expected}`);
  }
  await call('Page.navigate',{url:fixture.old},sessionId);
  let old=await until(async()=>{const value=await content('Committed Circle');return value.image===24?value:undefined;},'old snapshot image');
  if(process.argv[2]){const shot=await call('Page.captureScreenshot',{},sessionId);await writeFile(resolve(process.argv[2].replace(/\.json$/,'.png')),Buffer.from(shot.data,'base64'));}
  assert.equal(old.color,'rgb(20, 100, 160)');assert.equal(old.scripts,0);assert.equal(old.hacked,null);
  const box=await evaluate(`(()=>{let r=document.querySelector('#next').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`,old.contextId);
  const frameBox=await evaluate(`(()=>{let r=document.querySelector('iframe').getBoundingClientRect();return {x:r.x,y:r.y}})()`);
  await call('Input.dispatchMouseEvent',{type:'mouseMoved',x:box.x+frameBox.x,y:box.y+frameBox.y},sessionId);
  await call('Input.dispatchMouseEvent',{type:'mousePressed',x:box.x+frameBox.x,y:box.y+frameBox.y,button:'left',clickCount:1},sessionId);
  await call('Input.dispatchMouseEvent',{type:'mouseReleased',x:box.x+frameBox.x,y:box.y+frameBox.y,button:'left',clickCount:1},sessionId);
  const other=await content('Second Circle');assert.match(other.url,/\/old\/view\/[^/]+\/two\/about#section$/);assert.equal(other.hash,'#section');
  await call('Page.navigate',{url:fixture.new},sessionId);
  const next=await until(async()=>{const value=await content('Committed Circle');return value.color==='rgb(140, 20, 30)'?value:undefined;},'new snapshot stylesheet');
  await call('Page.navigate',{url:fixture.old},sessionId);
  old=await until(async()=>{const value=await content('Committed Circle');return value.color==='rgb(20, 100, 160)'?value:undefined;},'retained snapshot stylesheet');
  let application;
  if(nativeSite) {
    await call('Page.navigate',{url:fixture.application},sessionId);
    let counter=await content('Rust guest room');
    await until(()=>evaluate(`document.getElementById('app-status')?.textContent.includes('Circle connected')`),'Circle SDK connection');
    const stats=async()=>await (await fetch(fixture.stats)).json();
    const click=async(selector,context)=>{
      if(selector==='#inc')await evaluate(`document.getElementById('result').textContent=''`,context);
      const box=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});e.scrollIntoView({block:'center'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`,context);
      if(context){const f=await evaluate(`(()=>{const r=document.querySelector('iframe').getBoundingClientRect();return {x:r.x,y:r.y}})()`);box.x+=f.x;box.y+=f.y;}
      await call('Input.dispatchMouseEvent',{type:'mouseMoved',...box},sessionId);
      await call('Input.dispatchMouseEvent',{type:'mousePressed',...box,button:'left',clickCount:1},sessionId);
      await call('Input.dispatchMouseEvent',{type:'mouseReleased',...box,button:'left',clickCount:1},sessionId);
    };
    await click('#wallet-info',counter.contextId);
    await until(()=>evaluate(`document.querySelector('#result').textContent.includes(${JSON.stringify(fixture.wallet)})`,counter.contextId),'upstream wallet.info');
    await click('#get-counter',counter.contextId);
    await until(()=>evaluate(`(()=>{try{const r=JSON.parse(document.querySelector('#result').textContent);return r.label==='get_counter'&&r.value.result==='4'}catch{return false}})()`,counter.contextId),'canonical counter WASM execution');
    await click('#program-info',counter.contextId);
    await until(()=>evaluate(`(()=>{try{const r=JSON.parse(document.querySelector('#result').textContent);return r.label==='program.info'&&r.value.runtime==='wasm_v1'&&r.value.code_b64===null&&r.value.methods.some(m=>m.name==='get_counter')}catch{return false}})()`,counter.contextId),'canonical program descriptor');
    const caller=await evaluate(`OctraCircle.request('program.view',{method:'caller_echo',params:[]})`,counter.contextId);
    assert.deepEqual(caller,{result:'oct00000000000000000000000000000000000000000000'});
    const isolation=await evaluate(`(async()=>{let parentBlocked=false,networkBlocked=false;try{void parent.document.body;}catch{parentBlocked=true;}try{await fetch('/apps/app/request',{method:'POST',headers:{'X-Octra-Session':'0'.repeat(64)}});}catch{networkBlocked=true;}return {parentBlocked,networkBlocked,origin:window.origin};})()`,counter.contextId);
    assert.deepEqual(isolation,{parentBlocked:true,networkBlocked:true,origin:'null'});
    const unsupported=await evaluate(`OctraCircle.request('rpc.arbitrary').then(()=>false,()=>true)`,counter.contextId);assert.equal(unsupported,true);
    await click('#inc',counter.contextId);
    await until(()=>evaluate(`document.getElementById('circle-review').open`),'wallet review');
    const detail=await evaluate(`document.getElementById('review-intent').textContent`);
    assert.ok(detail.includes(`Circle: ${fixture.circle}`));assert.match(detail,/Method: inc/);assert.match(detail,/Amount: 0/);assert.match(detail,/OU limit: 1000/);
    assert.equal((await stats()).calls.length,0);
    await evaluate(`document.getElementById('review-approve').click()`);
    await evaluate(`parent.postMessage({type:'review',approve:true},'*')`,counter.contextId);
    assert.equal(await evaluate(`document.getElementById('circle-review').open`),true);
    assert.equal((await stats()).calls.length,0);
    await click('#review-decline');
    await until(()=>evaluate(`document.querySelector('#result').textContent.includes('declined')`,counter.contextId),'declined upstream call');
    assert.equal((await stats()).calls.length,0);
    await evaluate(`window.reviewProbeDone=false;OctraCircle.request('program.call',{method:'inc',params:['</pre><img id="injected-review" src=x onerror="alert(1)">'],amount:'0',ou:'1000'}).catch(()=>{}).finally(()=>{window.reviewProbeDone=true});true`,counter.contextId);
    await until(()=>evaluate(`document.getElementById('circle-review').open`),'untrusted parameters displayed for review');
    assert.equal(await evaluate(`document.getElementById('injected-review') === null && document.getElementById('review-intent').textContent.includes('<img id=')`),true);
    await click('#review-decline');
    await until(()=>evaluate(`window.reviewProbeDone`,counter.contextId),'untrusted parameters declined');
    if(process.argv[2]) { await click('#inc',counter.contextId);await until(()=>evaluate(`document.getElementById('circle-review').open`),'review screenshot');const shot=await call('Page.captureScreenshot',{},sessionId);await writeFile(resolve(process.argv[2].replace(/\.json$/,'.approval.png')),Buffer.from(shot.data,'base64'));await click('#review-decline');await until(()=>evaluate(`document.querySelector('#result').textContent.includes('declined')`,counter.contextId),'screenshot review declined'); }
    await click('#inc',counter.contextId);
    await until(()=>evaluate(`document.getElementById('circle-review').open`),'second wallet review');
    await click('#review-approve');
    await until(()=>evaluate(`(()=>{try{const r=JSON.parse(document.querySelector('#result').textContent);return r.label==='inc'&&/^[a-f0-9]{64}$/.test(r.value.tx.hash)}catch{return false}})()`,counter.contextId),'signed and committed upstream call');
    const submitted=await stats();assert.equal(submitted.calls.length,1);
    assert.equal(submitted.calls[0].context.circle_id,fixture.circle);
    assert.equal(submitted.count.result,'5');assert.equal(submitted.epoch,2);assert.equal(submitted.balance,'9000');assert.equal(submitted.nonce,1);assert.equal(submitted.supply,'10000');assert.equal(submitted.proposer_reward,'775');
    assert.equal(submitted.exex.length,1);assert.equal(submitted.exex[0].hash,submitted.calls[0].hash);
    const status=await evaluate(`OctraCircle.request('tx.wait',{hash:${JSON.stringify(submitted.calls[0].hash)}})`,counter.contextId);
    assert.equal(status.status,'committed');assert.equal(status.epoch,2);assert.equal(status.receipt.success,true);
    const pinned=await evaluate(`OctraCircle.request('program.view',{method:'get_counter',params:[]})`,counter.contextId);assert.equal(pinned.result,'4');
    assert.deepEqual(submitted.calls[0].call,{method:'inc',params:[],amount:'0',ou:'1000'});
    await click('#inc',counter.contextId);
    await until(()=>evaluate(`document.getElementById('circle-review').open`),'review before frame reload');
    await evaluate(`location.reload();true`,counter.contextId);
    await until(()=>evaluate(`document.getElementById('app-status').textContent.includes('Session closed') && !document.getElementById('circle-review').open`),'reload revokes application session');
    assert.equal((await stats()).calls.length,1);
    await call('Page.navigate',{url:fixture.application},sessionId);
    counter=await content('Rust guest room');
    await until(()=>evaluate(`document.getElementById('app-status')?.textContent.includes('Circle connected')`),'fresh Circle SDK connection');
    const nextPath=new URL(fixture.application).pathname.replace(new RegExp(`${fixture.circle}/$`),'two/about#section');
    await evaluate(`(()=>{let a=document.createElement('a');a.id='sdk-next';a.textContent='Other Circle';a.href=${JSON.stringify(nextPath)};a.dataset.octraNavigation='true';document.body.append(a);return true;})()`,counter.contextId);
    await click('#sdk-next',counter.contextId);
    const navigated=await content('Second Circle');assert.match(navigated.url,/\/apps\/view\/[^/]+\/two\/about#section$/);
    const freshOctb=await (await fetch(fixture.octb_application)).json();
    await call('Page.navigate',{url:freshOctb.url},sessionId);
    const octb=await content('Rust guest room');
    await until(()=>evaluate(`document.getElementById('app-status')?.textContent.includes('Circle connected')`),'OCTB Circle SDK connection');
    const octbInfo=await evaluate(`OctraCircle.request('program.info')`,octb.contextId);
    assert.equal(octbInfo.runtime,'octb');assert.equal(octbInfo.code_b64,null);
    assert.equal(octbInfo.methods.find(m=>m.name==='get_counter').view,true);
    assert.equal(octbInfo.methods.find(m=>m.name==='inc').view,false);
    assert.deepEqual(await evaluate(`OctraCircle.request('program.view',{method:'get_counter',params:[]})`,octb.contextId),{result:'4'});
    assert.deepEqual(await evaluate(`OctraCircle.request('program.view',{method:'caller_echo',params:[]})`,octb.contextId),{result:'oct00000000000000000000000000000000000000000000'});
    assert.equal(await evaluate(`OctraCircle.request('program.view',{method:'inc',params:[]}).then(()=>false,()=>true)`,octb.contextId),true);
    assert.equal((await stats()).epoch,2);
    await click('#inc',octb.contextId);
    await until(()=>evaluate(`document.getElementById('circle-review').open`),'OCTB wallet review');
    assert.equal((await stats()).calls.length,1);
    await click('#review-approve');
    await until(()=>evaluate(`(()=>{try{const r=JSON.parse(document.querySelector('#result').textContent);return r.label==='inc'&&/^[a-f0-9]{64}$/.test(r.value.tx.hash)}catch{return false}})()`,octb.contextId),'signed and committed OCTB call');
    const octbCommitted=await stats();
    assert.equal(octbCommitted.calls.length,2);assert.equal(octbCommitted.calls[1].context.circle_id,fixture.octb_circle);
    assert.equal(octbCommitted.octb_count.result,'5');assert.equal(octbCommitted.count.result,'5');
    assert.equal(octbCommitted.epoch,3);assert.equal(octbCommitted.nonce,2);assert.equal(octbCommitted.balance,'8000');
    assert.equal(octbCommitted.exex.length,1);assert.equal(octbCommitted.exex[0].hash,octbCommitted.calls[1].hash);
    const octbStatus=await evaluate(`OctraCircle.request('tx.wait',{hash:${JSON.stringify(octbCommitted.calls[1].hash)}})`,octb.contextId);
    assert.equal(octbStatus.status,'committed');assert.equal(octbStatus.epoch,3);assert.equal(octbStatus.receipt.success,true);
    assert.deepEqual(await evaluate(`OctraCircle.request('program.view',{method:'get_counter',params:[]})`,octb.contextId),{result:'4'});
    application={status:'pass',native_site:nativeEvidence,host:'native signed Circle transaction, admission, WASM execution, quorum-signed canonical commit and durable ExEx record on a development chain; public fixture keys, native epoch reward distribution but no peer consensus driver',checks:['upstream script and SDK reads','canonical counter view and program descriptor','native anonymous caller context','opaque origin and blocked direct network','unsupported method refusal','review required','synthetic approval ignored','untrusted parameters rendered as text','decline without submission','one approved native signed submission','canonical counter increment and fee debit','committed transaction status','durable ExEx transaction and receipt','retained app reads remain pinned','frame reload revocation','user-activated cross-Circle app navigation']};
    application.host='native signed Circle transactions, admission, WASM and OCTB execution, quorum-signed canonical commits and durable ExEx records on a development chain; public fixture keys and native epoch rewards, without a peer consensus driver';
    application.checks.push('OCTB descriptor and native caller context','OCTB views reject storage writes','approved OCTB signed submission and fee debit','OCTB canonical state and durable ExEx receipt','OCTB retained snapshot remains pinned');
  }
  const sourceSha256=Object.fromEntries(await Promise.all(sourcePaths.map(async path=>[path,createHash('sha256').update(await readFile(path)).digest('hex')])));
  assert.deepEqual(sourceSha256,startedSource,'source changed during browser qualification');
  const evidence={source_sha256:sourceSha256,status:'pass',scope:'Real Chromium CSS/images, user-activated cross-Circle links, fragment navigation, script isolation and immutable canonical snapshot resources',old:old.url,new:next.url,other:other.url,application,chrome:(await call('Browser.getVersion')).product};
  const output=process.argv[2];if(output)await writeFile(resolve(output),JSON.stringify(evidence,null,2)+'\n');
  console.log(JSON.stringify(evidence));
} finally {
  socket?.close();for(const {timeout,reject}of pending.values()){clearTimeout(timeout);reject(new Error('browser closed'));}
  await stop(chrome);await stop(server);await rm(temp,{recursive:true,force:true});
}
