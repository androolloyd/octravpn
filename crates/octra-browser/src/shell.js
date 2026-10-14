// Trusted local shell only. Circle code has an opaque origin and receives no
// session or review credentials. Only this document can approve a host intent.
(() => {
  const frame = document.getElementById('circle-content');
  if (!frame) return;
  const source = frame.getAttribute('src').split('#')[0];
  const update = () => { if (frame.getAttribute('src') !== source + location.hash) frame.src = source + location.hash; };
  window.addEventListener('hashchange', update);
  update();
  const host = document.getElementById('circle-host');
  if (!host) return;
  const token = host.dataset.token, api = host.dataset.api, navigation = host.dataset.navigation;
  delete host.dataset.token;
  const status = document.getElementById('app-status');
  const dialog = document.getElementById('circle-review');
  const details = document.getElementById('review-intent');
  const approve = document.getElementById('review-approve');
  const decline = document.getElementById('review-decline');
  const controller = new AbortController();
  let port, instance, closed = false, loaded = false, decide;
  const pending = new Set();
  const rpc = async (path, body) => {
    if (closed) throw new Error('Circle session closed');
    const response = await fetch(api + path, {method: 'POST', credentials: 'omit', cache: 'no-store', signal: controller.signal,
      headers: {'Content-Type': 'application/json', 'X-Octra-Session': token}, body: JSON.stringify(body)});
    const reply = await response.json();
    if (!response.ok) throw new Error(reply.error ?? 'Circle request refused');
    return reply;
  };
  const close = () => {
    if (closed) return;
    closed = true;
    controller.abort(); port?.close();
    decide?.(false); dialog.close();
    // Session credentials stay in a header even during teardown.
    fetch(api + '/close', {method: 'POST', credentials: 'omit', keepalive: true,
      headers: {'X-Octra-Session': token}}).catch(() => {});
    status.textContent = 'Session closed. Open the Circle again to reconnect.';
  };
  window.addEventListener('pagehide', close);
  frame.addEventListener('load', () => { if (loaded) close(); loaded = true; });
  approve.addEventListener('click', event => { if (event.isTrusted) decide?.(true); });
  decline.addEventListener('click', event => { if (event.isTrusted) decide?.(false); });
  dialog.addEventListener('cancel', event => { event.preventDefault(); decide?.(false); });
  const review = async entry => {
    if (decide) throw new Error('A Circle call is already awaiting review');
    const {context, call} = entry.intent;
    details.textContent = `Circle: ${context.circle_id}\nChain: ${context.provenance.chain_id}\nEpoch: ${context.provenance.epoch}\nMethod: ${call.method}\nAmount: ${call.amount}\nOU limit: ${call.ou}\nParameters:\n${JSON.stringify(call.params, null, 2)}`;
    const accepted = await new Promise(resolve => {
      const timer = setTimeout(() => decide?.(false), 85000);
      decide = value => { clearTimeout(timer); decide = undefined; dialog.close(); resolve(value); };
      dialog.showModal(); decline.focus();
    });
    return rpc('/review', {id: entry.id, approve: accepted});
  };
  const handle = async ({data}) => {
    if (closed || !data || typeof data !== 'object') return;
    if (data.type === 'navigate') {
      if (!navigator.userActivation.isActive || typeof data.url !== 'string' || data.url.length > 16384) return;
      const url = new URL(data.url, location.origin);
      if (url.origin === location.origin && url.pathname.startsWith(navigation)) location.assign(url.href);
      return;
    }
    if (data.type !== 'request' || !Number.isSafeInteger(data.id) || data.id < 1 || pending.has(data.id)) return;
    const reply = value => { if (!closed) port.postMessage({id: data.id, ...value}); };
    if (pending.size >= 8) { reply({error: 'Too many pending Circle requests'}); return; }
    pending.add(data.id);
    try {
      const body = {method: data.method, params: data.params ?? {}};
      if (new TextEncoder().encode(JSON.stringify(body)).length > 32768) throw new Error('Circle request too large');
      let value = await rpc('/request', body);
      if (value.review) value = await review(value.review);
      reply(value);
    } catch (error) { reply({error: error.message}); }
    finally { pending.delete(data.id); }
  };
  window.addEventListener('message', event => {
    if (closed || event.source !== frame.contentWindow || event.origin !== 'null' || event.data?.type !== 'octra-circle-ready') return;
    const id = event.data.instance;
    if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) return;
    if (instance) { if (instance !== id) close(); return; }
    instance = id;
    const channel = new MessageChannel();
    port = channel.port1; port.onmessage = handle;
    frame.contentWindow.postMessage({type: 'octra-circle-connect'}, '*', [channel.port2]);
    status.textContent = 'Circle connected. Calls require your approval.';
  });
})();
