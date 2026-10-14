// This SDK runs in the untrusted opaque Circle frame. It never holds a wallet
// credential or an approval token. Its only capability is a shell-owned port.
(() => {
  let port, serial = 0;
  const instance = Array.from(crypto.getRandomValues(new Uint8Array(16)), n => n.toString(16).padStart(2, '0')).join('');
  const pending = new Map();
  const send = message => { if (port) port.postMessage(message); };
  const request = (method, params = {}) => new Promise((resolve, reject) => {
    if (pending.size >= 8) { reject(new Error('Too many pending Circle requests')); return; }
    const id = ++serial;
    const message = {type: 'request', id, method, params};
    let size;
    try { size = new TextEncoder().encode(JSON.stringify(message)).length; }
    catch { reject(new Error('Circle request is not serializable')); return; }
    if (size > 32768) { reject(new Error('Circle request too large')); return; }
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error('Circle request timed out')); }, 165000);
    pending.set(id, {resolve, reject, timeout, message});
    send(message);
  });
  Object.defineProperty(window, 'OctraCircle', {value: Object.freeze({request}), writable: false, configurable: false});
  window.addEventListener('message', event => {
    if (port || event.source !== parent || event.data?.type !== 'octra-circle-connect' || event.ports.length !== 1) return;
    port = event.ports[0];
    clearInterval(readyTimer);
    port.onmessage = ({data}) => {
      const item = pending.get(data?.id);
      if (!item) return;
      pending.delete(data.id); clearTimeout(item.timeout);
      data.error ? item.reject(new Error(data.error)) : item.resolve(data.result);
    };
    for (const item of pending.values()) send(item.message);
  });
  document.addEventListener('click', event => {
    const link = event.target instanceof Element ? event.target.closest('a[data-octra-navigation],area[data-octra-navigation]') : null;
    if (!link || !event.isTrusted || event.button !== 0) return;
    event.preventDefault();
    send({type: 'navigate', url: link.getAttribute('href')});
  }, true);
  const ready = () => { if (parent !== window) parent.postMessage({type: 'octra-circle-ready', instance}, '*'); };
  const readyTimer = setInterval(ready, 250);
  ready();
})();
