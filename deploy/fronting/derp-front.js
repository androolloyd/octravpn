// derp-front.js — Cloudflare Worker that fronts an operator's DERP relay.
//
// Deploys to e.g. https://octravpn-front.workers.dev .  The
// octravpn-node client TLS-handshakes to that hostname (so the SNI
// the censor sees is `*.workers.dev`); the inner `Host:` header
// addresses the *real* DERP origin, which this Worker proxies to.
//
// Why fronting:
//   A state censor that can't break the wireguard/obfs4 TLS we wrap
//   DERP in can still cut the link by blocklisting every IP in the
//   operator's `derp-*` pool.  Cloudflare Workers share IPs with the
//   rest of the CDN; blocking us costs the censor every other site
//   on those IPs too.  Threat-model details:
//   docs/operators/derp-fronting.md.
//
// What it does, in order:
//   1. Constant-time verify the X-Octra-Front-Auth HMAC.  On failure,
//      return a generic 404 page that looks like a stale Worker.
//   2. Reject any request older than MAX_SKEW_SECS (replay window).
//   3. Build the upstream URL from the *inner* Host header and the
//      request path.  Forward body + safe headers.
//   4. Stream the response straight back to the client.
//
// Secrets required (set with `wrangler secret put`):
//   OCTRA_FRONT_KEY     — 64-char hex string, the 32-byte HMAC key.
//
// Optional env vars (configured in wrangler.toml `[vars]`):
//   OCTRA_REAL_HOST_ALLOWLIST — comma-separated list of real_host
//     values this Worker is willing to forward to.  Defenses-in-depth
//     against operator-key compromise; the attacker would still need
//     to land on an allowlisted backend.

// Header / canonical-form constants — MUST match
// crates/octravpn-tun/src/derp/front.rs verbatim.
const AUTH_HEADER = "x-octra-front-auth";
const TS_HEADER = "x-octra-front-ts";
const MAX_SKEW_SECS = 300;

// The generic 404 body.  Looks like a misconfigured Worker, not like
// "you guessed wrong, try again".
const NOT_FOUND_BODY =
  "<!doctype html><html><body><h1>404</h1><p>Not Found</p></body></html>";

/**
 * Hex-decode a string into a Uint8Array.  Returns null on malformed
 * input.
 *
 * @param {string} h
 * @returns {Uint8Array|null}
 */
function hexDecode(h) {
  if (typeof h !== "string" || h.length % 2 !== 0) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(h.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

/**
 * Lowercase hex-encode bytes.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function hexEncode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

/**
 * Constant-time byte-array equality.  WebCrypto verify is the gold
 * standard but it requires importing the key as HMAC-verify, which
 * forces us to compute the candidate ourselves anyway; this helper
 * keeps the comparison itself timing-safe.
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Compute the canonical HMAC tag.  Must stay bit-identical to
 * `auth_tag()` in front.rs.  The canonical string is
 *
 *   ts || '\n' || METHOD || '\n' || path || '\n' || hex(sha256(body))
 *
 * @param {Uint8Array} key 32-byte HMAC key.
 * @param {number}     ts  unix seconds.
 * @param {string}     method
 * @param {string}     path
 * @param {Uint8Array} body
 * @returns {Promise<Uint8Array>}
 */
async function authTag(key, ts, method, path, body) {
  const enc = new TextEncoder();
  const bodyHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", body),
  );
  const canonical = `${ts}\n${method}\n${path}\n${hexEncode(bodyHash)}`;
  const ck = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", ck, enc.encode(canonical)));
}

/**
 * Generic 404 — what we serve to anyone without a valid HMAC.
 * Includes the same cache headers a stale Worker would.
 */
function notFound() {
  return new Response(NOT_FOUND_BODY, {
    status: 404,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

/**
 * Main entrypoint.  Cloudflare hands us `{request, env, ctx}`.
 *
 * @param {Request} request
 * @param {Record<string, string|undefined>} env
 * @returns {Promise<Response>}
 */
export async function handleFetch(request, env) {
  // ── 1. parse / sanity-check headers ──────────────────────────────
  const url = new URL(request.url);
  const path = url.pathname + (url.search || "");
  const authHex = request.headers.get(AUTH_HEADER);
  const tsHdr = request.headers.get(TS_HEADER);
  if (!authHex || !tsHdr) return notFound();

  const candidate = hexDecode(authHex);
  if (!candidate || candidate.length !== 32) return notFound();

  const ts = parseInt(tsHdr, 10);
  if (!Number.isFinite(ts)) return notFound();

  // ── 2. skew check ────────────────────────────────────────────────
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > MAX_SKEW_SECS) return notFound();

  // ── 3. key import + HMAC verify ──────────────────────────────────
  const keyHex = env.OCTRA_FRONT_KEY;
  if (!keyHex || keyHex.length !== 64) {
    // Misconfigured — same 404 as a guess so we don't leak that the
    // Worker exists but is broken.
    return notFound();
  }
  const key = hexDecode(keyHex);
  if (!key) return notFound();

  // Read the body once into a buffer.  DERP requests are small (KB
  // range); larger uploads (~few MB) are still well under the Worker
  // request body cap (100 MB on paid, 100 KB on free — see docs).
  const bodyBuf = new Uint8Array(await request.clone().arrayBuffer());

  const expected = await authTag(key, ts, request.method, path, bodyBuf);
  if (!ctEqual(candidate, expected)) return notFound();

  // ── 4. resolve upstream from inner Host header ───────────────────
  const realHost = request.headers.get("host");
  if (!realHost) return notFound();

  // Optional allowlist defense-in-depth.
  const allow = (env.OCTRA_REAL_HOST_ALLOWLIST || "").trim();
  if (allow.length > 0) {
    const allowed = allow.split(",").map((s) => s.trim()).filter(Boolean);
    if (!allowed.includes(realHost)) return notFound();
  }

  // ── 5. forward upstream ──────────────────────────────────────────
  const upstream = `https://${realHost}${path}`;
  // Strip Worker-internal headers + headers Cloudflare adds (cf-*),
  // forward everything else.  Host is rewritten implicitly by `fetch`
  // using the upstream URL.
  const fwdHeaders = new Headers();
  for (const [k, v] of request.headers.entries()) {
    const lk = k.toLowerCase();
    if (lk === AUTH_HEADER || lk === TS_HEADER) continue;
    if (lk === "host") continue;
    if (lk.startsWith("cf-")) continue;
    if (lk === "x-real-ip" || lk === "x-forwarded-for") continue;
    fwdHeaders.set(k, v);
  }

  const upstreamReq = new Request(upstream, {
    method: request.method,
    headers: fwdHeaders,
    body:
      request.method === "GET" || request.method === "HEAD" ? undefined : bodyBuf,
    redirect: "manual",
  });

  let upstreamResp;
  try {
    upstreamResp = await fetch(upstreamReq);
  } catch (_e) {
    // Upstream unreachable.  Returning 502 would give a probing
    // censor a strong "this Worker forwards somewhere" signal, so
    // stay opaque.
    return notFound();
  }

  // Pass through upstream body + status; strip Server: header to
  // avoid leaking the DERP origin's identity.
  const respHeaders = new Headers(upstreamResp.headers);
  respHeaders.delete("server");
  return new Response(upstreamResp.body, {
    status: upstreamResp.status,
    headers: respHeaders,
  });
}

// Cloudflare Workers entrypoint.  Vercel Edge uses the same shape
// (export default { fetch }).
export default {
  /**
   * @param {Request} request
   * @param {Record<string, string|undefined>} env
   * @param {ExecutionContext} ctx
   */
  async fetch(request, env, ctx) {
    return handleFetch(request, env);
  },
};

// Exported for the Rust-side `verify_auth_tag()` cross-check and for
// `wrangler dev`-driven manual smoke tests.
export const __internal = {
  AUTH_HEADER,
  TS_HEADER,
  MAX_SKEW_SECS,
  authTag,
  ctEqual,
  hexDecode,
  hexEncode,
};
