# `oct://` URLs — the public flow

If your operator (or a member of the chain-anchored tailnet) gave
you a link like `oct://octCircleX/index.html`, this page explains
what happens when you click / paste / `octravpn fetch` it. This
file covers the **public** case (no encryption) — see
[`oct-url-sealed.md`](oct-url-sealed.md) for the sealed variant.

You only need this page if you're on a chain-anchored tailnet (your
operator told you to install the `octravpn` CLI). Stock-Tailscale
users don't see `oct://` links.

## 1. What `oct://<circle>/<path>` is

It's a stable name for a chunk of bytes hosted inside an **Octra
circle**. A circle is a key/value container on the Octra chain; each
entry is keyed by a deterministic `resource_key` derived from the
circle id and the canonical path:

```text
oct://<circle_id>/<canonical_path>
            │
            └──→ resource_key = sha256("octra:circle_resource_key:v1"
                                       || circle_id || canonical_path)
                                       (hex)
```

The client first tries
`circle_asset_ciphertext_by_resource_key([circle, rkey])`. If that view
misses, it checks `circle_info` before disclosing the path. Only a Circle
reporting both `privacy_class=public` and `resource_mode=public_resources`
can use `circle_asset([circle, path])`. The client verifies the returned
Circle, path, resource key, byte count, and SHA-256 blob hash. Sealed assets
keep the resource-key path and the `OCRS1` unseal flow described in
[`oct-url-sealed.md`](oct-url-sealed.md).

What the operator publishes as public:
- `index.html` for the operator's landing page
- `policy.json` for circles with public pricing
- attestation bundles, public configs, images
- anything else the operator chose to keep unencrypted

## 2. The portal binary

A local HTTP server you run on loopback. Render `oct://` URLs in
your normal browser through this portal — never through the public
internet.

Start it:

```sh
octravpn portal                            # default: 127.0.0.1:51823
octravpn portal --bind 127.0.0.1:51900     # custom bind
```

(There is no `serve` subcommand — the binary form is
`octravpn portal [--bind <addr>]`. The default port `51823` is the
`DEFAULT_PORTAL_PORT` constant in
[`crates/octravpn-client/src/portal/mod.rs:27`](../../crates/octravpn-client/src/portal/mod.rs).)

Open `http://127.0.0.1:51823/` in your browser. You'll see a small
address bar — paste `oct://octCircleX/index.html` and the portal:

1. Splits the URL into `(circle_id, path)`.
2. Checks the resource-key view and, for a confirmed public Circle, reads
   the plaintext asset by path and verifies its hash.
3. Notices the bytes are **not** sealed (no `OCRS1` magic, see
   [`crates/octravpn-client/src/portal/chain/cache.rs`](../../crates/octravpn-client/src/portal/chain/cache.rs)).
4. Sniffs the MIME (see §3).
5. Renders the asset using the type-appropriate handler.

The route table lives in
[`crates/octravpn-client/src/portal/routes.rs`](../../crates/octravpn-client/src/portal/routes.rs).

### Browser integration

You don't have to paste URLs by hand — the `dist/` directory ships
OS-level protocol-handler installers that make `oct://` clickable:

```sh
# Linux:
dist/linux/install-handler.sh

# macOS:
dist/macos/install-handler.sh

# Windows (PowerShell, admin):
dist/windows/install-handler.ps1
```

After install, clicking an `oct://…` link anywhere on your machine
dispatches to `octravpn open-url <url>`, which:

- Spawns a portal on `127.0.0.1:51823` if none is running, and
- Opens `http://127.0.0.1:51823/o/<base64-of-the-oct-url>` in your
  default browser.

The `open-url` flow is documented in
[`crates/octravpn-client/src/commands/open_url.rs`](../../crates/octravpn-client/src/commands/open_url.rs).

Firefox may ask before an `oct://` link launches the installed handler. For
links that work in any HTTPS-capable app without an external-protocol prompt,
the tailnet can publish a trusted gateway hostname instead:

```text
oct://<circle>/index.html
https://<gateway-host>/circles/<circle>/index.html
```

Tailnet DNS maps `<gateway-host>` to the gateway. The gateway resolves the
Circle and serves the asset; DNS itself cannot rewrite URL schemes or paths.
The Rust node's canonical read-only gateway implements `/circles/<circle>/<path>`
behind a tailnet HTTPS reverse proxy. The proxy, certificate, DNS record, and
tailnet enrollment must be deployed before that HTTPS address is usable.

## 3. MIME sniff and per-type rendering

The portal doesn't depend on file extensions — it sniffs the first
few bytes and dispatches based on the inferred type. Sniff order
(from [`crates/octravpn-client/src/portal/mime.rs`](../../crates/octravpn-client/src/portal/mime.rs)):

| Bytes start with                 | MIME                          | Renders as                                |
| -------------------------------- | ----------------------------- | ----------------------------------------- |
| PNG / JPEG / GIF / WebP magic    | `image/*`                     | `<img>` inside the portal chrome          |
| `%PDF-`                          | `application/pdf`             | Save-As                                   |
| `{` or `[` (after whitespace)    | `application/json`            | Pretty-printed in a `<pre>` block         |
| `<!DOCTYPE` / `<html` / `<svg`   | `text/html`                   | **Sandboxed iframe** — see below          |
| Valid UTF-8 otherwise            | `text/plain`                  | `<pre>` block                             |
| Anything else                    | `application/octet-stream`    | Save-As (content-disposition: attachment) |

Order matters: JSON is checked **before** HTML so a payload like
`{"...html..."}` doesn't get misclassified.

### The HTML sandbox

When the sniff says `text/html`, the portal does **not** render the
asset directly. It wraps the bytes in an iframe with
`sandbox="allow-popups"` and uses the `srcdoc` attribute so the
contents stay inside our origin:

```html
<iframe class="sandbox-frame" sandbox="allow-popups" srcdoc="…escaped html…"></iframe>
```

(See [`render_sandboxed_html`](../../crates/octravpn-client/src/portal/routes.rs)
at line 839, asserted in the test at line 960.)

Crucially: **no** `allow-scripts`, **no** `allow-same-origin`. A
malicious circle can't run JavaScript, can't read your cookies, can't
issue same-origin XHRs. The `allow-popups` flag stays so a hyperlink
in the asset can open a new tab, but that new tab re-enters the
portal's security gate.

## 4. The asset cache (#237)

To keep browsing snappy, decrypted/decoded asset bytes are cached
per `(circle_id, canonical_path)`:

- **Capacity: 256 entries** (LRU eviction).
- **TTL: 30 seconds.**
- The path is canonicalised so `/policy.json` and `policy.json`
  collapse to the same key.

Implementation: [`crates/octravpn-client/src/portal/chain/cache.rs`](../../crates/octravpn-client/src/portal/chain/cache.rs).
The cache is shared across all clones of `PortalState` (every
request handler) via `Arc<BoundedMap>`.

The cache only ever holds bytes you've already successfully
fetched; the **unseal** path (for sealed assets) intentionally
bypasses it — see [`oct-url-sealed.md`](oct-url-sealed.md) §"The
cache-bypass invariant".

## 5. Privacy: what an observer learns

The portal binds to loopback, then contacts the configured chain RPC over
HTTPS. It does not establish a VPN session or hide your source IP from that
RPC. A separate, active VPN route may carry the RPC connection if you have
configured one.

For a sealed asset, the RPC sees the Circle id and derived resource key. On
a sealed-asset miss, the client checks Circle metadata but does not disclose
the plaintext path. For a public Circle with public resources, the fallback
`circle_asset` request includes the plaintext path. The RPC can also observe
the connection metadata and timing. Browsing a public Circle does not require
a wallet or a paid VPN session.

## 6. Worked example: fetching a public `index.html`

The operator has a circle `octOperatorMain` and a public landing
page at `oct://octOperatorMain/index.html`.

```sh
# Configure [chain].rpc_url for the intended network, then start the portal:
octravpn --config client.toml portal
# Then paste oct://octOperatorMain/index.html into the portal's
# address bar.
```

Step-by-step:

1. The portal accepts the URL on `POST /` (or `GET /o/<b64>` if you
   followed a protocol-handler link).
2. It calls
   [`PortalChain::fetch_circle_asset_bytes`](../../crates/octravpn-client/src/portal/chain/fetch.rs).
3. The RPC returns the envelope (no `OCRS1` magic ⇒ not sealed).
4. MIME sniff returns `Html`.
5. The portal wraps the bytes in the sandboxed iframe and serves
   the wrapped HTML at a URL like
   `http://127.0.0.1:51823/view/<base64>`.
6. The next 30 s of requests to this asset hit the cache.

If you `octravpn fetch oct://octOperatorMain/index.html` instead,
the same fetch happens but the raw bytes are written to stdout —
no MIME-render, no sandbox, no cache (the CLI path doesn't share
the portal's cache).

## 7. Demo / replay

[`demo/tapes/02-portal-fetch.tape`](../../demo/tapes/02-portal-fetch.tape)
boots a portal against a demo circle, exercises the CLI `fetch` and
the HTTP portal side-by-side, and captures the result as a gif/mp4.
Re-run with `vhs demo/tapes/02-portal-fetch.tape` against the demo
state in `demo/state/portal/`.

## See also

- [`oct-url-sealed.md`](oct-url-sealed.md) — when the asset is
  encrypted: the unseal flow, cache-bypass invariant, passphrase
  precedence
- [`../oct-url-handler.md`](../oct-url-handler.md) — design notes
  for the OS-level protocol handler
- [`../v3-policy-schema.md`](../v3-policy-schema.md) — schema of
  the canonical `policy.json` asset
- [`../v3-members-schema.md`](../v3-members-schema.md) — schema of
  the `members.json` asset
