# `oct://` URL handler design

Status: **draft / scaffolding only**. Ships:

  - `crates/octravpn-client/src/commands/open_url.rs` — stub subcommand.
  - `dist/macos/` — `octravpn-oct-handler.plist` + `install-handler.sh`.
  - `dist/linux/` — `octravpn-oct-handler.desktop` +
    `install-handler.sh` + `uninstall-handler.sh`.
  - `dist/windows/` — `octravpn-oct-handler.reg` (UTF-16 LE w/ BOM) +
    `install-handler.ps1` + `uninstall-handler.ps1`.

Cross-platform install index: `dist/README.md`.

## What `oct://<addr>/<path>` actually means today

`oct://` is **not** a registered URL scheme anywhere in this repo or any
shipped client. There is no existing OS protocol handler. What does exist
is a **naming convention** for sealed assets stored inside an Octra
circle, used in comments and v3 docs as the canonical reference to "the
sealed JSON at this resource path inside this circle":

  - `oct://<circle_id>/policy.json`        (operator policy; v2 discover)
  - `oct://<circle_id>/state-root.json`    (v3 commitment anchor)
  - `oct://<circle_id>/attestation.json`   (optional remote attestation)
  - `oct://<owner-circle>/tailnet-{id}/members.json` (v3 members file)

References in code:

  - `crates/octravpn-core/src/v3_state_root.rs:4` — `oct://<circle_id>/state-root.json`
  - `crates/octravpn-core/src/v3_policy.rs:4`     — `oct://<circle_id>/policy.json`
  - `crates/octravpn-node/src/chain_v3.rs:212,407` — same pattern, v3.

The translation from a path like `/policy.json` to a chain RPC is done
inside the **Rust client**, not in any browser. The webcli is the
upstream `octra-labs/webcli` JS app (`static/circles.html` @
commit `f9c73e1`) — it is referenced by `octra-foundry/crates/octra-core/src/circle.rs:1-25`
as the source of truth for the wire format. We do not ship that webcli;
we re-implement its translation in Rust.

### The translation (citation)

`octra-foundry/crates/octra-core/src/circle.rs:67-72`:

```rust
pub fn resource_key(circle_id: &str, canonical_path: &str) -> String {
    h256_hex(
        "octra:circle_resource_key:v1",
        &[circle_id.as_bytes(), canonical_path.as_bytes()],
    )
}
```

Used here, in this worktree, at
`crates/octravpn-client/src/discover_v2.rs:255-281` (function
`fetch_one`):

```rust
let rkey = resource_key(circle_id, "/policy.json");
let resp = client.rpc()
    .raw_call("circle_asset_ciphertext_by_resource_key",
              json!([circle_id, &rkey])).await?;
// resp = { ciphertext_b64, plaintext_hash, key_id }
let plaintext = decrypt_sealed_bytes(circle_id, key_id, passphrase,
                                     ciphertext_b64, plaintext_hash)?;
```

So the full pipeline `oct://<circle>/<path>` → bytes is:

  1. Split URL into `(circle, canonical_path)`.
  2. `rkey = h256_hex("octra:circle_resource_key:v1", [circle, canonical_path])`.
  3. JSON-RPC `circle_asset_ciphertext_by_resource_key([circle, rkey])`
     → `{ ciphertext_b64, plaintext_hash, key_id }`.
  4. `plaintext = decrypt_sealed_bytes(circle, key_id, passphrase, ciphertext_b64, plaintext_hash)`
     (`octra-core/src/circle.rs:310`). Sealed envelope is `OCRS1` magic
     + 12-byte nonce + AES-256-GCM (PBKDF2-HMAC-SHA256, 120 000 iters).
  5. Hand the plaintext bytes off based on MIME / file extension.

That is the exact algorithm the JS webcli runs in-browser; we just want
to run it from a native handler instead of inside that JS app.

## Handler binary: subcommand, not new binary

We add a clap subcommand to the existing `octravpn` binary:

```
octravpn open-url <oct-url>
```

Argued because:

  - The translation logic already lives inside this binary via the
    `octravpn-client` crate (`circle::resource_key`, `decrypt_sealed_bytes`,
    `Rpc::raw_call`). A new binary would have to depend on the same
    crates — pure duplication.
  - The wallet passphrase (`OCTRAVPN_SEALED_PASSPHRASE` or
    `[v2].sealed_passphrase`) is already loaded by the standard config
    path used by `discover`. A new binary would reimplement loading.
  - OS handler registrations point at a single executable plus an
    argv prefix (e.g. `["/usr/local/bin/octravpn", "open-url"]`). One
    binary is fine.

Tradeoff: handler invocations spin up `tokio` + `tracing` for a single
RPC call. Cold start is ~tens of ms; acceptable for a click-to-open UX.

## "VPN is up" check

The handler does NOT strictly require the WireGuard tunnel because the
chain RPC (`circle_asset_ciphertext_by_resource_key`) is served by the
node's public JSON-RPC endpoint — not by anything tunneled.

But the design intent is: a click on `oct://...` while connected fetches
**through** the tunnel so the user's IP isn't visible to the RPC
endpoint. That requires a live `utun*` interface plus a default route
into it.

Recommendation for the MVP:

  - Default: refuse to act if no `utun` interface has the expected
    address bound and instead print
    `VPN tunnel not active; please run \`octravpn connect-v3\` first.`
    Exit non-zero. (No browser dialog — the handler is the dialog,
    its terminal output is what the user sees in `Console.app`.)
  - Override: `--offline` (or env `OCTRAVPN_OPEN_URL_OFFLINE=1`) lets
    you fetch via the chain RPC over clearnet. Useful for dev / when
    the user is OK with leaking IP to fetch a public sealed asset.

Tunnel-up probe (macOS) without coupling to `octravpn-tun` internals:

  - `getifaddrs()` and look for any `utun*` with an IPv4 in the
    Octra tailnet allocation range (`octravpn-mesh/src/ip_alloc.rs`).
  - Or, simpler and good enough for the stub: probe a known
    in-tunnel-only endpoint (the magic DNS resolver at port 53 on the
    tailnet gateway). The stub does **neither** — it just prints
    "would open" and exits.

The scaffold returns early when offline; wiring real probes is left for
the follow-up that actually performs the RPC.

## Security model — risky, needs team call

`oct://` URLs in web pages are equivalent to "arbitrary JSON-RPC plus
arbitrary AES ciphertext" that anyone can ask the user to decrypt and
display. Three concrete risks:

  1. **Passphrase-oracle attack.** A malicious page can spam
     `oct://attacker-circle/asset` URLs and observe (via timing or via
     a 'success' signal) whether the user's sealed passphrase decrypts
     a given ciphertext. Mitigation: the AES-GCM tag means decrypt
     either works or fails cleanly; no timing oracle by default. But
     we should **never silently retry** with multiple passphrases.

  2. **Drive-by execution.** If the handler treats the decrypted
     plaintext by extension (`.html`, `.js`, …) and hands it to the
     default app, a sealed asset that contains a `.html` file can
     deliver arbitrary HTML to a system browser with the local
     filesystem context. **Default MUST be**: open in a sandboxed
     viewer (a per-MIME inert renderer — text gets pretty-printed JSON,
     binary gets a `Save As` dialog) and NEVER write to disk in a
     location the system associates with auto-exec.

  3. **Confirmation prompts.** First time a given origin (the calling
     web page's URL, passed via the `Referer`-equivalent on macOS:
     `NSAppleEventDescriptor` source-bundle) triggers an `oct://`
     fetch, the handler MUST surface a native dialog showing the full
     URL and the sealed-asset path before fetching. We do not get this
     for free; it needs a small AppKit shim or a `osascript -e display dialog`
     fallback.

Default policy in the stub: **always confirm**, **always
sandbox-render**, **never auto-open in browser**. This is more annoying
than the webcli — that's the right tradeoff for a system-wide handler.

## How rendering decides

The portal's `view_asset` handler walks the bytes through a fixed
pipeline before picking a renderer:

  1. **Fetch.** `PortalChain::fetch_circle_asset_bytes(circle_id, path)`
     calls the chain's `circle_asset_ciphertext_by_resource_key` view
     and base64-decodes the result. The fetcher accepts either
     `bytes_b64` (a future plaintext-view RPC field) or `ciphertext_b64`
     (today's sealed-view field), preferring the former.
  2. **Sealed-envelope sniff.** If the decoded bytes start with the
     OCRS1 magic (`"OCRS1" || nonce[12] || AES-GCM(...)`) the fetcher
     attempts decryption with the per-tailnet passphrase resolved at
     portal startup (env `OCTRAVPN_SEALED_PASSPHRASE` > config
     `[v2].sealed_passphrase`). One decrypt attempt — we never try
     multiple passphrases (passphrase-oracle risk; see open question
     #4 below).
  3. **Decrypt error → structured page.** If no passphrase is
     configured, the route layer renders a `412 Precondition Failed`
     page pointing the operator at `OCTRAVPN_SEALED_PASSPHRASE` /
     `[v2].sealed_passphrase`. Same page if the passphrase is wrong or
     the envelope is corrupt — the underlying decrypt error is
     deliberately not leaked through the UI.
  4. **Non-sealed bytes → pass through.** No OCRS1 magic ⇒ the bytes
     are returned verbatim. Keeps the renderer forward-compatible with
     a v3 plaintext-asset RPC.
  5. **MIME sniff.** The (now-plaintext) bytes hit the small magic
     table in `portal/mime.rs`: PNG / JPEG / GIF / WebP / PDF by binary
     magic, then JSON (leading `{` / `[`), then HTML / SVG by tag,
     then UTF-8-clean text, else `application/octet-stream`.
  6. **Render dispatch.** Images render inline as a data: URI. JSON
     gets pretty-printed. HTML lands in an `<iframe sandbox="allow-popups">`
     with no `allow-scripts` / `allow-same-origin`. Anything that
     falls to `octet-stream` becomes a Save-As download.

Practical consequence: a circle's sealed `/policy.json` now renders as
pretty-printed JSON in the portal instead of falling out as Save-As,
**provided** the operator has configured the per-tailnet passphrase
locally. Without the passphrase the portal still starts (with a `warn!`
at boot) and every sealed asset surfaces as the 412 page.

## Where the registration lives in the repo

Per-platform glue under `dist/<platform>/`; see the section per
platform below for shipped files. See `dist/README.md` for the
install-quickstart index.

Alternative considered: bake registration into `octravpn doctor` or a
new `octravpn install-url-handler` subcommand. Rejected for now because
running platform-protocol registration as a side-effect of a CLI
command is surprising — the user typed `doctor`, not "rewrite my
system LaunchServices DB / mimeapps.list / registry". A subcommand
called `octravpn install-handler` (no side effects until invoked) is a
fine follow-up; not in scope here.

## macOS registration (shipped)

`dist/macos/octravpn-oct-handler.plist` is an Info.plist FRAGMENT — the
keys to merge into the host bundle's Info.plist when we ship a real
`.app`. Until we have an `.app`, `dist/macos/install-handler.sh` builds
a minimal `OctravpnUrlHandler.app` bundle under
`~/Library/Application Support/octravpn/handler/` that wraps a shell
shim doing `exec octravpn open-url "$1"`, then registers it with
`lsregister -f -R -trusted <bundle>` and verifies via `lsregister -dump`.

Manual test:

  1. `cargo build --release -p octravpn-client`
  2. `bash dist/macos/install-handler.sh`
  3. `open "oct://octdeadbeef.../policy.json"`
  4. Expect: terminal window with `would open oct://...` (stub).

None of the install scripts in this commit were executed by the agent
that wrote them — they all mutate the user's per-session shell state
(LaunchServices DB / `mimeapps.list` / HKCU registry) and need a real
GUI session to test.

## Linux registration (shipped)

Files:

  - `dist/linux/octravpn-oct-handler.desktop` — `.desktop` template
    with `__OCTRAVPN_BIN__` placeholder for the binary path.
  - `dist/linux/install-handler.sh` — locates `octravpn` (env override,
    PATH, then `target/release/octravpn`), renders the template into
    `~/.local/share/applications/octravpn-oct-handler.desktop`, runs
    `update-desktop-database` (when present), then
    `xdg-mime default octravpn-oct-handler.desktop x-scheme-handler/oct`
    and verifies via `xdg-mime query`.
  - `dist/linux/uninstall-handler.sh` — clears the binding (only if it
    still points at us) and removes the desktop file.

The desktop entry, rendered:

```
[Desktop Entry]
Type=Application
Name=OctraVPN URL Handler
Exec=/usr/local/bin/octravpn open-url %u
Terminal=false
NoDisplay=true
MimeType=x-scheme-handler/oct;
Categories=Network;
```

Manual test:

  1. `cargo build --release -p octravpn-client`
  2. `bash dist/linux/install-handler.sh`
  3. `xdg-open 'oct://octdeadbeef.../policy.json'`
  4. Expect: terminal-style invocation that prints `would open oct://...`.

Caveat: KDE reads `kbuildsycoca5/6`; GNOME reads
`update-desktop-database`. The script handles the latter; KDE usually
picks the new `.desktop` up on its filesystem watch.

## Windows registration (shipped)

Files:

  - `dist/windows/octravpn-oct-handler.reg` — UTF-16 LE / BOM registry
    template with `__OCTRAVPN_EXE__` placeholder. Writes the per-user
    `HKCU\Software\Classes\oct` subtree only — never HKLM.
  - `dist/windows/install-handler.ps1` — locates `octravpn.exe`
    (parameter override, then `Get-Command`, then
    `target\release\octravpn.exe`), renders the template into a temp
    `.reg` (with backslashes doubled per `.reg` REG_SZ rules), applies
    via `reg import`, then reads `HKCU:\Software\Classes\oct` back and
    asserts the values stuck.
  - `dist/windows/uninstall-handler.ps1` — `Remove-Item -Recurse`
    against `HKCU:\Software\Classes\oct`.

The rendered registry layout:

```
HKCU\Software\Classes\oct\(Default) = "URL:OctraVPN Protocol"
HKCU\Software\Classes\oct\URL Protocol = ""
HKCU\Software\Classes\oct\DefaultIcon\(Default) = "<path-to-octravpn.exe>,0"
HKCU\Software\Classes\oct\shell\open\command\(Default)
    = "\"<path-to-octravpn.exe>\" open-url \"%1\""
```

Manual test:

  1. `cargo build --release -p octravpn-client` (cross-compile or
     build on Windows).
  2. `powershell -ExecutionPolicy Bypass -File dist\windows\install-handler.ps1`
  3. `cmd /c start "" "oct://octdeadbeef.../policy.json"`
  4. Expect: a console window from `octravpn.exe` printing
     `would open oct://...`.

Edge/Chrome/Firefox each prompt the first time. No way to skip that
prompt without an installer-signed scheme registration (out of scope).

## Open questions for the team

  1. Sandboxed viewer: build it (small `egui` or AppKit window) or
     punt to "always Save As"? Save-As is safer; viewer is friendlier.
  2. Tunnel-up policy: hard refuse when down, or fall back to clearnet
     RPC with a warning? IP-leak risk vs. broken-link UX.
  3. Confirm-on-first-fetch: per-page-origin grant DB, or
     prompt-every-time forever? Per-origin DB needs a real source of
     truth for "page origin" passed by macOS (`NSAppleEventDescriptor`
     gives bundle id, not page URL).
  4. Should the handler also accept `oct://<oct_wallet_address>` (no
     path) and open the wallet-explorer? Out of scope for the
     sealed-asset MVP; needs its own design.

## `oct://` as a protocol adapter

`oct://` is not just a browser-handler scheme — it's a system-wide
adapter, accessible from any tool that follows OS URL-handler
conventions or that can hit `http://127.0.0.1:51823`. Three entry
points share one auth model:

| Entry point         | Caller             | Auth surface                     |
|---------------------|--------------------|----------------------------------|
| `octravpn open-url` | OS protocol handler | per-circle confirm, env passphrase |
| `octravpn fetch`    | shell / pipelines  | per-circle confirm, env passphrase, `-i` TTY prompt |
| portal `/raw`       | curl / wget / scripts | per-circle confirm (HMAC token), per-circle unseal cache |
| portal `/o/<b64>`   | system browser     | per-circle confirm, per-circle unseal cache (interactive form) |

The portal's HMAC-SHA256 confirm token is the single approval
primitive. The CLI mints one via `GET /confirm?u=...&accept=cli`
(JSON), the browser mints one via the existing interstitial. They are
indistinguishable on the server side — there is no separate CLI
privilege class.

The sealed-asset passphrase has two source modes:

- **Boot-time configured.** Whatever `OCTRAVPN_SEALED_PASSPHRASE` or
  `[v2].sealed_passphrase` resolved to when the portal / CLI started.
  Used as the default for every circle.
- **Per-circle unseal cache.** Built when the operator submits a
  passphrase via `POST /unseal` (browser) or supplies one via
  `octravpn fetch --secret` / `-i`. Lives in portal process memory
  only; restart re-prompts.

There is no on-disk passphrase database. There is no system-wide DNS
or SOCKS proxy. The portal is the gateway; this design makes it a
usable gateway, not a transparent one.

## Using from `curl` / `wget`

Any tool that can speak HTTP loopback can dereference `oct://` URLs.
The portal exposes a raw-bytes endpoint at `GET /raw?u=<oct-url>`
that returns the asset body with a `Content-Type` derived from the
existing MIME sniffer — no HTML wrapping.

### Worked example

```
# 1. Start the portal in the background.
$ octravpn portal &

# 2. First fetch returns a 412 with an approve URL.
$ curl http://127.0.0.1:51823/raw?u=oct://octCircleX/policy.json
{
  "error": "circle not approved",
  "circle_id": "octCircleX",
  "approve_url": "/confirm?u=oct%3A%2F%2FoctCircleX%2Fpolicy.json&accept=cli",
  "hint": "GET the approve_url to mint a one-shot token, then retry with &token=<hex>"
}

# 3. Mint a token (the &accept=cli bypass returns JSON, not HTML).
$ TOKEN=$(curl -s "http://127.0.0.1:51823/confirm?u=oct://octCircleX/policy.json&accept=cli" | jq -r .token)

# 4. Re-fetch with the token. If the asset is plaintext or the
#    operator's boot-time passphrase decrypts it, this returns the
#    body. Otherwise a 412 with a sealed_decrypt_failed code points
#    at the browser unseal flow.
$ curl "http://127.0.0.1:51823/raw?u=oct://octCircleX/policy.json&token=$TOKEN"
{"endpoint": "vpn.example:51820", "region": "us-east", ...}

# 5. wget works the same way:
$ wget -O policy.json "http://127.0.0.1:51823/raw?u=oct://octCircleX/policy.json&token=$TOKEN&dl=1"
```

### Optional: a system-wide curl wrapper

For ergonomics, the repo ships a tiny `oct-curl` shim that does the
token dance for you. macOS + Linux + Windows. See
`dist/<platform>/oct-curl[.ps1]`. Sample usage:

```
$ oct-curl oct://octCircleX/policy.json
{"endpoint": "vpn.example:51820", ...}
$ oct-curl -o /tmp/policy.json oct://octCircleX/policy.json
```

The wrapper is **not** installed by `install-handler.sh` — it's
opt-in. Copy it to `/usr/local/bin/oct-curl` (or wherever) yourself.

### CLI fetch

Operators who prefer not to start the portal can hit the same path
through `octravpn fetch`:

```
$ octravpn fetch oct://octCircleX/policy.json                      # bytes → stdout
$ octravpn fetch -o /tmp/policy.json oct://octCircleX/policy.json  # bytes → file
$ octravpn fetch --secret PASS oct://octCircleX/policy.json        # one-shot pass
$ octravpn fetch -i oct://octCircleX/policy.json                   # prompt on TTY
$ octravpn fetch --headers -o /tmp/x.json oct://octCircleX/x.json  # CT to stderr
```

Exit codes (so wrapper scripts can branch):

| Code | Meaning                                                    |
|------|-------------------------------------------------------------|
| 0    | success                                                    |
| 2    | bad usage / bad URL / wrong protocol_version               |
| 3    | fetch failed (transport, RPC, write)                       |
| 4    | sealed and no passphrase available (env / config / `-i`)   |
| 5    | wrong passphrase, retry attempts exhausted (3 attempts)    |

## Interactive unseal flow

Sealed assets sometimes need a passphrase the operator didn't have
when they launched the portal — they only learned it after the
browser opened. The portal supports an in-browser unseal form so they
don't have to restart with a new `OCTRAVPN_SEALED_PASSPHRASE`.

### Browser side

When `/o/<b64>` fetches a sealed asset and decryption fails, the
portal renders an `<form action="/unseal" method="POST">` with a
single `<input type="password">` and hidden `circle` + `next` fields.

Submitting the form triggers `POST /unseal`. The handler validates
the candidate passphrase by attempting to decrypt the circle's
canonical resource-key fixture (`/state-root.json` first, then
`/policy.json` if state-root isn't published). On success the
passphrase is cached **per-circle** in process memory and the browser
is redirected back to `next_url` (the `/o/<b64>` the operator
originally visited).

On failure (`DecryptFailed`) the form re-renders with "wrong
passphrase, try again". The operator can retry as many times as they
like — there is no per-form lockout, but the cache only commits on a
successful decrypt.

### CLI side

`octravpn fetch -i` prompts on the controlling TTY using
[`rpassword`] (no-echo). Up to three attempts. The candidate
passphrase is wrapped in `zeroize::Zeroizing` so the heap buffer
wipes on drop.

### Cache lifecycle

- **In-memory only.** The `PortalState.unseal_cache` is a
  `BTreeMap<circle_id, Arc<Zeroizing<String>>>`. Nothing is written
  to disk. A portal restart re-prompts.
- **Per-circle.** Submitting a passphrase for `octCircleA` does not
  unlock `octCircleB`. Different circles are different keys.
- **Fallback chain.** When the portal needs a passphrase for
  `circle_id`, it consults the unseal cache first, then the
  boot-time configured passphrase. Either is sufficient.

### Security: no oracle iteration

The form requires the operator to actively submit a passphrase. The
server runs **one** decrypt attempt per submission. There is no
retry loop on the server side, no enumeration of candidates, no
timing-difference exposure beyond what `aes-gcm` itself provides.

This is identical to the CLI prompt: three attempts is a UX
convenience, not a security primitive — each attempt is one decrypt
call, and the cache only commits on success. An attacker who
controls a malicious oct:// URL still cannot use the portal as a
passphrase oracle: they would need to convince the operator to type
the passphrase, and the form's `next_url` is sanitized to
same-origin portal paths.
