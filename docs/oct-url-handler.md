# `oct://` URL handler design

Status: **draft / scaffolding only**. Ships:

  - `crates/octravpn-client/src/commands/open_url.rs` — stub subcommand.
  - `dist/macos/octravpn-oct-handler.plist` — macOS LSHandler fragment.
  - `dist/macos/install-handler.sh` — `lsregister`-based installer.

Linux + Windows are described here, not shipped.

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

## Where the registration lives in the repo

Put the platform-specific glue under `dist/<platform>/`:

  - `dist/macos/octravpn-oct-handler.plist`  — Info.plist fragment.
  - `dist/macos/install-handler.sh`          — `lsregister` installer.
  - `dist/linux/octravpn-oct.desktop`        — (not shipped here)
  - `dist/linux/install-handler.sh`          — (not shipped here)
  - `dist/windows/install-handler.ps1`       — (not shipped here)

Alternative considered: bake registration into `octravpn doctor` or a
new `octravpn install-url-handler` subcommand. Rejected for now because
(a) platform installers (homebrew, MSI, dpkg) already have a notion of
"post-install scripts", and (b) running platform-protocol registration
as a side-effect of a CLI command is surprising — the user typed
`doctor`, not "rewrite my system LaunchServices DB". A subcommand
called `octravpn install-handler` (no side effects until invoked) is a
fine follow-up; not in scope here.

## macOS registration (shipped)

`dist/macos/octravpn-oct-handler.plist` is an Info.plist FRAGMENT — the
keys to merge into the host bundle's Info.plist when we ship a real
`.app`. Until we have an `.app`, the install script registers the bare
binary via `lsregister -url` and a tiny on-the-fly bundle skeleton.

`dist/macos/install-handler.sh`:

  - Locates the `octravpn` binary at `target/release/octravpn`.
  - Builds a minimal `OctravpnUrlHandler.app` bundle in
    `~/Library/Application Support/octravpn/handler/` that wraps a
    shell shim doing `exec octravpn open-url "$1"`.
  - Calls
    `/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f -R -trusted <bundle>`
    to register, then
    `lsregister -dump | grep -A2 'oct:'` to verify.

Manual test (not run during scaffolding):

  1. `cargo build --release -p octravpn-client`
  2. `bash dist/macos/install-handler.sh`
  3. `open "oct://octdeadbeef.../policy.json"`
  4. Expect: terminal window with `would open oct://octdeadbeef.../policy.json`

I did NOT execute step 2 or 3 because this worktree is headless and
`lsregister` mutates the user's LaunchServices DB — that is the kind of
side effect we don't run from an agent without an explicit ask.

## Linux registration (described, not shipped)

`~/.local/share/applications/octravpn-oct.desktop`:

```
[Desktop Entry]
Type=Application
Name=OctraVPN oct:// handler
Exec=/usr/local/bin/octravpn open-url %u
MimeType=x-scheme-handler/oct;
NoDisplay=true
Terminal=false
```

Install:

```
xdg-mime default octravpn-oct.desktop x-scheme-handler/oct
update-desktop-database ~/.local/share/applications
```

Caveat: KDE/Plasma reads `kbuildsycoca5` cache; GNOME reads
`update-desktop-database`. Ship both.

## Windows registration (described, not shipped)

Per-user registry under `HKCU\Software\Classes\oct\`:

```
HKCU\Software\Classes\oct\(Default) = "URL:OctraVPN Protocol"
HKCU\Software\Classes\oct\URL Protocol = ""
HKCU\Software\Classes\oct\shell\open\command\(Default)
    = "\"C:\\Program Files\\OctraVPN\\octravpn.exe\" open-url \"%1\""
```

PowerShell installer:

```powershell
New-Item -Path "HKCU:\Software\Classes\oct" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\oct" -Name "(Default)" `
    -Value "URL:OctraVPN Protocol"
Set-ItemProperty -Path "HKCU:\Software\Classes\oct" -Name "URL Protocol" -Value ""
$cmd = '"C:\Program Files\OctraVPN\octravpn.exe" open-url "%1"'
New-Item -Path "HKCU:\Software\Classes\oct\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\oct\shell\open\command" `
    -Name "(Default)" -Value $cmd
```

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
