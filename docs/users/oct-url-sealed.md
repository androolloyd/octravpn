# `oct://` URLs — the sealed (encrypted) flow

Some circle assets are **sealed**: the bytes on chain are AES-GCM
ciphertext, decrypted only when the right passphrase is supplied. This
page covers what that looks like from a user's perspective — how the
portal handles the unseal step, what the CLI alternative is, and the
load-bearing invariants that keep sealed assets from leaking.

Public-asset flow is in [`oct-url-public.md`](oct-url-public.md); read
that first.

## 1. Why a circle hosts encrypted blobs

Three operator-level reasons:

1. **Operator-controlled access.** Only the members the operator
   handed the passphrase to can read the asset. Membership is
   off-chain, distributed by the operator (SMS, signed email, an
   onboarding portal).
2. **Per-member passphrases.** Different members get different
   passphrases derived from the same key class; rotation invalidates
   one member without re-sealing everything.
3. **Per-class policy.** The operator can publish public
   `policy.json` for prices + region, but seal `members.json` (or a
   subset of fields) so only paying members see contact info.

Canonical examples your operator may hand out:

- `oct://<operator>/members.json` — the v3 members file
  (schema: [`docs/v3-members-schema.md`](../v3-members-schema.md))
- `oct://<operator>/internal-config.json` — paid-tier configuration
- `oct://<operator>/private/<member-id>.json` — per-member blobs

## 2. The sealed envelope

Sealed assets start with the `OCRS1` magic prefix (`b"OCRS1"`):

```text
[ "OCRS1" (5B) ][ 12B nonce ][ AES-256-GCM ciphertext ][ 16B tag ]
                ╰────────────────╮
                                  │
                key = PBKDF2-HMAC-SHA256(passphrase,
                                         salt = derive(circle, key_id),
                                         iters = 120_000)
```

The codec lives in
[`octra-foundry/crates/octra-core/src/circle.rs`](/Users/androolloyd/Development/octra-foundry/crates/octra-core/src/circle.rs).
We re-implement the decrypt path in Rust in
[`crates/octravpn-client/src/portal/chain/decrypt.rs`](../../crates/octravpn-client/src/portal/chain/decrypt.rs);
the magic-prefix check is in
[`crates/octravpn-client/src/portal/chain/cache.rs:60`](../../crates/octravpn-client/src/portal/chain/cache.rs)
(`SEALED_MAGIC` constant).

## 3. The portal unseal flow

You click an `oct://` link, the portal fetches the envelope, and
the magic sniff says "sealed". What happens next depends on whether
the portal already has a passphrase for the circle:

### First-time visit to a sealed circle

The portal returns a **200 OK** with an **interactive HTML
form** (not a render of the asset!). The form looks roughly like:

> **Unseal this asset**
>
> Circle: `octOperatorMain`
>
> URL: `oct://octOperatorMain/members.json`
>
> [ passphrase: __________________________ ] [ Unseal ]

You type the passphrase the operator gave you and click Unseal.
The form POSTs to `/unseal`; on success, the portal stores the
passphrase in its in-memory `UnsealCache` (zeroized on shutdown,
*never* written to disk) and redirects you to the rendered asset.

### Subsequent visits in the same session

The cached passphrase is tried automatically. Render goes through
the same pipeline as a public asset — MIME sniff, sandboxed-HTML
for HTML, pretty-JSON for JSON, etc. (See
[`oct-url-public.md`](oct-url-public.md) §3.)

The passphrase cache is **process-local** and clears when you stop
the portal. Restart the portal → unseal again.

## 4. The cache-bypass invariant (load-bearing)

The portal's plaintext-asset cache (256 entries, 30 s TTL — see
[`oct-url-public.md`](oct-url-public.md) §4) has a critical
exception:

> **`try_decrypt_with_passphrase` MUST NEVER serve cached plaintext.**

Why: `POST /unseal` validates the operator-supplied passphrase by
calling `try_decrypt_with_passphrase` and treating success as proof
the passphrase is correct. If a cached plaintext (decrypted under a
**previous** passphrase) satisfied the call, the unseal step would
collapse into a **false-positive validation oracle** — any wrong
passphrase submitted after a successful one would also "succeed",
because the cache would short-circuit the decrypt.

The invariant is enforced in
[`crates/octravpn-client/src/portal/chain/decrypt.rs`](../../crates/octravpn-client/src/portal/chain/decrypt.rs)
— the unseal path calls `fetch_inner` (the cache-bypass pipeline)
directly, never `fetch_cached`, and never writes back into the
cache. The test
`try_decrypt_with_passphrase_bypasses_cache` (same file) pins it.

If you're hacking on the portal, this is the one invariant you
must not break. The cache-bypass module's doc-comment spells it
out at the top.

## 5. The CLI alternative

If you don't want a browser in the loop — automation, shell
pipelines, headless scripts — use `octravpn fetch`:

```sh
# Passphrase from env (recommended for shared hosts):
OCTRAVPN_SEALED_PASSPHRASE="…" octravpn fetch oct://octOpMain/members.json

# Interactive prompt (no echo, up to 3 attempts):
octravpn fetch -i oct://octOpMain/members.json

# One-shot via flag — convenience, NOT for shared hosts:
octravpn fetch --secret 'pass' oct://octOpMain/members.json

# Save to disk instead of stdout:
octravpn fetch -o ./members.json oct://octOpMain/members.json

# Also emit Content-Type to stderr (curl -i style):
octravpn fetch --headers oct://octOpMain/members.json
```

There is **no** `--passphrase-file` flag. If you want a file source,
shell-quote into env:

```sh
OCTRAVPN_SEALED_PASSPHRASE="$(cat ~/.octra/pass.txt)" \
    octravpn fetch oct://octOpMain/members.json
```

(File mode would be a 10-line patch in
[`commands/fetch.rs`](../../crates/octravpn-client/src/commands/fetch.rs);
the env path covers the same use case today.)

### Passphrase precedence

Resolved in order, first non-empty wins
(`crate::discover_v2::resolve_passphrase`):

1. **`OCTRAVPN_SEALED_PASSPHRASE` env var.**
2. **`--secret <pass>`** on the CLI (or the portal's
   `POST /unseal` form value).
3. **`[v2].sealed_passphrase`** in your client config TOML.

If none resolve and stdout is a TTY with `-i` set, the CLI prompts
interactively. Otherwise it exits **4** (missing passphrase).

### Exit codes (CLI)

| Code | Meaning                                                                |
| ---- | ---------------------------------------------------------------------- |
| 0    | success                                                                |
| 2    | bad usage / bad URL / mode conflict                                    |
| 3    | fetch failed (transport, RPC, output write, etc.)                      |
| 4    | sealed asset, no passphrase resolved + no TTY                          |
| 5    | wrong passphrase — 3 attempts exhausted                                |

Documented in
[`commands/fetch.rs`](../../crates/octravpn-client/src/commands/fetch.rs)
module docstring.

## 6. MIME sniff for sealed JSON

Common case: the operator publishes a sealed JSON blob like
`members.json` and ships you the passphrase out-of-band.

The flow:

1. Envelope arrives, magic prefix is `OCRS1`.
2. Portal/CLI calls `try_decrypt_with_passphrase`.
3. On success, the plaintext starts with `{` (after whitespace).
4. MIME sniff returns `Json`.
5. Portal renders pretty-printed JSON in a `<pre>` block. CLI writes
   the plaintext to stdout (or `--output`).

The sniff doesn't care about extensions — `members` with no
extension and `members.json` with one render identically.

## 7. Failure modes

### "Wrong passphrase"

The portal shows the unseal form again with an inline error:
**"decrypt failed"**. The page comes from
[`unseal_form_page`](../../crates/octravpn-client/src/portal/routes.rs)
which re-renders the form with the previous URL but a fresh
nonce/token.

CLI: exit code 5 after 3 attempts in interactive mode, or exit
code 3 on a single non-interactive failure.

The portal does not throttle per-passphrase attempts on its own —
the caller (you) is expected to back off. Don't script a wordlist
attack against `/unseal`; the chain RPC is the rate limit, and
operators can blocklist circle ids that show up in script-shaped
patterns.

### "Stale `key_id`"

The operator rotated the sealing key. Your old passphrase no longer
decrypts the current envelope because the envelope was re-sealed
under a new `key_id`. Symptoms: same circle, same path, used to
work, now "decrypt failed".

Fix: ask the operator for the new passphrase. The chain RPC always
returns the **latest** envelope for the asset path, so there's no
way to reach the old one.

### "Operator rotated keys mid-session"

You unseal an asset, browse for 30 seconds, the operator rotates
the key, the next click hits the new envelope under the same path
→ "decrypt failed" with the cached passphrase. The portal renders
the unseal form again; you type the new passphrase.

The portal's plaintext cache TTL is 30 s, which bounds how stale a
cached render can be — see
[`crates/octravpn-client/src/portal/chain/cache.rs:30`](../../crates/octravpn-client/src/portal/chain/cache.rs)
(`DEFAULT_ASSET_CACHE_TTL`).

### "Asset doesn't exist"

The chain RPC returns null for the resource key. The portal
renders a 502 page with the underlying RPC error. Usual causes:

- Typo in the URL — paths are case-sensitive.
- The operator removed the asset (publish revoked).
- You're talking to the wrong RPC (`[chain].rpc_url` in your
  client config points at a different chain than the operator
  publishes to).

## See also

- [`oct-url-public.md`](oct-url-public.md) — non-sealed flow,
  portal startup, MIME sniff details, sandbox attributes
- [`../oct-url-handler.md`](../oct-url-handler.md) — the
  protocol-handler design notes (the URL-to-RPC translation)
- [`../v3-members-schema.md`](../v3-members-schema.md) — what a
  decoded `members.json` looks like
- [`octra-foundry/crates/octra-core/src/circle.rs`](/Users/androolloyd/Development/octra-foundry/crates/octra-core/src/circle.rs)
  — the canonical sealed-asset codec
