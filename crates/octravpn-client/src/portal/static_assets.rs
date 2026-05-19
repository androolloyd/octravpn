//! Inline HTML/CSS/JS for the portal's chrome.
//!
//! Hardcoded `include_str!`-style strings rather than a `serve_dir`
//! tower-http service: total budget is well under 8 KB and we want
//! exactly zero filesystem reads at runtime so the portal works inside
//! a sandboxed container without filesystem access beyond its own bin.
//!
//! **Decision log.** No JS framework. The index page has *one* function:
//! a form submit that base64url-encodes the `oct://` URL and navigates
//! to `/o/<b64>`. No external scripts, no inline event-handler attrs
//! (would clash with a future CSP). All forms are GET / POST with
//! `action=` and no JS dependency for the core flow.

/// The chrome wrapping a fetched asset (rendered title + URL bar +
/// payload `{inner}` placeholder).
pub(crate) const PAGE_SHELL: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{title}</title>
<style>
:root { color-scheme: light dark; }
body { font: 14px/1.45 -apple-system, system-ui, sans-serif; margin: 0; padding: 0; }
header { padding: 10px 14px; background: #1a1a2a; color: #d8d8e8; display: flex; gap: 8px; align-items: center; }
header a { color: #9ad; text-decoration: none; }
header form { flex: 1; display: flex; gap: 6px; }
header input[type=text] { flex: 1; padding: 6px 8px; border-radius: 4px; border: 1px solid #444; background: #0d0d18; color: #eee; font: 13px monospace; }
header button { padding: 6px 12px; border-radius: 4px; border: 0; background: #4a6cf7; color: white; cursor: pointer; }
main { padding: 14px; }
pre { background: #f6f6f9; padding: 12px; border-radius: 4px; overflow: auto; }
@media (prefers-color-scheme: dark) { pre { background: #1a1a22; color: #d8d8e8; } }
iframe.sandbox-frame { width: 100%; height: 80vh; border: 1px solid #888; border-radius: 4px; background: white; }
img.asset { max-width: 100%; height: auto; }
.confirm-card { max-width: 560px; margin: 4em auto; padding: 1.5em; border: 1px solid #888; border-radius: 6px; }
.confirm-card h2 { margin-top: 0; }
.confirm-card code { background: #eee; padding: 2px 4px; border-radius: 3px; word-break: break-all; }
@media (prefers-color-scheme: dark) { .confirm-card code { background: #2a2a36; } }
.error { color: #c33; }
</style></head>
<body>
<header>
<a href="/">octra portal</a>
<form action="/go" method="get">
<input type="text" name="u" value="{url}" placeholder="oct://&lt;circle&gt;/&lt;path&gt;" autocomplete="off" />
<button type="submit">Open</button>
</form>
</header>
<main>{inner}</main>
</body></html>
"#;

/// Index page (when no URL is open). The form submits to `/go` which
/// redirects to `/o/<b64>`.
pub(crate) const INDEX_BODY: &str = r#"<p>Paste an <code>oct://&lt;circle&gt;/&lt;path&gt;</code> URL above. The portal will fetch the asset over the active VPN session and render it locally — content is content-addressed via the on-chain resource_key.</p>
<p>Security gates active in this session:</p>
<ul>
<li>Tunnel-up check: portal refuses to start without <code>protocol_version=v3</code> (or v2 fallback).</li>
<li>HTML rendered inside a <code>sandbox="allow-popups"</code> iframe — no scripts, no same-origin.</li>
<li>First fetch per circle requires explicit confirm.</li>
<li>Unknown / encrypted bytes fall back to Save-As, never inline-rendered.</li>
</ul>
"#;
