# Bounded unpaid Circle portal

The native gateway can expose a small, explicitly selected set of public Circle
assets before paid traffic admission. This is a website read capability. It does
not enroll a device, fund an account, sign transactions, authorize an exit, or
grant unrestricted Tailscale, DNS or DERP carriage.

Configure the gateway's existing loopback backend and exact HTTPS origin:

```json
{
  "gateway": {
    "listen": "127.0.0.1:20805",
    "origin": "https://octra.to",
    "portal": {
      "circle": "REPLACE_WITH_PORTAL_CIRCLE",
      "paths": [
        "/index.html",
        "/join.html",
        "/browse.html",
        "/operators.html",
        "/style.css",
        "/logo.svg"
      ]
    }
  }
}
```

The Circle must publish those assets in canonical public state. The HTTPS
reverse proxy supplies TLS and preserves the real Host header; forwarding
headers never choose the gateway authority. The backend remains loopback-only.
Do not configure `sites` together with `portal`: startup rejects that mixture.
The repo's deployable [octra.to Circle bundle](../../sites/octra-to/README.md)
uses this exact six-asset allowlist. Its stock-client paid Circle origin is
separate from the free portal, so `/resolve` and arbitrary Circle paths remain
unavailable before paid admission.

`/` maps directly to the explicitly allowed `/index.html`. The allowlist is
immutable for that running gateway, contains at most 128 distinct paths, and
requires canonical ASCII file paths of at most 1,024 bytes. Directory wildcards,
implicit directory indexes, percent escapes, dot traversal, duplicate paths and
query strings are refused. Assets retain the normal browser per-asset size
limit and passive-content policy; portal HTML does not gain script execution.
Keep the portal's links and asset references free of query-string cache tags.

The sanitized renderer uses `/circles/<Circle>/<file>` for navigation and
`/snapshots/<scope>/<Circle>/<file>` for subresources. Portal mode permits these
forms only for its exact Circle and allowlisted files. Another Circle, an
unlisted file, an unrecognized snapshot or an executable app/RPC route remains
unavailable. Existing canonical publication and catch-up checks still apply.

Use the assets for join instructions, funding instructions, operator offers and
other bounded onboarding information. Live balance views, wallet approval and
paid forwarding need their own authenticated native/client paths. This gateway
mode does not claim an OS captive-portal popup or a completed payment-tier
integration. All traffic settlement still takes zero protocol commission;
operator prices and unpaid portal reachability are separate concerns.
