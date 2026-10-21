# octra.to Circle site

This directory is the source bundle for the `octra.to` onboarding Circle. The
site uses only passive HTML, CSS and SVG. The public gateway sanitizes the HTML,
rewrites same-Circle links to pinned Circle routes, and deliberately disables
forms, scripts, wallet operations and arbitrary external navigation. Keep those
boundaries when editing the copy.

All six current assets are byte-verified on public devnet at Circle
`octC9XpV4K4LJWFzc16zvaS1Rk3z8nyiqS7xwswH84Tca7E`. The
[current publication record](../../docs/rust-node/checkpoints/2026-10-21/octra-to-site.json)
pins the three onboarding updates and all six asset hashes. The pages describe
the invited native SDK profile and link to the private alpha guide. DNS resolves
the apex to `143.110.222.241`, and trusted TLS is verified. The latest HTTPS
check returned HTTP 503 while the final Rust observer catches up; public RPC
and general Circle paths remain 404. Private paid ingress is still closed,
and this publication does not qualify the public alpha.

The site also presents the bonded devnet operator's sealed offer. Its
`operator-profile.json` is published at `/operators/octra.to/v1.json` in the
operator-owned tariff Circle, signed by that Circle's owner wallet. It binds the
site name, wallet, payment Circle, offer and tariff asset without claiming that
public enrollment or sustained exit service is available. The profile is not a
free portal asset; its canonical hash and transaction belong in the deployment
checkpoint.

Publish these six files at the **same paths** in one Circle configured for public
resources, then wait for canonical inclusion before enabling the gateway:

| Circle asset path | MIME |
| --- | --- |
| `/index.html` | `text/html` |
| `/join.html` | `text/html` |
| `/browse.html` | `text/html` |
| `/operators.html` | `text/html` |
| `/style.css` | `text/css` |
| `/logo.svg` | `image/svg+xml` |

No build step or remote image/font request is required. `index.html` is the
entrypoint, including for `/`. Do not publish `README.md` as a portal asset.
The asset bytes in this directory are the publication inputs. The repository
does not sign publication transactions.
`bundle.json` records their MIME types, sizes and SHA-256 hashes. Before
publication, run `python3 sites/octra-to/bundle.py --check`; use `--write`
after an intentional asset edit.

## Gateway wiring

For a public pre-join `https://octra.to` front door, place TLS termination in
front of the Rust node's loopback gateway. The reverse proxy must preserve the
real `Host: octra.to`; do not forward `/rpc` or a general proxy through this
origin. The devnet portal Circle is fixed to the verified publication:

The current devnet route uses the shared relay at `143.110.222.241`. Its
[Caddyfile](Caddyfile) terminates HTTPS and forwards only to relay loopback
`127.0.0.1:20885`. An SSH reverse forward connects that loopback port to the
Mac's Docker-published `127.0.0.1:20806`; the Docker bridge reaches the Rust
gateway at `127.0.0.1:20805` inside the node network namespace. The proxy
cannot reach node RPC. Keep the reverse forward bound to relay loopback:

```sh
ssh -NT -o BatchMode=yes -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -R 127.0.0.1:20885:127.0.0.1:20806 root@143.110.222.241
```

Use a pinned SSH host key and supervised restart for the forward. Set the
`octra.to` apex A record to the relay and allow only TCP 80/443 for public
web access. Caddy obtains the public certificate after DNS reaches the relay.
The Mac must stay online for this devnet route; a dedicated always-on node is
needed before treating the site as a durable public service.

```json
{
  "gateway": {
    "listen": "127.0.0.1:20805",
    "origin": "https://octra.to",
    "portal": {
      "circle": "octC9XpV4K4LJWFzc16zvaS1Rk3z8nyiqS7xwswH84Tca7E",
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

An operator can expose the same bounded asset set after registration through
`stock_portal` at `198.18.0.1:443`, with the same Circle ID and allowlist,
`origin: "https://octra.to"`, and a trusted TLS certificate/key. The public
gateway and stock portal are different listeners; the stock route supplies a
free way back to the site after enrollment. Public DNS points `octra.to` to the
public TLS proxy. Operator MagicDNS may override it on the tailnet to the
registration-only portal. Both paths must serve the same canonical Circle
assets; neither grants general Circle access.

The paid stock Circle gateway has a **separate** origin:

```json
{
  "stock_circle_gateway": {
    "origin": "https://circles.octra.to",
    "sites": {},
    "tls": {
      "certificate": "circles.pem",
      "private_key": "circles.key"
    }
  }
}
```

The stock exit maps its paid route to that gateway only after a confirmed
prepaid purchase. MagicDNS must map `circles.octra.to` to the paid gateway's
reserved VPN address, and its certificate must be trusted by the client. The
native gateway serves any *publicly readable* Circle at
`https://circles.octra.to/circles/<circle>/<path>`. It also accepts
`GET /resolve?u=<percent-encoded-oct-url>` and redirects to the corresponding
same-origin Circle path. The free `octra.to` portal rejects `/resolve` and other
Circles. DNS alone never rewrites an `oct://` URL.

## Release check

After publishing and deploying, verify a canonical head and the exact asset
bytes through the actual HTTPS origin:

```sh
curl -fsSI https://octra.to/
curl -fsS https://octra.to/join.html
curl -fsSI https://octra.to/circles/ANOTHER_CIRCLE/index.html  # must fail
curl -fsSI 'https://octra.to/resolve?u=oct%3A%2F%2FANOTHER_CIRCLE%2Findex.html'  # must fail
```

Then, from a registered client with a confirmed paid allowance, verify a known
public Circle through `circles.octra.to` and ensure the same URL is unavailable
before purchase or after exhaustion. Also test that the browser receives a
trusted certificate and that an unregistered device cannot reach the paid
route. These are deployment acceptance checks. The Circle publication is
verified; public DNS/TLS and general signup are not yet qualified.
