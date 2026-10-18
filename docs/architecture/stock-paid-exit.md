# Stock Tailscale paid exit

The native node can attach its prepaid payment service to a stock Tailscale
client. This is an explicit operator configuration. Registration grants access
to a fixed Circle onboarding portal; an accepted canonical byte purchase grants
paid carriage. The node meters decrypted IPv4 packets at the exit endpoint.
DERP authenticates registered peers and relays encrypted WireGuard packets; it
cannot classify or bill the traffic inside them.

These are implementation and configuration notes. The final qualification
checkpoint records which combinations have actually passed; this document alone
is not a deployment or interoperability result.

## Operator configuration

The normal node network/devnet configuration adds `mesh.stock_exit`,
`stock_portal`, and optionally `stock_circle_gateway` alongside its existing
`payments` configuration. For example, these are the additional fields, not a
complete network configuration:

```json
{
  "mesh": {
    "state_dir": "mesh",
    "tailnet_id": "my-octranet",
    "hostname": "control.example.org",
    "http_addr": null,
    "https_addr": "0.0.0.0:9443",
    "control_url": "https://control.example.org:9443",
    "admin_token_file": "mesh-admin.token",
    "tls": {"certificate": "control.pem", "key": "control.key"},
    "serve_derp": true,
    "dns": {
      "magic_dns": true,
      "base_domain": "mesh.example.org",
      "nameservers": {"global": [], "split": {}},
      "search_domains": [],
      "extra_records": []
    },
    "stock_exit": {
      "operator_ipv4": "100.64.0.1",
      "portal_port": 443,
      "circle_gateway": true
    }
  },
  "stock_portal": {
    "listen": "198.18.0.1:443",
    "origin": "https://join.example.org",
    "portal": {"circle": "CONFIRMED_PORTAL_CIRCLE", "paths": ["/index.html"]},
    "tls": {"certificate": "portal.pem", "private_key": "portal.key"}
  },
  "stock_circle_gateway": {
    "origin": "https://circles.example.org",
    "sites": {},
    "tls": {"certificate": "circles.pem", "private_key": "circles.key"}
  }
}
```

Replace the Circle address and provide certificates trusted by the client for
each configured DNS name. Relative certificate/key paths resolve against the
node configuration file's directory. The example does not provision DNS,
certificates, a public control endpoint, NAT or a firewall. Use a dedicated VPN
TUN; retain its address book and payment journals across restarts.
Control HTTPS needs its own socket. A wildcard bind on port 443 conflicts with
the fixed portal listener; port 8443 also conflicts when the paid Circle listener
is enabled. The example uses port 9443. A specific control-interface address can
share a port only when it differs from the fixed listener addresses.

Stock mode reserves the operator's CGNAT address and manages a policy that
connects clients to that operator. It refuses conflicting registrations or DNS
records. Its inline MagicDNS records map the portal origin to the operator's
CGNAT address and the paid Circle origin to the reserved VPN address
`198.18.0.0`. DNS does not implement an `oct://` protocol handler; applications
use ordinary HTTPS URLs.

The registration-only route maps operator TCP 443 to `198.18.0.1:443`. That
listener serves only the configured Circle and exact asset allowlist, including
`/index.html`. It grants no RPC, wallet, application execution or arbitrary
Circle access. The paid Circle route maps `198.18.0.0:443` to the separate TLS
listener at `198.18.0.1:8443`; it requires a paid connection and consumes purchased
bytes. The two origins must differ. General Circle URLs use
`https://circles.example.org/circles/CIRCLE/index.html`; published pages pin their
subresources to the same authenticated snapshot.

## Client consent and recovery

Join the operator's control service with stock Tailscale using an operator-issued
enrollment credential. Select the advertised Octranet exit. Enrollment alone
permits the fixed onboarding portal. Accept a finite payment plan, then run the
control-only `octravpn stock-payments` command with that plan, a durable journal,
the payer's receipt-key path and the stock client's public `nodekey:` value.
The controller does not read the Tailscale private key, install a second TUN or
change the user's routes. Its CLI help gives the exact options.

The stock connection signature has its own domain. A public stock request cannot
be replayed through the native framed endpoint or vice versa. The server binds
transport mode, node key, machine identity, registration time, expiry and IP to
the durable connection watermark. Re-registration or transport changes require
fresh payer consent with a newer sequence. Restart cannot reset consumed,
pending or uncertain allowance; valid prior framed journals migrate explicitly
as framed journals.

IPv4 Internet traffic and the paid Circle route require confirmed purchases in
the operator's immutable tariff classes. Exhaustion or canonical revocation
stops paid forwarding. The fixed portal remains a separate registration
capability. IPv6 is captured and refused in this version; it is not an IPv6 exit
service. Protocol commission is zero. Operators set their own prices; purchases
remain final, and available channel OCT can be withdrawn immediately.
