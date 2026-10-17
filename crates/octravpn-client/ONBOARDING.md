# Octranet onboarding from the client

There are two distinct connection paths.

**Personal Octranet.** Creating a personal tailnet has no treasury deposit.
Traffic carried on your own Octranet infrastructure has no operator toll.
Traffic carried or exited by another operator requires that operator's paid
OCT session; membership alone does not pay for transport. The current entry
point is the node's mesh service and a Tailscale
client: `octravpn-node mesh serve`, issue a pre-auth key with
`octravpn-node mesh mint-preauth`, then join with `tailscale up --login-server`
and that key. A Circle deployment and other chain transactions still incur
ordinary OCT transaction costs. This client command does not set up or bill a
personal mesh. Running a registered paid relay has separate operator stake and
session rules.

```sh
octravpn onboard personal --login-server https://mesh.example
```

This opens a read-only local guide in the system browser. It shows the
login-server and the stock Tailscale join command. The pre-auth key must be
minted by the running node and saved to a private local file; the browser never
receives it. The guide does not claim a successful join or switch the host's
existing Tailscale account. `tailscale status` is the independent check.
Use [Tailscale's `--auth-key=file:/private/path` form](https://tailscale.com/docs/reference/tailscale-cli/up)
so the key bytes are not
placed in shell history or the process command line; restrict file permissions
and delete a single-use key file after successful admission.

A chain-anchored personal mesh needs the revised v5 app deployed first. Its
owner creates the tailnet with `octravpn-node --config node.toml v3
create-personal-tailnet --members-root <64-hex-root>` (transaction value zero),
publishes the sealed `/tailnet-{id}/members.json` asset to the owner Circle,
then updates the root with `v3 update-members-root --tailnet-id <id>
--new-members-root <hash>`. The mesh daemon must run with
`--members-policy-owner <owner-wallet> --members-policy-circle <asset-host-circle>
--members-policy-tailnet-id <id>`;
admission denies everyone until the published asset and committed root match.
After ownership transfer, configure `--members-policy-owner` with the new
wallet, publish the new member asset and update its on-chain root; a daemon
still configured for the old owner denies admission on its next sync.
These steps incur ordinary transaction fees, but no personal mesh treasury
deposit or paid-relay operator stake. They do not authorize unmetered use of
another operator's relay or exit. The public devnet deployment still needs
to adopt that revised v5 app before this chain-anchored path is available there.

**Paid provider VPN.** Configure `[chain].protocol_version = "v3"`, the current
settlement app, `[v3].circle_id`, `[v3].tailnet_id`, wallet and `max_pay`, then:

```sh
octravpn --config client.toml connect-v3 --tun-name octra0 --onboard
```

`--onboard` only shows funding and connection status; it does not divert host
traffic. For an opt-in Linux public IPv4 exit, with the personal Tailscale mesh
already active, use:

```sh
octravpn --config client.toml connect-v3 --tun-name octra0 --onboard --paid-exit
```

The guarded route activates only after the paid tunnel authenticates. It needs
the host privileges and independent physical route to the operator endpoint
required by `--paid-exit` preflight. Other operating systems do not currently
support this guarded host route.
An unexpected client exit leaves OctraVPN's IPv4 and IPv6 blocking routes in
place. Before reopening a paid session, inspect
`ip -4 -j route show proto 186` and `ip -6 -j route show proto 186`, verify
that each route belongs to this client (metrics 45678/45679) and that no paid
TUN is active, then delete only those verified routes with `ip route del`.
Do not flush all routes with that protocol number without checking ownership.

The client checks the anchored operator policy and local TUN capability, opens
a read-only page on a random `127.0.0.1` port, and asks the OS browser launcher
to show it. The address is printed if the launcher is unavailable. The page
shows the wallet address, current raw OU balance, and an estimated minimum
covering `max_pay` plus opening/settlement transaction fee reserve. Fund it using
an ordinary Octra wallet transfer; the page never accepts keys, authorizes a
transaction, or redirects application traffic. Once the balance reaches that
estimate, the CLI submits the existing signed `open_session` and requires
canonical admission and an authenticated WireGuard handshake before reporting
"connected". Policy and chain checks can still reject the opening. Provider
traffic is charged at the operator's committed OCT rate, which the operator
can set to zero. The protocol takes no commission. Escrow is refunded or
settled through the existing session rules.

The paid provider path is a separate tunnel. Automatic paid-exit federation
between stock Octranets is not active; stock Tailscale mesh and DERP traffic
are not metered by this settlement application. Do not offer a third-party
carrier through that path as a paid Octranet service. The client does not bind a stock
Tailscale exit selection to a paid session. A source Octranet gateway cannot
yet bill forwarded members through this command: their `100.64/10` packet
sources fail the paid TUN's session-address check. Such a gateway needs
session-scoped NAT and isolated Tailscale underlay before use.

`--onboard` requires `--tun-name`. Without `--paid-exit`, host route, NAT and
DNS setup for the TUN are explicit deployment steps. On macOS,
Windows and Linux, the CLI tries the platform browser launcher and prints the
loopback URL. VPN connection alone cannot reliably trigger a Wi-Fi captive
network popup on these operating systems. This implementation does not hijack
DNS or HTTP, intercept HTTPS, or expose the local page to other devices.
