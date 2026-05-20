# OctraVPN on macOS — install + first connect

This walks an end-user from a vanilla macOS box to a working
WireGuard tunnel into someone else's OctraVPN tailnet. You will
install two pieces:

1. **Tailscale** — the stock open-source client from
   <https://tailscale.com/download>, either as the Mac App Store GUI
   or the standalone CLI tarball / Homebrew formula. This speaks
   WireGuard to peers and Tailscale-wire to the operator's
   mesh-control endpoint.
2. **`octravpn`** (this project's optional client CLI). End users on
   a normal `--login-server` tailnet usually do **not** need it. See
   [`docs/tailnet-user-guide.md`](../tailnet-user-guide.md) if your
   operator told you to use the chain-anchored flow.

There are two flavours of "Tailscale on macOS" and the choice
affects everything downstream:

- **Mac App Store / Tailscale.app** — full GUI, signed Network
  Extension, runs as your user. Most end-users want this. Login via
  CLI works alongside the GUI.
- **Tailscale CLI (Homebrew / tarball)** — runs `tailscaled` as a
  LaunchDaemon, no GUI. Better if you live in the terminal or want
  to script the join.

Pick one path and stick with it; running both at the same time
fights for the `utun` device.

## 1A. Install via the Mac App Store (recommended)

1. Open the App Store, search for "Tailscale", install. (The
   developer is "Tailscale Inc.")
2. Launch Tailscale from `/Applications/Tailscale.app`. The first
   launch triggers macOS to ask permission for "Tailscale would like
   to add VPN configurations" — accept. This is the **Network
   Extension permission prompt** and it is the #1 macOS gotcha; if
   you decline, the entire flow silently no-ops.
3. The menu-bar icon appears. Right-click → "Log in…" — but stop
   there if you need a custom login-server (see §3 below).

## 1B. Install via Homebrew CLI

```sh
brew install tailscale
sudo brew services start tailscale
```

`brew services` installs a LaunchDaemon at
`/Library/LaunchDaemons/homebrew.mxcl.tailscale.plist`. The
`tailscale` CLI lands on your `$PATH` automatically.

Verify:

```sh
tailscale version
sudo launchctl list | grep tailscale
```

You should see version `1.78.x` or newer. OctraVPN regression-tests
against `1.78+`; older clients may not reach the post-DERP datapath.

## 2. (Optional) Install the `octravpn` CLI

Skip if your operator only gave you a preauth key + login-server.

### Via the project's installer

```sh
curl -fsSL https://octravpn.org/install.sh | sh
```

This drops `/usr/local/bin/octravpn`. It does **not** require root if
`/usr/local/bin` is writable; otherwise it `sudo install`s. See
[`deploy/install.sh`](../../deploy/install.sh) for the exact logic.

### From a release tarball

Grab `octravpn-VERSION-aarch64-apple-darwin.tar.gz` (Apple Silicon)
or `octravpn-VERSION-x86_64-apple-darwin.tar.gz` (Intel) from the
GitHub Releases page, then:

```sh
tar xzf octravpn-*.tar.gz
sudo install -m 0755 octravpn /usr/local/bin/
```

### Via Homebrew tap (when available)

```sh
brew tap octra-labs/octravpn
brew install octravpn
```

The formula is at
[`deploy/homebrew/octravpn.rb`](../../deploy/homebrew/octravpn.rb).
The tap is published per the release pipeline; if `brew tap` errors
"could not resolve repository", fall back to the tarball.

## 3. macOS Network Extension permission

This catches people every time. macOS sandboxes VPN config changes
behind a System Settings prompt. The first time a Tailscale binary
tries to create the `utun` interface, macOS pops a dialog:

> "Tailscale" would like to add VPN configurations. All network
> activity on this Mac may be filtered or monitored when using VPN.

You **must** click "Allow" and then authenticate with Touch ID or
your admin password. If you missed the prompt, find it later under:

**System Settings → General → Login Items & Extensions → Network
Extensions**

(On older macOS: **System Settings → Network → VPN & Filters** or
**System Preferences → Network → VPN**.)

Look for "Tailscale". Toggle it on. Without this, `tailscale up` will
appear to succeed but never produce a working interface.

If you installed via Homebrew CLI (not the App Store), the prompt
fires the first time you run `sudo tailscale up` — keep the System
Settings UI open in another window so you can grant it without
restarting the command.

## 4. First connect (CLI)

Get from your operator:

- **Login-server URL** — usually `https://<host>:443`.
- **Preauth key** — single-use unless they said otherwise.

Then, in Terminal:

```sh
sudo tailscale up \
    --login-server https://mesh.example.org \
    --authkey octrapreauth-YOUR-KEY-HERE
```

Notes:

- The first `sudo tailscale up` may pop the Network Extension prompt
  if it hasn't already. Grant it, then re-run.
- `--authkey` consumes the key on first use. Subsequent `tailscale
  up` runs (after reboot etc.) don't need it — the registration
  persists in `/Library/Tailscale/`.
- If you installed via the App Store GUI, you can also use:
  `tailscale login --login-server https://mesh.example.org`. This
  opens the menu-bar UI's auth flow — but for preauth keys, the CLI
  `--authkey` form is the documented path.

## 5. Verify

### Via the CLI

```sh
tailscale status
tailscale ip -4
```

`status` lists every peer with its tailnet IP, hostname, and current
relay status. `ip -4` prints your assigned address (a `100.64.x.x`
out of CGNAT space).

### Via System Settings

**System Settings → Network → VPN** — you should see a "Tailscale"
entry showing "Connected" with the tailnet IP. Toggle it off here in
an emergency; it's equivalent to `sudo tailscale down`.

### Peer reachability

```sh
tailscale ping <peer-hostname>
```

The headline test. RTTs that mention `via DERP(...)` are routed
through your operator's relay; RTTs with a UDP `ip:port` are direct
peer-to-peer (fastest, NAT permitting). Either result means you are
joined and the datapath is live.

## 6. Troubleshooting

### VPN config not appearing in System Settings

The Network Extension permission was declined. Re-trigger:

```sh
sudo tailscale down
sudo tailscale up --login-server ... --authkey ...
```

…and look for the dialog. If macOS suppresses it (e.g., you clicked
"Don't Allow" earlier), open **System Settings → Privacy & Security
→ General** and check for a "Some system software was blocked from
loading" warning. Click "Allow".

For Homebrew CLI installs specifically, also check
`sudo launchctl list | grep tailscale` — the daemon must be running
for the prompt to fire.

### "WireGuard endpoint refused" — UDP 51820 blocked

Symptom: `tailscale status` shows peers, but `tailscale ping <peer>`
only ever reports `via DERP(...)`, never direct.

Some corporate networks and many hotel Wi-Fis block UDP. Tailscale
falls back to DERP relay automatically; the connection works but is
slower. Confirm with:

```sh
sudo lsof -nP -iUDP | grep tailscale
```

If you see nothing bound on UDP, your firewall (corporate, school,
hotspot) is blocking egress. There's no client-side fix; the operator
must run a DERP relay reachable on TCP/443 — which they likely
already do, hence the working DERP fallback.

### TLS handshake failure on first launch

Symptom: `tailscale up` stalls at "control: connecting" then errors
out with a TLS-related message.

Causes:

1. **Self-signed cert.** During fresh deployments the operator's
   cert is not in the system trust store. Ask them for the CA PEM
   and add it via Keychain Access → System → Certificates →
   File → Import (set Trust to "Always Trust"). The interop harness
   does this automatically in CI; production deployments should use
   a real public-CA cert.
2. **System clock drift.** TLS verification fails if your clock is
   off by more than a few minutes. `sudo sntp -sS time.apple.com`.

### macOS firewall blocking

If you have the application firewall enabled (System Settings →
Network → Firewall), make sure `tailscaled` is allowed:

```sh
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/tailscaled
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/local/bin/tailscaled
```

For App Store installs, Tailscale.app is allowed automatically.

### App + CLI fighting

If you installed Tailscale both ways (App Store **and** Homebrew),
two daemons race for `utun`. Pick one:

```sh
# Drop the brew daemon, keep the app
sudo brew services stop tailscale
brew uninstall tailscale

# OR drop the app, keep the brew CLI
sudo /Applications/Tailscale.app/Contents/Resources/relaunch quit
rm -rf /Applications/Tailscale.app
```

Then re-run `sudo tailscale up …`.

## 7. Removing the Network Extension cleanly

Just uninstalling Tailscale leaves the Network Extension entry behind
in System Settings. Full cleanup:

```sh
# Stop everything first
sudo tailscale down
sudo tailscale logout
sudo brew services stop tailscale 2>/dev/null || true

# Remove the binary
brew uninstall tailscale 2>/dev/null || true
sudo rm -rf /Applications/Tailscale.app

# Remove state + extension cache
sudo rm -rf /Library/Tailscale
sudo rm -rf /Library/LaunchDaemons/com.tailscale.tailscaled.plist
sudo rm -rf /Library/Application\ Support/Tailscale
rm -rf ~/Library/Containers/io.tailscale.ipn.macsys
rm -rf ~/Library/Group\ Containers/*.io.tailscale.ipn

# Then in System Settings → General → Login Items & Extensions →
# Network Extensions, click the "-" next to Tailscale and confirm.
```

If you also installed `octravpn`:

```sh
sudo rm /usr/local/bin/octravpn
rm -rf ~/.octravpn          # bookmarks + per-tailnet config
```

See [`uninstall.md`](uninstall.md) for the cross-platform state-file
list.

## If something breaks

- macOS-specific extension/firewall issues — §6 above.
- Cross-platform connect issues (preauth key format, login-server
  URL, ephemeral vs persistent, what `tailscale up` actually does) —
  [`connect.md`](connect.md).
- Operator-side problems (their control plane is unhealthy, cert
  expired, DERP unreachable) — point them at
  [`docs/operators/tls-rotation.md`](../operators/tls-rotation.md)
  and [`docs/troubleshooting.md`](../troubleshooting.md).
