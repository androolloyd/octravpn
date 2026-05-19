# OctraVPN release runbook

This is the operator-facing guide for cutting an OctraVPN release.
The CI lane lives at [`.github/workflows/release.yml`](../.github/workflows/release.yml)
and the cargo-deb / cargo-generate-rpm metadata lives at
[`crates/octravpn-node/Cargo.toml`](../crates/octravpn-node/Cargo.toml).

Scope is Linux x86_64 + aarch64 only. Windows + macOS artifacts and
OCI containers are deferred — see the top of `release.yml` for the
out-of-scope list.

## 1. Cut a release

```sh
# Bump workspace version in /Cargo.toml first if it isn't already,
# then commit + tag. The tag MUST match `v<semver>`.
git tag -s v0.1.0 -m "OctraVPN 0.1.0"
git push origin v0.1.0
```

Pushing a `v*` tag fires the `Release` workflow. Tag-push only — no
on-demand dispatch — to make it obvious that the only way a release
artifact gets produced is by an authenticated tag push.

## 2. What CI does

For each Linux target (x86_64, aarch64):

1. Builds release binaries for `octravpn-node` + `octravpn-client`.
2. Runs `cargo deb -p octravpn-node --no-build`, producing
   `octravpn-node_<version>-1_<arch>.deb`.
3. Runs `cargo generate-rpm -p octravpn-node`, producing
   `octravpn-node-<version>-1.<arch>.rpm`.
4. Tars the two binaries plus README + LICENSE into
   `octravpn-<version>-<target>.tar.gz`.
5. If a GPG signing key is configured (see §5), produces a
   `<artifact>.sig` armored detached signature next to each artifact.
6. Generates a per-target `SHA256SUMS-<target>` line set.

The publish job:

7. Downloads every matrix artifact.
8. Merges all per-target SHA256SUMS lines into a single `SHA256SUMS`.
9. Generates a markdown changelog from
   `git log <prev-tag>..HEAD --no-merges`.
10. Creates a **draft** GitHub release with the artifacts attached,
    titled with the tag name.

The release is created as a **draft** — nothing is public until the
operator manually flips it to "Published" via the GitHub UI. This
gives the operator a chance to review the auto-generated changelog
before users see it.

## 3. Publish the draft

1. Go to <https://github.com/octra-labs/octravpn/releases> and click
   into the draft for `v<version>`.
2. Sanity-check the artifact list — there should be, for each of
   `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`:
   - `octravpn-<version>-<target>.tar.gz` (+ optional `.sig`)
   - `octravpn-node_<version>-1_<arch>.deb` (+ optional `.sig`)
   - `octravpn-node-<version>-1.<arch>.rpm` (+ optional `.sig`)
   plus one consolidated `SHA256SUMS`.
3. Edit the generated changelog if a release-blocker or rollback
   note needs to be called out.
4. Click **Publish release**.

If something looks wrong (missing artifact, wrong target, etc.) —
delete the draft, fix the issue, force-push the tag (rare; usually
better to cut a fresh `v0.x.(y+1)` tag), and re-run.

## 4. Operator install

### Debian / Ubuntu

```sh
sudo dpkg -i octravpn-node_<version>-1_<arch>.deb
sudo systemctl edit /etc/octravpn/node.toml   # operator-supplied config
sudo systemctl start octravpn-node.service
sudo systemctl status octravpn-node.service
```

The postinst hook creates the `octravpn` system user, lays out
`/etc/octravpn` (0750), `/var/lib/octravpn` (0700), and
`/var/log/octravpn` (0750), grants the binary `CAP_NET_ADMIN` +
`CAP_NET_BIND_SERVICE` via `setcap`, and `systemctl enable`s the unit
without starting it. The operator MUST drop a `node.toml` before
the first start — `octravpn-node` refuses to run without it.

### RHEL / Fedora / Rocky / Alma

```sh
sudo rpm -i octravpn-node-<version>-1.<arch>.rpm
sudo systemctl start octravpn-node.service
```

Same post-install setup as the deb (the `[package.metadata.generate-rpm]`
`post_install_script` mirrors the debian `postinst`).

### Tarball

```sh
tar -xzf octravpn-<version>-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 octravpn-<version>-*/octravpn-node    /usr/local/bin/
sudo install -m 0755 octravpn-<version>-*/octravpn-client  /usr/local/bin/
```

Tarball installs do NOT set up users, systemd units, or `setcap` — use
the deb/rpm unless you're running under a config management system
that handles those itself.

## 5. GPG signing — enabling the signed-artifact path

The `gpg` block in `release.yml` is gated on `secrets.RELEASE_GPG_KEY`
being set. While it's unset, the workflow still runs and produces
unsigned artifacts. To enable signing:

1. Generate (or repurpose) an ed25519 release key offline. Use a
   subkey so you don't have to expose the primary signing identity.
2. Export the armored secret:

   ```sh
   gpg --armor --export-secret-keys <KEYID> | base64 -w0 > release-key.b64
   ```

3. Add two repo secrets under
   `Settings → Secrets and variables → Actions`:
   - `RELEASE_GPG_KEY` ← contents of `release-key.b64`
   - `RELEASE_GPG_PASSPHRASE` ← key passphrase
4. Publish the corresponding **public** key:
   - As a release asset on a pinned `v0.0.0-signing-key` release, OR
   - On the project website at
     `https://octra.org/keys/octravpn-release.asc`
5. Document the fingerprint in this file (below) so operators have a
   pinned reference.

### Current signing key

| Field        | Value                                              |
| ------------ | -------------------------------------------------- |
| Fingerprint  | _UNSET — populate when the key is generated._       |
| Key URL      | _UNSET — populate when the key is published._       |
| Algorithm    | _Recommendation: ed25519 / cv25519 subkey._        |

## 6. Verifying a release

```sh
# 1. Import the OctraVPN release public key.
curl -fsSL https://octra.org/keys/octravpn-release.asc | gpg --import

# 2. Verify the signature on the tarball / deb / rpm.
gpg --verify octravpn-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sig \
              octravpn-0.1.0-x86_64-unknown-linux-gnu.tar.gz

# 3. Cross-check the SHA256SUMS file (also signed).
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

`gpg --verify` should print `Good signature from "OctraVPN release"`
with the fingerprint matching the one in §5. Any other output —
"NOT a detached signature", "BAD signature", an unexpected
fingerprint — means **do not install the artifact**, raise the
incident in `#octravpn-ops`.

## 7. Punted (deferred follow-ups)

- **Windows + macOS release artifacts** — the existing
  `deploy/windows/` + `deploy/macos-pkg/` trees ship the historical
  builders, but cross-compile from an Ubuntu runner needs MSVC build
  tools (Windows) and Xcode codesigning identities (macOS). Owner:
  TBD.
- **OCI container images** — `ghcr.io` publishing belongs in a
  follow-up `oci.yml` workflow; out of scope here.
- **Homebrew tap** — `deploy/homebrew/` has a formula skeleton; tap
  publishing is gated on a published macOS artifact, which is
  deferred above.
- **SBOM publishing** — CycloneDX SBOMs are not yet attached. The
  prior workflow had a `sbom` job; it'll come back once the
  signed-artifact path lands.
