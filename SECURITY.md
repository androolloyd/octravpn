# Security Policy

OctraVPN handles real OCT stake and routes user traffic. Vulnerability
reports are taken seriously and rewarded.

## Reporting a vulnerability

**Do not open a public GitHub issue** for a security report. Instead:

1. Email **`security@octra.org`** (or `dev@octra.org` if no security
   alias is set up yet) with:
   - A description of the vulnerability.
   - Steps to reproduce (proof of concept welcome).
   - Affected versions and components.
   - Suggested fix or mitigation if you have one.
2. Optionally encrypt with our PGP key, fingerprint:
   `<pending — see https://octra.org/security.asc>`.

You'll receive an acknowledgement within **48 hours** and a triage
decision within **5 business days**.

## Scope

In scope:

- Anything in this repository (`program/main.aml`, the Rust crates,
  the install scripts, the deployment harness).
- Released binaries (`octravpn`, `octravpn-node`, `octra`).
- Released container images and packages.

Out of scope:

- Bugs in the Octra chain itself (report to Octra Labs).
- Bugs in upstream dependencies (`boringtun`, `curve25519-dalek`,
  `tun-rs`, etc.) unless we mis-use them.
- Issues that require physical access to a node operator's machine.
- Denial-of-service against a single node operator's public RPC.

## What counts as a vulnerability

| Class | Examples |
| --- | --- |
| **Critical** | Fund-stealing from program escrow; signature forgery; bond bypass; permanent program corruption |
| **High** | Slashing avoidance; receipt unforgeability break; cross-tx replay; client/exit-node identity leak during a session |
| **Medium** | Sweep-bypass; metric spoofing; DoS that scales beyond one node |
| **Low** | Crash bugs without state corruption; information disclosure of non-sensitive data |
| **Informational** | Best-practice violations; documentation errors |

## Disclosure timeline

1. **T+0**: Report received.
2. **T+5d**: Triage decision communicated to reporter.
3. **T+30d** (typical): Fix shipped in a tagged release.
4. **T+60d** (typical, longer for critical): Coordinated public
   disclosure.

If a vulnerability is being actively exploited we'll disclose
faster; if it requires upstream changes (e.g. in Octra's chain) the
timeline extends.

## Bounty

There is no formal bug-bounty program at v1. Critical reports may
receive an ad-hoc bounty from the slashing treasury (see
`docs/governance.md`).

## Hall of fame

Reporters who consent will be listed at
`https://github.com/octra-labs/octravpn/blob/main/SECURITY-HALL-OF-FAME.md`.

## Out-of-band: emergency response

If you discover an actively-exploitable critical vulnerability:

1. Email `security@octra.org` with `[URGENT]` in the subject.
2. Tag `@octra-labs/security` on Discord / Telegram for an
   out-of-band channel.
3. We will coordinate an emergency `set_paused(1)` if necessary
   (see `docs/governance.md` § Emergency Response).

## Threat model

See `docs/security.md` § 1 for the full threat model. Short version:

- Dolev-Yao network attacker.
- Long-term-key compromise of validators and clients.
- Honest-majority validator set (Octra consensus assumption).
- Out of scope: side channels on operator hardware; supply-chain
  attacks on upstream dependencies.
