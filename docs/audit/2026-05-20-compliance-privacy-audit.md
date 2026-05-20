# OctraVPN — Compliance + Privacy Audit (2026-05-20)

> Auditor: compliance-privacy subagent, single-pass walk.
> Head: `11f83a198b7b04e5a79ebc00a238d7326888337a` (worktree
> `agent-ad645ba8961427f56`, branched off `main`).
> Scope: GDPR/CCPA, FinCEN AML/KYC, OFAC, US BIS EAR (ECCN 5D002),
> DMCA §1201, intermediary-liability (NIS2, CDA §230), OSS licence.
> Posture: **lawyer-prep deliverable.** Citations are regulator
> section numbers; nothing here is a legal opinion. "Hire counsel?" —
> yes; ranking at §11.

---

## 1. Executive summary — legal-risk register

Ranked by liability magnitude × probability-of-enforcement. "Magnitude"
is the worst-case sanction (criminal vs. civil vs. injunctive);
"probability" is the probability a regulator notices a mainnet
launch of OctraVPN absent affirmative outreach.

| Rank | Regulation | Hook | Magnitude | Probability | Status |
|----:|------------|------|-----------|-------------|--------|
| **R1** | US FinCEN MSB rules (31 CFR §1010.100(ff)) | Operators receive OCT via `claim_earnings`; OCT is transferable + has a USD spot. Each operator may meet the "money transmission" prong. | Criminal (18 USC §1960) — up to 5 yr per count. Operator-level. | **High**: any onboarded US operator settling > $1k/day in OCT triggers; we have no AML/KYC controls. | **OPEN. Launch-blocker.** |
| **R2** | OFAC sanctions (31 CFR §501, SDN list) | No IP geolocation; no on-chain address screening; operators may relay traffic for, or pay, a sanctioned wallet. | Civil up to $1.5M per transaction; criminal up to 20 yr. Strict-liability. | **High**: a single Iran/NK/Crimea-resident user is statistically likely. | **OPEN. Launch-blocker.** |
| **R3** | EU GDPR (Reg. 2016/679) — §17 right-to-erasure, §32 data-min, §44 cross-border | Audit log + receipt journal write `session_id` to disk; on-chain anchors are permanent; operators are joint controllers under §26. | Up to €20M or 4% global turnover. EU operators in scope automatically. | **Medium-High**: any EU-served session triggers; DSAR requests are mechanically impossible because chain is immutable. | **OPEN.** Documented limitation; lawful basis (legitimate interest under §6(1)(f)) is arguable but not yet documented. |
| **R4** | US BIS — EAR (15 CFR §740.13(e)) + ECCN 5D002 | We ship X25519 / Ed25519 / ChaCha20-Poly1305 / AES-GCM / HFHE in Rust + GPL-isolated PVAC. Public open-source distribution from GitHub. | Civil up to $300k per violation; criminal up to 20 yr (egregious). | **Low**: 740.13(e) "publicly available" / TSU exemption is a strong fit; missing only the e-mail notification. | **OPEN but tractable**: file the 5D002 self-classification + BIS/NSA notice e-mail before tagging mainnet. |
| **R5** | Common-carrier / intermediary-liability (US CDA §230, EU NIS2 + DSA) | Operators are exit nodes; they egress arbitrary traffic. No "operator ToS" or content-policy document exists. | Civil. EU NIS2: "essential entity" obligations + incident-reporting in 24h. | **Medium**: §230 likely covers US operators for user-generated transit; EU DSA Art. 4–6 mere-conduit defence requires posted T&Cs. | **OPEN**: need an Operator ToS template + Acceptable-Use Policy before any operator self-registers. |
| **R6** | EU GDPR — Article 26 joint-controllership | Operator, tailnet-owner, and (arguably) the OctraVPN project each touch personal data. No Art. 26 arrangement exists. | Same envelope as R3; separately enforceable. | **Medium**: enforced reactively (post-DSAR). | **OPEN**: needs a model joint-controller agreement bundled with deploy docs. |
| **R7** | US Travel Rule (FinCEN 31 CFR §1010.410(f)) | OCT settlement transfers > $3k cumulative require originator/beneficiary identity. We have pseudonymous wallets. | Same envelope as R1. | **Low-Medium**: only triggered above threshold; threshold accumulates per-operator. | **OPEN if R1 is open.** Conditional. |
| **R8** | DMCA §1201 anti-circumvention | Product is a privacy VPN. Docs do not promote geo-bypass or DRM-evasion. Risk is reputational + low-probability secondary-liability. | Civil up to $25k per violation. | **Very low**: §1201 targets DRM evasion, not network privacy tools. | **GREEN with a docs caveat** — see §6. |
| **R9** | Open-source licence / IP | Apache-2.0 OR MIT for workspace; GPL-2+ (OpenSSL exception) for `pvac-sidecar/` as a separate executable. Already aisle-walked by the claims audit (`2026-05-20-claims-audit.md`). | Civil; injunctive risk if combined incorrectly. | **Very low**: per-component licences are clean and the GPL isolation is documented in `pvac-sidecar/LICENSE.NOTICE.md`. | **GREEN.** |

**The single most likely launch-blocker** is **R1 (FinCEN MSB
registration)**: every US-resident operator who turns on
`claim_earnings` is, on plain reading of 31 CFR §1010.100(ff)(5)(i)(B),
a money transmitter — even at micro-OCT volumes. The remedy is either
(a) gate US operators behind a registered MSB front-end, (b) restructure
settlement so the chain pays the user and the operator is paid by the
user's wallet directly (no "on behalf of"), or (c) accept that
operators are personally liable and document it in the Operator ToS.
None of those is a code change; all of them are a counsel decision.

---

## 2. Privacy data inventory

Trace of every JSON record the operator daemon writes to disk or
broadcasts off-process. Identifiers are flagged as **direct PII**,
**pseudonymous identifier** (reversible only by a party that already
has off-chain context), or **non-identifier**.

### 2.1 Operator-daemon disk artifacts

| Artifact | Path (default) | Schema | Identifier content | Retention | Where it goes |
|---|---|---|---|---|---|
| **Audit log** | `<state>/audit/audit-YYYY-MM-DD.jsonl` | `ChainedLine { record_json, prev_mac, mac }` wrapping `AuditRecord { ts_unix, kind, source, session_id, extra }` (see `crates/octravpn-node/src/audit/log.rs:23-48`) | `source` is **None** in every production emit site (verified across `control/handlers/session.rs`, `control/handlers/receipt.rs`, `audit_cli.rs`, `cli_ops.rs` — the field is reserved and only populated in unit tests). `session_id` (32-byte hex) is a **pseudonymous identifier** — links the announce + every receipt for one session. `extra.bytes_used` + `extra.seq` are non-identifiers. | **No automated retention.** Operator must manage rotation manually. Files persist indefinitely. | Local disk only. HMAC-chained for tamper-evidence; the HMAC key is `.audit.key` in the same dir (`audit/chain.rs`). |
| **Receipt journal** | `<state>/receipts.bin` | v1 binary: `[magic:8][record:44]*`; each record is `[session_id:32][seq:u64 BE][crc:u32 BE]` (see `crates/octravpn-core/src/receipt_journal/codec.rs`) | `session_id` only. No wallet, no IP. The journal is a **per-session monotonic-seq floor** for forced-restart protection (P1-8/9); it carries no `bytes_used`, no timestamps, no user identifier. | Compacted automatically when file exceeds `DEFAULT_COMPACTION_WATERMARK` (≈ 10 MB); compaction collapses duplicates per `session_id`. | Local disk only. |
| **Analytics indexer DB** | configurable; bucketed by `octravpn-analytics` | `AnalyticsEvent` enum (`crates/octravpn-analytics/src/event.rs:38-69`) — typed projection of the audit log | `session_id` per-event, `bytes_used` per-event, `ts_unix`. **Pseudonymous identifier** at per-event granularity (same as audit log); aggregated counters on top are non-identifiers. | Indexer is fed from the audit tap — same retention as the audit log unless the operator buckets it. | Local Prometheus / Grafana surface; tap-receiver runs in-process. |
| **Members.json** | sealed asset at `oct://<tailnet-owner-circle>/tailnet-{id}/members.json` | See `docs/v3-members-schema.md`. Fields: `wallet` (Octra address), `wg_pubkey_b64`, `joined_epoch`, `ip_salt`. | `wallet` is a **pseudonymous identifier** (a public key) but globally linkable across the chain via tx history. `wg_pubkey_b64` identifies a device. `ip_salt` lets the tailnet-owner derive each member's tailnet IP. | No automated retention; tailnet-owner manages. | Stored sealed (AES-GCM under owner key) inside a Circle on-chain; SHA-256 anchor is on-chain immutably. **Cross-border**: any chain replica replicates the anchor; the sealed body is fetchable only by Circle-authorized callers. |
| **Operator key material** | `<state>/keys/operator.sk` (Ed25519) + `keys/operator.box` (sealed at-rest under `OCTRAVPN_KEY_PASSPHRASE`) | See `docs/v2-operator-key-hygiene.md` | The operator's wallet pubkey IS the operator's on-chain identity. Not user PII. | Until rotation (`docs/maintenance/operator-rotation.md`). | Local only. |
| **Headscale / tailnet-wire state** | `<state>/headscale-bridge/...` | `MachineRecord` (in `headscale-api::tailscale_wire`) — captures hostname + Tailscale-allocated 100.64/10 IP + machine pubkey | Hostname = **direct PII** if user supplied a personal hostname (e.g. "andrews-iphone"). Machine pubkey = **device identifier**. CGNAT IP = pseudonymous per-tailnet. | Until `delete_machine`. | Local disk; not chain-anchored. |
| **MagicDNS membership cache** | in-memory only (`crates/octravpn-mesh/src/magic_dns.rs`) | `(tailnet_id, hostname) -> Ipv4Addr` | Hostname = potential direct PII. | Process lifetime. | Memory only. |

### 2.2 On-chain artifacts (immutable)

| Artifact | Where | Identifier content | Why it's immutable |
|---|---|---|---|
| `open_session` tx | mainnet | `from = client_wallet`, `to = circle_id`, `session_id` (32-byte) | Octra chain semantics. Permanent. |
| `settle_session` tx | mainnet | `operator_circle_id`, `bytes_used` (v1.1: plaintext; v2: HFHE-encrypted; v3: SHA-256 hash anchor) | Permanent. |
| `claim_earnings` tx | mainnet | `operator_address`, ledger Pedersen commitment delta | Permanent. |
| `tailnet_members_root[tid]` | main-v3 | SHA-256(canonical members.json) | Permanent; preimage is the sealed members.json. |
| Receipt SSE event | in-process bus | `session_id`, `seq`, `bytes_used` | Ephemeral but observable to any local subscriber (operator dashboard). |

### 2.3 What the operator does NOT collect

(Listing these so the lawyer can write affirmative "we do not process X"
defences.)

- **No client source IP** is ever logged. The audit `source` field
  exists in the struct but is populated `None` in every production
  call site. The control plane authenticates by announce-signature,
  not by IP — and the WireGuard tunnel forwards raw bytes without
  per-packet attribution.
- **No DNS query content.** MagicDNS handles only `<host>.<tailnet>.octra`
  lookups against the in-memory table; everything else is forwarded
  to the OS resolver and is not logged by us.
- **No deep-packet inspection.** Onion-router / tunnel modules forward
  the WireGuard payload opaquely.
- **No payment-card data.** All settlement is on-chain in OCT; there
  is no fiat rail in the operator daemon.

---

## 3. GDPR mapping + user-rights gaps

### 3.1 Lawful-basis catalogue

For every personal-data processing op, the only candidate Art. 6 basis
is **legitimate interest (Art. 6(1)(f))**. Consent (6(1)(a)) doesn't
fit — joining a tailnet is not informed consent to audit. Contract
(6(1)(b)) needs a written operator↔user agreement we don't have today.
The project must be ready to defend an LIA per EDPB guidance:

| Processing | Necessary for? | Less-intrusive alternative? |
|---|---|---|
| Audit log `session_id` + `bytes_used` | Settlement + dispute (chargeback-equivalent). | None — `session_id` is the only handle linking client + on-chain `settle_session`. |
| Receipt journal `(session_id, seq)` | Anti-double-sign (slash-protection invariant P1-8/9). | None — restart safety requires persistent floor. |
| Analytics indexer per-event | Operator capacity planning + invoicing. | Bucketing to ≥ 1h windows would still answer most questions. **Recommendation: ship a "privacy mode" that disables per-event indexing.** |
| Headscale `MachineRecord` (hostname + IP) | Tailnet membership + MagicDNS. | Allow opt-out of hostname (default to `node-<short-pubkey>`). |

### 3.2 §17 right-to-erasure: known limitation

**The chain is immutable.** A §17 erasure request cannot remove a
`session_id` from on-chain `settle_session`. Two mitigations:

1. On-chain identifier is `session_id` (32 random bytes), not the
   client wallet directly — wallet only appears in
   `open_session(from=...)`. A user can rotate wallets to break
   forward-linkability; past sessions remain.
2. Off-chain artifacts (audit log, receipts.bin, indexer DB) CAN be
   redacted on operator request. Tooling missing — recommend
   `octravpn-node audit redact --session <id>` that rewrites the
   chained log to a tombstone (preserves the HMAC chain via a
   "redacted" record kind). **Open task.**

`docs/audit/known-limitations.md` does not currently mention GDPR
— add an entry tying "immutable receipts" to "§17 partial-compliance".

### 3.3 §32 data-min / security of processing

- HMAC-chained audit log: covered.
- Sealed assets (AES-GCM, PBKDF2-SHA256-120k): covered.
- Operator key at-rest sealing under passphrase: covered
  (`docs/v2-operator-key-hygiene.md`).
- TLS for control plane: required by deploy docs (operators front
  with a TLS terminator).
- **Gap**: no documented breach-notification SLA per §33 (72h).
  Recommend a paragraph in the Operator ToS template.

### 3.4 §26 joint-controllership

The project + each operator + each tailnet-owner all decide some
purpose of processing. A bare-minimum Art. 26 arrangement names a
single point-of-contact and divides the response obligation for
DSARs. **Open task**: ship a template at
`docs/operators/joint-controller-arrangement.template.md`.

### 3.5 §44 cross-border transfer

An EU operator serving a US tailnet-owner ships sealed `members.json`
across the Atlantic; US chain replicas hold the SHA-256 anchor.
Art. 44 et seq. needs one of: Art. 45 adequacy (EU-US DPF; tenuous
post-Schrems II), SCCs (Standard Contractual Clauses), or an Art. 49
derogation (fragile). **Recommendation**: bundle SCCs into the
Operator ToS, or geo-fence operator participation per chain region.

### 3.6 CCPA (Cal. Civ. Code §1798.100 et seq.) delta

CCPA's "personal information" is broader than GDPR's; the hostname +
machine_key in `MachineRecord` qualifies. We do not sell PI →
§1798.135 is moot. The §1798.100 disclosure ("at or before collection")
is **OPEN** — no privacy notice in user docs.

---

## 4. AML / KYC analysis

### 4.1 Is OctraVPN a money services business?

US FinCEN, 31 CFR §1010.100(ff): an MSB includes a "money transmitter":

> "(A) a person that provides money transmission services. The term
> 'money transmission services' means the acceptance of currency,
> funds, or other value that substitutes for currency from one
> person and the transmission of currency, funds, or other value
> that substitutes for currency to another location or person by
> any means."

Three candidate "persons" who might be the transmitter:

| Candidate | Does it accept value? | Does it transmit to another person? | MSB? |
|---|---|---|---|
| **The Octra chain itself** | Yes (it holds OCT escrow during `open_session`) | Yes (`settle_session` debits client treasury, credits operator ledger) | FinCEN has historically declined to call peer-to-peer software an MSB (see 2013 Virtual Currency Guidance + 2019 supplement), but the line is fact-dependent. **Likely no** for the protocol per se. |
| **The OctraVPN GitHub maintainers** | No (we don't custody) | No | **No.** |
| **Each operator** | Yes (escrow-bonded OCT in their circle) | Yes (`claim_earnings` moves OCT into the operator's wallet from a pool that is, at least in part, contributed by users) | **Almost certainly yes** under FinCEN's 2019 guidance §4.5.1 (anonymising service providers / unhosted-wallet operators). Each individual operator IS an MSB when they "claim" from value contributed by a user they don't know. |

The 2013 Guidance carve-out for "users" (people who just spend their
own crypto) does not apply because an operator is being paid for a
service by third-party users.

### 4.2 What an MSB-classified operator must do

If §4.1 holds (counsel to confirm):

1. **Register with FinCEN** via BSA E-Filing (RMSB) within 180 days
   of first transmission.
2. **State licences**: 49 of 50 US states require a money-transmitter
   licence separately (NY BitLicence is the toughest). This is *the*
   friction — exchanges spent 1-2 years + $1M+ on it.
3. **Customer Identification Programme (CIP)**, 31 CFR §1022.210:
   collect name + DOB + address + ID for any user > $3k cumulative.
   OctraVPN has *no* identity controls today.
4. **Suspicious Activity Reports**, 31 CFR §1022.320: file within
   30 days of detecting a ≥ $2k suspicious tx. No tooling.
5. **Currency Transaction Reports**, 31 CFR §1022.310: file for
   cash-equivalent > $10k. Unlikely per-session but cumulative.
6. **OFAC sanctions screening** of every counterparty.
7. **Travel Rule**, 31 CFR §1010.410(f): for ≥ $3k transmissions,
   include originator name + address + account in the order.
   On-chain OCT carries only the address — the IVMS-101 problem
   the rest of crypto is still solving.

### 4.3 Jurisdictions other than US

- **EU MiCA (Reg. 2023/1114)**: CASP authorisation needed for
  third-party OCT transfer services (Art. 60); transition ended
  Q3 2025. **Open** — may need to geo-block EU operators pre-CASP.
- **UK FCA**: cryptoasset registration under MLR 2017 (as amended).
- **Singapore MAS**: Payment Services Act 2019 (DPT service licence).
- **Switzerland FINMA**: FMIA financial-intermediary registration.

### 4.4 Travel-rule technical gap

Even with out-of-band KYC, conveying IVMS-101 to the counterparty has
no standard in v3. **Recommendation**: post-launch task — most
operators stay below $3k threshold; at scale, protocol needs an
off-chain travel-rule channel.

---

## 5. Sanctions + export control

### 5.1 OFAC sanctions screening (31 CFR §501 et seq.)

OFAC is **strict-liability** — intent is irrelevant; a single
sanctioned-country IP in service surface is a violation.

**Current posture**: zero controls.
- No IP geolocation (verified: `control/handlers/` does not capture
  client IP).
- No on-chain SDN-wallet screening (OFAC has listed wallet addresses
  since the 2022 Tornado Cash action).
- No country-block on the GitHub release page.

**Minimum remediation before mainnet**:
1. Client-side ToS click-through naming OFAC SDN countries +
   listed-individuals SDN list, with user representation of non-coverage.
2. Operator-side: IP-geolocation gating against comprehensive-sanctions
   countries (Cuba, Iran, North Korea, Syria, occupied regions of
   Ukraine). Currently we capture no client IP — code change required.
3. On-chain: SDN-wallet block-list embedded in operator-circle policy
   (lists from Chainalysis / TRM). Tooling required.

### 5.2 US BIS / EAR (15 CFR Parts 730-774)

Crypto in scope: ECCN **5D002** (cryptographic information-security
software) — what we ship under `crates/octravpn-core/`, `crates/octravpn-node/`,
`pvac-sidecar/`. Specifically:

- X25519 + Ed25519 (curve25519-dalek): asymmetric, > 56 bit symmetric
  equivalent → 5A002.a.1 / 5D002.a.1.
- ChaCha20-Poly1305 (chacha20poly1305 0.10.1): 256-bit symmetric →
  5A002.a.1.
- AES-256-GCM (sealed-asset envelope, "OCRS1"): 256-bit symmetric.
- HFHE / PVAC (vendor/pvac, GPL-2+): post-quantum-style FHE; novel
  but still classifiable under 5D002 in absence of a TSU exemption.

**Available exemptions**:
- **15 CFR §734.3(b)(3)** "publicly available" carve-out — open-source
  released publicly is **not** subject to the EAR. Primary defence.
- **15 CFR §740.13(e)** "publicly available encryption source code" —
  one-time e-mail to BIS + NSA naming the source URL. §740.13(e)(3)
  requires it PRIOR to or AT the time of release.
- **15 CFR §740.17 (ENC)** — covers binaries (5D992.c) under
  §740.17(b)(1). Requires one-time **Encryption Registration Number
  (ERN)** via SNAP-R.

**Recommendation**: file BOTH §740.13(e) notification (source) AND
§740.17(b) ERN (binaries: `.deb`/`.rpm`/`.msi`/`.pkg`). 1-2 day task;
failure-to-file is a 5-year SoL civil exposure.

**Restricted destinations**: Country Group E:1 (Cuba, Iran, NK, Syria)
prohibited even with exemptions — same geo-block as OFAC §5.1.

**China / Russia**: §744.6 FDP rule post-2022 has crypto carve-outs.
Open-source distribution to non-government end-users generally OK;
contracting with a Chinese SOE is not. Document "open-source project,
no foreign-government end-user contracts" posture.

### 5.3 Wassenaar / "intrusion software" (Cat. 4A005 / 4D004)

OctraVPN is NOT intrusion software (the EAR definition centres on
exploitation of vulnerabilities). Mention this affirmatively in any
BIS filing to pre-empt the question.

---

## 6. Anti-circumvention language sweep

DMCA §1201 (17 USC §1201) prohibits "circumvention of technological
measures that effectively control access to a work" — designed for
DRM. A privacy VPN is squarely outside that target absent marketing
language that pitches the product as a DRM/geo-bypass tool.

### 6.1 Findings

I grep'd `README.md`, `docs/value.md`, `docs/whitepaper.md`,
`docs/users/*.md` (the user-facing surface) for the canonical
red-flag terms: `netflix`, `streaming`, `geo-block`, `geoblock`,
`bypass.*region`, `hide.*location`, `access.*restricted`, plus
softer signal terms `circumvent`, `censorship`, `anonymity`,
`surveillance`.

| Finding | File:line | Severity | Recommendation |
|---|---|---|---|
| `docs/value.md:104` — "Censorship — one government can lean on one company." | docs/value.md | LOW: framed as a property of centralised VPNs, not as a feature of OctraVPN. | Keep. Maybe soften to "Single points of failure — one government can lean on one company." |
| `docs/users/exit-node.md` — neutral mechanics doc ("hide your egress IP behind someone else's connection") | docs/users/exit-node.md | LOW: standard VPN-functionality description. | Keep. Add a paragraph: "OctraVPN exit nodes provide privacy of egress; they are not designed to circumvent content licences, paywalls, or DRM. Use of an exit node to evade access controls of a third party is the user's responsibility." |
| Operator docs | docs/operators/* | NONE | Operator-side docs are technical; no circumvention pitch. |
| Whitepaper | docs/whitepaper.md | NONE | Cryptography + economics; no marketing. |

### 6.2 Verdict

The repo currently has **no language that promotes circumvention of
access controls** in the §1201 sense. The minor recommendation is to
add a single explicit "not a DRM/geo-restriction circumvention tool"
disclaimer somewhere on the user-docs landing page. Low priority.

The EUCD (EU Directive 2001/29/EC Art. 6) analogue is comparable; the
same disclaimer covers it.

---

## 7. Operator-liability model

### 7.1 The mere-conduit question

Exit nodes carry arbitrary user traffic. Frameworks exempting the
operator require "mere conduit" status:

- **US**: 47 USC §230(c)(1) (civil claims from user content); 17 USC
  §512(a) DMCA mere-conduit safe-harbour. §512(a) five-prong test —
  (i) user-initiated, (ii) automated, (iii) no recipient selection,
  (iv) no extra-retention copy, (v) unmodified content — satisfied
  by an OctraVPN exit.
- **EU**: e-Commerce Dir. 2000/31/EC Art. 12, now DSA (Reg. 2022/2065)
  Art. 4. Same five-prong test.
- **EU NIS2 (Dir. 2022/2555)**: 24h early-warning / 72h incident-
  notification. Operator likely an "important entity" under Annex II
  — counsel to confirm. **Open task**: incident-notification SOP.

### 7.2 Operator ToS template — required sections

A model Operator ToS must cover:
1. **Service definition** — "exit/relay node forwarding encrypted
   traffic; no inspection / modification / selection".
2. **AUP** — no CSAM, no OFAC counterparties, no third-party
   access-control evasion.
3. **DMCA §512(c) designated agent** for takedown (operator-website,
   not wire — list defensively).
4. **Limitation of liability** — no uptime / content warranty.
5. **Privacy notice** — what is logged (`session_id`, `bytes_used`,
   `seq`; see §2.1); what is not (no IP, no DNS, no DPI).
6. **GDPR Art. 26 joint-controller statement** (by reference).
7. **Operator-jurisdiction declaration** — which jurisdictions
   served.
8. **OFAC representation** — geo-block comprehensive-sanctions
   countries as tooling enables.

**Open task**: ship as `docs/operators/operator-tos.template.md`.

### 7.3 Tailnet-owner liability

A tailnet-owner is closer to a "system administrator" than a service
provider. They control `members.json` and decide who joins. Their
liability surface is the standard system-administrator one: GDPR
controller in respect of `members.json`, no MSB exposure (they don't
custody user payments), no §1201 exposure absent promotion.

The tailnet-owner ToS template (companion to the operator one) needs
only the GDPR notice + an acceptable-use-policy passthrough.

---

## 8. Open-source licence + IP (delta from Audit-7)

The earlier `2026-05-20-claims-audit.md` walked the licence terrain;
the legal-relevant summary:

- **Workspace**: dual-licensed Apache-2.0 **OR** MIT
  (`LICENSE-APACHE`, `LICENSE-MIT`, root `LICENSE`). Downstream picks
  whichever they prefer — the canonical permissive-Rust posture.
- **`pvac-sidecar/`**: GPL-2.0-or-later **with the OpenSSL
  exemption** (the C++ PVAC fork it vendors carries that grant
  upstream). Shipped as a **separate executable** with its own
  GPL-2 LICENSE file; communicated to from `octravpn-node` via Unix-
  domain-socket IPC only. The boundary is documented in
  `pvac-sidecar/LICENSE.NOTICE.md` and enforced by the lack of any
  build-time link between the two artifacts.
- The GPL-2 propagation argument hinges on "separate executable +
  arms-length IPC". GPL FAQ ("What is the difference between an
  aggregate and other kinds of modified versions?") supports this
  reading; one Stallman opinion piece would prefer a stricter line,
  but the case law (e.g. Free Software Foundation v. Cisco settlement,
  2009; Versata v. Ameriprise, 2014) accepts the separate-executable
  boundary in practice.

**Recommendation**: include the licence notice + the separate-executable
argument in the BIS 740.13(e) source-availability filing too, so the
crypto-exemption rationale aligns with the licence story.

---

## 9. Recommendations — ranked legal moves before mainnet

In landing order. Each is a counsel-input task, not (with one
exception) a code task. Bracketed `[CODE]` flags items that also need
implementation work.

1. **Engage a US fintech / crypto regulatory lawyer**. The R1 (MSB) +
   R2 (OFAC) + R7 (Travel Rule) cluster is the launch-blocker and
   only counsel can credibly draw the line between "the chain is the
   MSB" / "each operator is an MSB" / "no one is an MSB". Without a
   memo on this point, a US mainnet launch is reckless. **Critical.**
2. **File US BIS 740.13(e) notification** for source-code + SNAP-R
   ERN for binaries. Administrative; 1-2 days; closes R4. **High.**
3. **Draft + ship Operator ToS template + AUP** (`docs/operators/operator-tos.template.md`).
   Closes R5 + R6 partial + R8 disclaimer. **High.**
4. **Draft + ship Tailnet-Owner ToS + GDPR notice** (`docs/tailnet-owners/tailnet-owner-tos.template.md`).
   Closes R6 partial. **High.**
5. **Draft + ship user-facing privacy notice** at `docs/users/privacy.md`
   linked from the install flow. Closes CCPA §1798.100 + GDPR
   Art. 13. **High.**
6. **[CODE] Implement `octravpn-node audit redact --session <id>`**
   that rewrites the chained audit log + indexer DB to tombstone a
   given `session_id` while preserving the HMAC chain (record a
   "redacted" envelope, MAC over the tombstone). Closes GDPR §17
   partially. **Medium.**
7. **[CODE] Implement OFAC geo-gate at the operator daemon.** Read
   the client's tunnel endpoint IP, geolocate (offline MaxMind GeoLite
   or equivalent), reject sessions from E:1 destinations. Closes R2
   partial. **Medium.** Counsel must confirm the strict-liability
   posture is acceptable as mitigated.
8. **Engage an EU data-protection lawyer** for the SCC + Art. 26
   model arrangement + MiCA CASP analysis. **Medium.**
9. **Engage an international-trade lawyer** for the BIS filings (if
   #2 is not done by us) + the China/Russia destination analysis. Can
   be the same firm as #1 in larger shops. **Medium.**
10. **Add a single-line DRM/geo disclaimer** to `docs/users/README.md`
    and the public website. Closes R8 hygiene. **Low.**
11. **[CODE] Disable analytics indexer per-event granularity by
    default**; require operator opt-in or window-bucket to ≥ 1h.
    Closes GDPR §32 data-min posture. **Low.**

---

## 10. Honest assessment — clear vs. murky

**Clear** (counsel will agree):
- R4 (BIS) — §740.13(e) fits; filing is cheap.
- R8 (DMCA §1201) — privacy VPN, no DRM-evasion promotion: green.
- R9 (licence) — Apache/MIT + GPL-isolated PVAC is clean.
- §2 data-inventory — verified against code paths.

**Murky** (reasonable people disagree):
- R1 (FinCEN MSB) — plain reading of 2019 guidance says operator IS
  an MSB; protocol-as-such defence (FinCEN's reluctance to label
  decentralised software) cuts the other way. No precedent for a
  permissionless OCT-settled VPN.
- R3 (GDPR §17) — "chain is immutable; operator redacts off-chain
  mirror" partial-compliance posture is untested in EDPB enforcement.
  Worst case: affirmative chain-fork demand. Intractable.
- R5 (DSA mere-conduit) — small operators; whether they are
  "providing service in the Union" is fuzzy.

**The one question the audit cannot resolve**: whether the project
qualifies for a "decentralised software / no operator" carve-out as
Bitcoin protocol developers have. Turns on (a) upgrade-key control,
(b) whether maintainers run validators, (c) foundation / token-treasury
existence. These are organisational-design decisions, not regulatory
questions — a lawyer must shape them.

---

## 11. Report summary (for the orchestrator)

- **Commit hash audited**: `11f83a198b7b04e5a79ebc00a238d7326888337a`.
- **Top 3 legal risks (ranked)**:
  1. US FinCEN MSB classification of operators (criminal, strict).
  2. OFAC sanctions exposure (strict-liability, no IP gating today).
  3. GDPR Art. 17 + Art. 26 + Art. 44 cluster (large civil envelope, immutable-chain limitation).
- **Most likely launch-blocker**: FinCEN MSB registration. Without
  counsel's go-ahead on either (a) operator-as-MSB requiring KYC
  before any US operator turns on `claim_earnings` or (b) a
  decentralised-protocol carve-out memo, a US mainnet launch is the
  single largest unmitigated legal exposure in the project.
- **Counsel to engage, in order**:
  1. **US fintech / crypto-regulatory lawyer** (FinCEN MSB + OFAC + state MTLs). Highest priority.
  2. **EU data-protection lawyer** (GDPR Art. 17 / 26 / 44, MiCA CASP).
  3. **International-trade lawyer** (BIS 5D002 + EAR §740.13(e) + §740.17). Cheapest; can be folded into #1 at a full-service firm.
  4. **IP / open-source counsel** is **not** needed at launch; current licence posture is clean.
