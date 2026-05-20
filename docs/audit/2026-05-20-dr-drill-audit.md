# Disaster Recovery Drill Audit — OctraVPN

**Date:** 2026-05-20
**Audited HEAD:** `4495dec0d1c67b498a24196041f1b906c1fc058d`
**Scope:** validate `docs/maintenance/{recovery,rotation-master,audit-verify}.md`
against eight failure scenarios.
**Methodology:** static review of recovery runbooks against shipped
sources (`crates/octravpn-{core,node}/src/...`), operator shell scripts
(`scripts/operators/*`), and the docker harness; partial live execution
of `rotate-pvac.sh` end-to-end on this host; rest are documented dry-runs
against the actual code paths.

> A full live drill requires the docker devnet stack + a built
> `octravpn-node` CLI on `PATH`; neither is provisioned on the audit
> host. For drills needing the daemon I cite the command shape the
> operator runs + the code path that executes.

## 1. Executive summary

| # | Drill | Pass/Fail | RTO | Doc agrees? |
|---|---|---|---|---|
| 1 | State wipe → restore | PASS\* | ≈3 min | partial: rebuild-CLI gap (doc flags it UNVERIFIED) |
| 2 | Sealed-key compromise / passphrase rotation | PASS | ≈5 min | accurate |
| 3 | Network outage / RPC unreachable | PASS | ∞ tolerance | **DOC GAP** — running-loop behavior undocumented |
| 4 | PVAC pubkey rotation (dry-run) | PASS (steps 1-2 live, 3-5 walked) | ≈10 min + 24 h | accurate |
| 5 | Audit-log chain break | PASS | ≈2 min | accurate (best runbook in tree) |
| 6 | Receipt-journal CRC corruption (mid-record) | FAIL on RTO | ≥30 min | doc flags UNVERIFIED but lacks byte layout |
| 7 | `kill -9` mid-receipt-sign | PASS (journal) / PARTIAL (audit) | ≈1 min | **DOC GAP** — audit-flusher window undocumented |
| 8 | Backup + restore on fresh host | PASS with caveats | ≈10 min | accurate |

**Worst scenario:** drill #6 — no shipped CLI to rebuild a corrupted
journal; manual hex work, ≥30 min RTO, with material risk of an
operator just deleting the journal and exposing themselves to chain
equivocation slashing.

**Most-load-bearing off-site backup:** the audit dir
(`<audit_dir>/audit-*.jsonl` + `.audit.key`). It is the only artifact
that rebuilds the receipt-journal floor after corruption (drill #6
step 3), the only chain of custody for dispute defense (drill #5
step 4), and the only forensic record. Wallet loss is bounded (mint a
new wallet, bond burnt, host boots); audit-log loss is unbounded
(every future dispute defaults against the operator, every journal
corruption becomes permanent).

---

## 2. Per-drill walkthrough

### Drill #1 — State wipe → restore

**Failure:** `rm -rf /var/lib/octravpn/{audit,receipts.bin,tailscale-wire}`;
keep sealed `wallet.hex.sealed` + `wg.key.sealed`; restart daemon.

**Expected (recovery.md):** sealed keys survive → Phase 2 unseal
succeeds; Phase 3 auto-creates `.audit.key`; Phase 4 auto-creates
empty journal via `ensure_v1_header` (`receipt_journal/migration.rs:117`);
tailscale-wire `noise_static.key` regenerates.

**Observed (code-walk):**
- `replay_v1` (`codec.rs:35`) opens an empty file fine.
- Audit log creates `.audit.key` on first append (mode 0600).
- `noise_static.key` regeneration **silently changes mkey identity**
  — every client with a pinned `oct://` URL breaks. Not documented in
  recovery.md (gap G-1).
- On-chain re-anchor: operator must re-run `octravpn-node register`
  to bind the new WG-pubkey-hash to the circle. Not listed as a
  state-wipe step in recovery.md (gap G-1).
- Audit-log → journal-floor reconstruction: documented in
  `recovery.md §Corrupted receipt journal` step 3, BUT the doc
  flags (correctly) that no shipped CLI rebuilds the binary file;
  the operator must hand-write the v1 format.

**Pass/fail:** PASS for boot; partial fail for "rebuild floor from
off-host audit log" (manual hex work).
**RTO:** ≈3 min restart + 30 s on-chain re-anchor.

### Drill #2 — Sealed-key compromise (passphrase rotation)

**Failure:** passphrase leaked; rotate to a fresh sealing passphrase.

**Walkthrough (v2-operator-key-hygiene.md §5 + rotation-master.md
§Wallet key):**
1. `unseal-keys --out /tmp/tmpfs/w.hex` (CLI enforces tmpfs).
2. Set new `OCTRAVPN_KEY_PASSPHRASE`; `seal-keys` produces new
   sealed envelope.
3. Atomic-rename new sealed file over the path `node.toml` already
   points at.
4. Update env file; `systemctl restart`; verify via `/health`.

**Observed:**
- `seal-keys`/`unseal-keys` cited in recovery.md Phase 2; tmpfs
  enforcement per `crates/octravpn-node/src/seal.rs`.
- **Pre-rotation receipts still verify:** the wallet keypair is
  unchanged; passphrase only wraps the on-disk envelope.
- Restart picks up the new env; no in-mem caching of the passphrase
  past Phase 2.

**Pass/fail:** PASS. Constraint: swap-file-then-restart-under-new-env
must be sequenced correctly or Phase 2 fails on next boot.
**RTO:** ≈5 min (unseal-tmpfs + reseal + rename + restart).

### Drill #3 — Network outage / RPC unreachable

**Failure:** drop egress to `OCTRA_RPC_URL` at the firewall.

**Expected:** `recovery.md §Phase 1` covers ONLY boot-time RPC fail.
Running-loop behavior is undocumented.

**Observed (`hub/attestation.rs:543-573` —
`spawn_validator_health_loop`):**
- RPC errors are `warn!`-logged; the loop sleeps for
  `poll_interval_secs` and retries indefinitely.
- `metrics.record_rpc(false)` bumps the error counter;
  `last_attestation_unix` STOPS advancing (this is the freshness
  gauge — Audit-2 reference).
- Prom metric `octravpn_last_attestation_unix` exposed at
  `control/handlers/metrics.rs:63`. Alarm rule:
  `time() - octravpn_last_attestation_unix > 3 * poll_interval_secs`.
- Receipts are signed locally (no RPC per receipt); `settle_claim`
  only fires at session close.
- `AccumulatorStore` (`hub/attestation.rs:528`) persists locally;
  only resets after successful `claim_earnings`. Long outage just
  delays the claim — no data loss.

**Tolerance window:** indefinite. The only failure mode is
"operator unbonded for missed attestation" — chain-side validator
churn, not a daemon failure.

**Pass/fail:** PASS for daemon resilience. **DOC GAP** (G-4) —
recovery.md doesn't tell the operator this is safe; an inexperienced
operator might panic-restart.
**RTO:** zero downtime, indefinite tolerance.

### Drill #4 — PVAC pubkey rotation (dry-run)

**Setup:** `/tmp/pvac-drill-statedir/{pvac/,wallet.json}`.

**Live execution on the audit host:**

```text
$ bash scripts/operators/rotate-pvac.sh --state-dir /tmp/pvac-drill-statedir
[…] wallet=oct1qtest…  rpc=https://devnet.octrascan.io/rpc
[…] step 2/5: minting new lattice keypair via sidecar
[…] keygen ok (pk 4139140 chars, sk 752 chars)
[…] step 3/5: sealing new secret under wallet passphrase envelope
rotate-pvac.sh: passphrase env var OCTRA_WALLET_PASSPHRASE is empty
```

With passphrase set, step 3 fails because the `octravpn-node` CLI
is absent on this host. The script is dry-run-safe; nothing was
written to chain, no file was overwritten.

| Step | Live? | Verdict |
|---|---|---|
| Pre-flight (jq/openssl/curl/sha256) | yes | PASS |
| Sidecar binary resolution | yes | PASS (found `pvac-sidecar/octra-pvac-sidecar`) |
| Wallet resolution from `wallet.json` | yes | PASS |
| Step 2 — sidecar keygen | yes | PASS (`hfhe_v1|...` pk ~4 MB, sk 752 chars) |
| Step 3 — seal sk under wallet passphrase | walk | needs `octravpn-node pvac seal --stdin` |
| Step 4 — AES KAT | walk | `op:"kat_roundtrip"` + `encrypt_zero` fallback in sidecar |
| Step 5 — build register tx | walk | `octravpn-node pvac register-tx` writes envelope |
| 24h dual-decrypt window | walk | enforced by `--archive-old`/`--broadcast` mutex |

**Pre-rotation receipts redeem post-rotation?** Yes, during the 24h
window. Old sealed sk is at `${state_dir}/pvac/backup/<TS>/sk.enc`;
PVAC dispatcher routes by `pvac_pk_hash` field. After
`--archive-old`, the backup moves to `pvac/cold-archive/` and the
warm copy is gone — any pre-rotation ciphertext arriving after that
goes through the v3 dispute path.

**Pass/fail:** PASS. Script is dry-run-safe (confirmed live).
**RTO:** ≈10 min on-host + 24 h dual-decrypt window.

### Drill #5 — Audit-log chain break

**Failure:** tamper with line N in `audit-2026-05-20.jsonl`
(`sed -i '1247s/receipt_signed/receipt_TAMPER/'`).

**Expected (`audit-verify.md §Recovering from a chain break`,
lines 138-237):**
1. Localize via `sed -n '1245,1250p'`.
2. Discriminate tampering vs disk corruption (auditd / dmesg /
   key-mode / clustering).
3. Stop daemon → `mv` broken file to `broken/` subdir → restart.
4. Cross-check journal floor against surviving audit rows to
   lower-bound the unaudited window.

**Observed:**
- `AuditLog::verify_file` returns `FileVerifyReport.first_error =
  Some("line 1247: MAC mismatch")`. CLI exits 1.
- On daemon restart with the broken file in place, Phase 3
  pre-verify (`recovery.md §Phase 3`) refuses to start: "audit log
  MAC chain broken at boot" — conservative refusing-to-extend.
- Quarantine works: daemon walks every `audit-*.jsonl`; moving the
  broken one to a sibling `broken/` subdir is exactly the doc's
  prescription. The verifier auto-discovers `.audit.key` in the
  parent.

**Pass/fail:** PASS. This is the best-quality recovery runbook in
the tree — it covers source discrimination, quarantine, the
unaudited window caveat, and journal cross-check fallback. End-to-end
actionable.
**RTO:** ≈2 min stop + archive + restart.

### Drill #6 — Receipt-journal CRC corruption (mid-record)

**Failure:** flip one bit in record 500's session_id (offset
`8 + 499*44 = 21964`).

**Expected (`recovery.md §CRC fail on a middle record`, lines
122-167):**
1. Stop daemon.
2. Back up corrupt file.
3. "Rebuild from audit log via `audit replay`" — doc flags
   `<!-- UNVERIFIED — no such CLI exists -->` (line 157).
4. Worst case: delete journal, accept rollback, rely on chain
   equivocation slash as the load-bearing defense.

**Observed (`crates/octravpn-core/src/receipt_journal/codec.rs:35-74`):**
- CRC mismatch returns `JournalError::ChecksumMismatch { path,
  offset }` immediately. `replay_v1` does NOT skip the bad record;
  it aborts replay.
- `ReceiptJournal::open` propagates → Phase 4 boot fails.
- No skip-bad-record mode. Doc-cited rebuild CLI does not exist.

**Operator's actual manual rebuild:**

```python
# Hand-write the v1 file. Operator has to do this from a transcript.
import struct, zlib
MAGIC = b"OCRJ2\0\0\0"   # NB: recovery.md line 105 says
                          # "OCRJ1\0\0\0" which is the LEGACY v0
                          # magic. Current v1 magic is OCRJ2. Doc bug G-2.
with open("receipts.bin.rebuilt", "wb") as f:
    f.write(MAGIC)
    for (sid_bytes, max_seq) in floors_from_audit_log:
        rec = sid_bytes + struct.pack(">Q", max_seq)
        crc = zlib.crc32(rec) & 0xFFFFFFFF
        f.write(rec + struct.pack(">I", crc))
```

**Pass/fail:** FAIL on RTO. Detect side PASSES; rebuild side has
no CLI.
**RTO:** ≥30 min hand-built, OR ≈1 min "delete + accept rollback"
with chain-side equivocation slash as the only remaining defense.

> **Fixed in commit `21df30e` on branch `worktree-agent-a557416bd6d3fba66`.**
> Drill #6 (H-RTO) is now PASS: the new
> `octravpn-node journal rebuild --from-audit <dir> --output <path>`
> CLI (`crates/octravpn-node/src/cli/journal.rs`) walks the HMAC-chained
> audit log via `AuditLog::verify_file`, harvests the
> `(session_id, seq)` pairs, computes the per-session floor, and emits
> a fresh v1 journal — with post-write verification that the rebuilt
> floor map matches the audit-derived plan. Exit codes:
> 0 success / 1 tampered audit / 2 IO / 3 refuse-overwrite / 4 verify-mismatch.
> `--dry-run` previews the plan without writing.
> Wall-clock on a synthetic 10 000-entry audit log: **~1.06 s**
> (test `cli::journal::tests::rebuild_10k_entries_under_two_minutes`).
> New target RTO: under 2 minutes including operator ceremony
> (stop daemon, rebuild, restart).

### Drill #7 — `kill -9` mid-receipt-sign

**Failure:** `kill -9 octravpn-node` while signing receipts + with
audit batch in flight in the unbounded mpsc.

**Expected (`recovery.md §Torn-tail`):** journal's torn-tail
tolerance kicks in; daemon boots cleanly. Doc says nothing about
the audit flusher.

**Observed:**
- **Journal:** `codec.rs:71-72` drops trailing partial record
  silently. Per the `EveryWrite` fsync policy + the README's
  atomicity contract (`receipt_journal/README.md`), the caller
  fsyncs before signing — so any dropped record was never visible
  to the rest of the system. PASS.
- **Audit:** `audit/batched.rs:21-25` —
  `DEFAULT_BATCH_INTERVAL_MS=100`, `DEFAULT_BATCH_SIZE=64`,
  channel is `unbounded_channel()` (line 49). On `kill -9`:
  - Records in the mpsc but not drained: lost.
  - Records drained into the in-flight batch but pre-fsync: lost.
  - Window bounded by `batch_interval_ms` (default 100 ms).
  - Doc comment at `batched.rs:64-67` confirms "≤ batch_interval_ms
    of recent records can be lost".

**Skew:** a receipt can land in the journal but its `receipt_signed`
audit row gets lost. `audit-verify.md` calls this a "Warn" outcome
("journal-only sessions") and (incorrectly) labels it a
"write-ordering bug." It is actually the documented audit-flusher
durability gap. Soften the warning (gap G-3).

**Pass/fail:** PASS (journal); PARTIAL FAIL (audit window
intentional but undocumented in recovery.md).
**RTO:** ≈1 min auto-recover. No operator action.

### Drill #8 — Backup + restore onto a fresh host

**Failure:** original host destroyed. Off-site backup has the audit
dir + sealed wallet + sealed WG key. Passphrase from separate KMS.
Receipt journal NOT backed up.

**Restore:**

```sh
rclone copy s3:audit-archive-octravpn/<host>/ /var/lib/octravpn/audit/
cp /off-site/{wallet.hex.sealed,wg.key.sealed} /var/lib/octravpn/
OCTRAVPN_KEY_PASSPHRASE=<from-KMS> systemctl start octravpn-node
```

**Observed:**
- Phases 1-6 succeed (audit log + key restored together → pre-verify
  passes; journal auto-creates empty; control plane binds; tunnel up).
- Operator's circle on chain unchanged — same wallet, same
  WG-pubkey-hash. No re-anchor needed.
- **Permanently lost state:**
  - `noise_static.key` → mkey identity churns → pinned-mkey clients
    break (drill #1 gap).
  - The ≤100 ms audit window before the original host's last fsync
    (drill #7 gap).
  - Receipt-journal floor for any session active at disaster time
    whose `receipt_signed` row was in the audit-flusher batch.
- Floor MUST be rebuilt from the restored audit log before signing
  any new receipt for pre-disaster sessions, or the operator
  re-signs an old (session_id, seq) and gets equivocation-slashed.

**Pass/fail:** PASS with documented caveats.
**RTO:** ≈10 min file copies + restart + KMS fetch.

---

## 3. Documentation gaps surfaced

| ID | Location | Gap |
|---|---|---|
| G-1 | recovery.md | No mention of `noise_static.key` churn on state-dir wipe or fresh-host restore. Clients with pinned mkey URLs break silently. Add to §Phase 6. |
| G-2 | recovery.md line 105 | Journal magic listed as `OCRJ1\0\0\0` — that's the LEGACY v0 magic. Current v1 is `OCRJ2\0\0\0` (`receipt_journal/codec.rs:15`). Foot-gun for hand-rebuild operators. |
| G-3 | audit-verify.md §FileVerifyReport | "journal-only sessions" warning calls it "a write-ordering bug." Not always — it's the documented audit-flusher ≤`batch_interval_ms` window. Soften. |
| G-4 | recovery.md | No coverage of running-daemon RPC outage. Add §"Chain RPC unreachable mid-session" citing `last_attestation_unix` gauge + indefinite retry. |
| G-5 | recovery.md §Corrupted receipt journal step 3 | `<!-- UNVERIFIED -->` flag is honest, but the doc should ship the v1 byte layout (currently only in `receipt_journal/README.md`). Operator mid-incident shouldn't have to grep the source tree. |
| G-6 | rotation-master.md §Coordinated rotations | "Wait for `octra_pvacPubkey` to return the new hash" — `rotate-pvac.sh:382-394` polls for sha256 match. Be explicit: `sha256(pubkey_blob) == registered.sha256`. |
| G-7 | rotation-master.md audit-trail regex | `rotat\|seal\|anchor_flipped` doesn't necessarily match every emitted `kind` (chain-watcher PVAC events). Verify against shipped strings or update. |
| G-8 | audit-verify.md macOS/Windows | Lines 96-101 launchd + Scheduled Task analogs flagged `<!-- UNVERIFIED -->`. Verify or drop. |

---

## 4. Hardening recommendations (likelihood × impact)

### R-1 — Ship `octravpn-node journal rebuild --from-audit <dir>`

**Likelihood:** medium (CRC corruption is rare but inevitable on
long-running hosts — SSD bit-rot, COW-FS quirks, fsync-window
power loss).
**Impact:** high (turns a 1-minute incident into ≥30-minute manual
hex work, with risk of operator deleting the journal and exposing
themselves to a chain equivocation slash).
**Action:** subcommand consuming `audit-*.jsonl` + `.audit.key`,
computing per-session max seq from `receipt_signed` rows, emitting
a fresh v1 journal at a target path. Closes G-5 + drill #6 RTO.

### R-2 — Make audit flusher's pending batch durable on shutdown

**Likelihood:** medium (any kill -9, OOM, or systemd timeout hits
this).
**Impact:** medium (≤ 100 ms audit loss; reconcilable via journal
cross-check but undermines the audit log's "complete post-mortem"
claim).
**Action:** SIGTERM handler calls `flush_and_close()` (already
implemented at `batched.rs:94`); OR swap `unbounded_channel` for
`bounded(N)` to backpressure producers.

### R-3 — Document running-daemon RPC outage path

**Likelihood:** high (RPC outages happen — TLS rotations, validator
churn, ISP issues).
**Impact:** low-medium (daemon is resilient by design; the gap is
that an operator might panic-restart).
**Action:** add §"Chain RPC unreachable mid-session" to recovery.md.

### R-4 — Fix the magic-byte typo (G-2)

**Likelihood:** low (most operators never rebuild a journal by hand).
**Impact:** low-medium (v0 magic happens to migrate-up correctly so
it's a foot-gun, not a hard fail).
**Action:** one-line edit to recovery.md line 105.

### R-5 — Add tailnet-state re-anchor advisory (G-1)

**Likelihood:** medium (state-dir wipes happen — disk full, log
overflow, accidental rm).
**Impact:** medium (silent client mkey-pin breakage).
**Action:** prose addition to recovery.md §Phase 6.

### R-6 — Quarterly DR drill CI job

Run drills #1, #5, #7 against the devnet docker stack on a quarterly
cron; flag any deviation. See §5.

### R-7 — Verify launchd + Scheduled Task analogs (G-8)

Close the cross-platform documentation gap with actual platform
testing on `octravpn-audit-verify.timer` analogs.

---

## 5. Quarterly drill — automation

**Pick drill #7** as the recurring CI job: deterministic
(`kill -9` is repeatable), exercises the highest-value resilience
invariant (no acknowledged receipt is ever lost), and has known
expected behavior on both journal + audit log.

**Shape:**

```bash
#!/usr/bin/env bash
# scripts/dr-drill-quarterly.sh — runs against the devnet harness.
set -euo pipefail

COMPOSE='docker compose -f docker-compose.yml \
  -f docker/devnet/docker-compose.devnet.yml --profile devnet'

# 1. Bring up node1 + drive a stream of receipts via v3-smoke.
$COMPOSE up -d --force-recreate node1
docker/devnet/v3-smoke.sh --quick &
SMOKE_PID=$!

# 2. Wait for ≥100 records in the journal.
sleep 30
SIZE=$($COMPOSE exec -T node1 stat -c %s /var/lib/octravpn/receipts.bin)
test "${SIZE}" -ge $((8 + 100*44)) || { echo FAIL; exit 1; }

# 3. kill -9 the daemon.
$COMPOSE exec -T node1 pkill -9 octravpn-node || true

# 4. Restart; verify boot succeeded + replay clean.
$COMPOSE restart node1
$COMPOSE exec -T node1 octravpn-node audit verify \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin

# 5. Cross-check journal vs audit (with ≤200ms skew tolerance for
#    the flusher window — see drill #7).
$COMPOSE exec -T node1 octravpn-node audit replay \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin \
    --format json | python3 scripts/dr-cross-check.py --max-skew-ms 200

wait $SMOKE_PID || true
$COMPOSE down -v
```

Wire as `.github/workflows/dr-quarterly.yml` with
`cron: '0 4 1 */3 *'` (04:00 UTC, 1st of every third month).
Failure opens a P1 issue tagged `dr-drill-regression`.

Quarterly cadence catches:
- Audit-flusher durability regressions (drill #7's window widens).
- Journal torn-tail handling regressions (`replay_v1`'s drop-tail
  contract broken by a codec change).
- Boot-sequence ordering regressions (daemon starts before journal
  verify).
- New audit-log `kind` strings without corresponding journal
  cross-check.

---

## Footer

- **Commit hash:** `4495dec0d1c67b498a24196041f1b906c1fc058d`
- **Pass/fail summary:** 5 PASS / 2 PARTIAL (drill #1 rebuild-CLI gap,
  drill #7 audit-flusher window) / 1 FAIL on RTO (drill #6 manual
  journal rebuild).
- **Worst recovery scenario:** drill #6. No shipped CLI to rebuild
  a corrupted receipt journal; manual hex-writing 44-byte records
  with CRC-32-IEEE; RTO ≥ 30 min with material risk of an operator
  "just deleting" the journal and exposing themselves to chain-side
  equivocation slashing.
- **Most-load-bearing off-site backup:** the audit dir
  (`audit-*.jsonl` + `.audit.key`). It is the only artifact that
  rebuilds the receipt-journal floor after corruption, the only
  audit chain that can defend a dispute, and the only forensic
  record. Wallet loss is bounded (mint a new one); audit-log loss
  is unbounded.
