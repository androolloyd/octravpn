//! OctraVPN v3 — canonical `members.json` schema.
//!
//! Each tailnet-owner circle holds a sealed asset at
//! `oct://<tailnet-owner-circle>/tailnet-{id}/members.json`. The chain
//! anchors `tailnet_members_root[tid] = sha256_hex(members.json)` as a
//! 64-char lowercase hex digest (see `program/main-v3.aml`'s
//! `create_tailnet` / `update_members_root` entrypoints). Off-chain
//! verifiers fetch the JSON, recompute the SHA-256, and compare against
//! the on-chain anchor.
//!
//! The chain does NOT decode or interpret the JSON — integrity is
//! enforced entirely by the commit/recompute cycle. As with the sibling
//! `state-root.json` and `policy.json` schemas, two clients producing
//! semantically identical `TailnetMembers` MUST emit byte-identical
//! canonical bytes or the anchor will not round-trip.
//!
//! In v2 the equivalent record lived on chain as a `Tailnet` struct that
//! held an `ip_salt` field used to scramble the per-member IP-to-wallet
//! binding inside the tailnet. v3 moves the whole record off chain into
//! this file; only its sha256 digest remains on chain. The `ip_salt`
//! field is therefore part of THIS schema, not the chain contract.
//!
//! # Canonical encoding rules
//!
//! These mirror `v3_state_root.rs` and `v3_policy.rs` exactly — all three
//! schemas MUST canonicalise the same way so the same `canonical_write`
//! discipline can be re-used between them by anyone re-implementing the
//! schema:
//!
//! 1. Object keys are emitted in lexicographic (byte-wise on UTF-8) order.
//!    Insertion order is NOT preserved — `serde_json`'s default behaviour
//!    is overridden by re-walking the `Value` tree.
//! 2. No whitespace anywhere. Tokens are concatenated directly; `,` and
//!    `:` are the only structural separators.
//! 3. Integer fields are emitted as bare decimal digits, no leading
//!    zeros, no `+`/`-` sign for unsigned values, no scientific notation.
//!    `serde_json`'s default integer formatting already matches this.
//! 4. Optional fields that are `None` are omitted entirely; they do NOT
//!    appear as `"field":null`. v1 has no optional fields, but the rule
//!    is preserved for forward compatibility.
//! 5. UTF-8 output, no BOM, no trailing newline. ASCII fields
//!    (`wallet`, `wg_pubkey_b64`, `ip_salt`) have their character set
//!    further constrained by `validate()`. Freeform string fields admit
//!    non-ASCII text; future producers SHOULD NFC-normalise.
//! 6. The `members` array is sorted by `wallet` in lexicographic
//!    (byte-wise on UTF-8) order BEFORE canonicalisation. This is a
//!    schema-level invariant: reordering the input MUST NOT change the
//!    canonical bytes (and therefore the hash). Duplicates are rejected.
//!
//! # Hashing
//!
//! `hash_hex()` returns the lowercase 64-char hex SHA-256 of
//! `canonical_bytes()`. This is the value committed on chain as
//! `tailnet_members_root[tid]`.
//!
//! # Versioning
//!
//! The `v` field is the schema version. v1 is the initial release. Adding
//! an optional field that defaults to `None`/absent does NOT require
//! bumping `v` — old verifiers will silently ignore unknown keys and
//! recompute a different hash, which is fine because the on-chain anchor
//! was written by the new encoder. Bumping `v` is reserved for breaking
//! changes (field removal, field rename, semantics shift).
//!
//! Unknown fields encountered during decode are preserved verbatim
//! (`#[serde(flatten)]` into a `BTreeMap`) and round-trip through
//! `canonical_bytes()` so a verifier built against v1 can still compute
//! the correct `tailnet_members_root` for v2+ data.
//!
//! # `ip_salt` semantics
//!
//! `ip_salt` is exactly 64 lowercase hex characters (32 random bytes).
//! Clients derive per-member tailnet IPs as a deterministic function of
//! `(wallet, ip_salt)` — typically the first N bits of
//! `sha256(ip_salt || wallet)` mapped into the tailnet's CIDR — so that
//! observers without the salt cannot link a tailnet IP back to a wallet,
//! and members never see the wallet → IP map for peers they haven't
//! joined a session with. The salt is fixed at tailnet-creation time and
//! never rotated; rotating it would require a new `members.json` version
//! AND a new tailnet IP allocation for every member. Concrete IP
//! derivation lives in client code (TBD — point at the client mesh
//! crate's `ip_alloc` module when it lands; the on-wire derivation is
//! intentionally NOT pinned by this schema so client implementations
//! can choose CIDR widths and prefixes per tailnet config.json).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Canonical schema version emitted by encoders in this crate.
pub const SCHEMA_VERSION_V1: u32 = 1;

/// Length of a SHA-256 hex digest. Matches AML's `sha256()` builtin and
/// the `HEX_HASH_LEN` constant in `v3_state_root.rs` / `v3_policy.rs`.
pub const HEX_HASH_LEN: usize = 64;

/// Required length of `ip_salt` (hex characters of a 32-byte random
/// value). Lowercase hex, validated at every encode/decode boundary.
pub const IP_SALT_HEX_LEN: usize = 64;

/// Expected character length of a base64-encoded 32-byte WireGuard
/// public key. 32 bytes → ceil(32/3)*4 == 44 characters, including one
/// `=` pad byte. Mirrors `WG_PUBKEY_B64_LEN` in `v3_policy.rs`.
pub const WG_PUBKEY_B64_LEN: usize = 44;

/// Expected decoded length of a WireGuard public key, in bytes.
pub const WG_PUBKEY_RAW_LEN: usize = 32;

/// Required prefix on every Octra address (`oct...`). The tailnet schema
/// does not validate the address payload — only that it is non-empty and
/// carries the family prefix. Full address validation lives in
/// `octra-core::address`.
pub const WALLET_PREFIX: &str = "oct";

/// Errors surfaced by the v3 `TailnetMembers` encoder/decoder.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum V3MembersError {
    #[error("schema version unsupported: got {got}, this build understands {supported}")]
    UnsupportedVersion { got: u32, supported: u32 },
    #[error("ip_salt length is {len}, expected {IP_SALT_HEX_LEN} (hex of 32 random bytes)")]
    BadIpSaltLength { len: usize },
    #[error("ip_salt contains a non-hex character or uppercase letter")]
    BadIpSaltEncoding,
    #[error("member at index {index}: wallet is empty")]
    EmptyWallet { index: usize },
    #[error("member at index {index}: wallet {wallet:?} is missing the {prefix:?} prefix")]
    BadWalletPrefix {
        index: usize,
        wallet: String,
        prefix: &'static str,
    },
    #[error(
        "member at index {index}: wg_pubkey_b64 length is {len}, expected {WG_PUBKEY_B64_LEN}"
    )]
    BadWgPubkeyLength { index: usize, len: usize },
    #[error("member at index {index}: wg_pubkey_b64 is not valid base64: {reason}")]
    BadWgPubkeyEncoding { index: usize, reason: String },
    #[error(
        "member at index {index}: wg_pubkey_b64 decodes to {got} bytes, expected {WG_PUBKEY_RAW_LEN}"
    )]
    BadWgPubkeyDecodedLength { index: usize, got: usize },
    #[error("duplicate wallet {wallet:?} at indices {first} and {second}")]
    DuplicateWallet {
        wallet: String,
        first: usize,
        second: usize,
    },
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// A single tailnet member entry.
///
/// # Field semantics
///
/// `wallet` is the member's Octra address (e.g. `"oct7Mofan..."`). The
/// schema enforces non-emptiness and the `oct` family prefix; full
/// address-payload validation is outside scope here (it lives in
/// `octra-core::address`).
///
/// `wg_pubkey_b64` is the member's WireGuard public key in standard
/// base64 (32 bytes raw → 44 chars, one `=` pad). NOT a hash — the
/// tailnet IP derivation and the WG dial both consume the raw key.
///
/// `joined_epoch` is the chain epoch at which the member joined the
/// tailnet. Used by clients to detect members whose sessions predate a
/// rotation event the tailnet owner has since published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Member's Octra wallet address (`oct…`). Non-empty.
    pub wallet: String,

    /// Base64-encoded WireGuard public key (32 raw bytes → 44 chars
    /// including one `=` pad). Validation enforces both the textual
    /// length and that it decodes cleanly to exactly 32 bytes.
    pub wg_pubkey_b64: String,

    /// Chain epoch at which the member joined the tailnet.
    pub joined_epoch: u64,
}

/// Canonical tailnet member-set commitment.
///
/// One of these is produced by the tailnet-owner-side daemon each time
/// the owner wants to rotate the on-chain `tailnet_members_root` anchor
/// (member added, member removed, key rotation, …). It is sealed into
/// the tailnet-owner circle at
/// `oct://<tailnet-owner-circle>/tailnet-{id}/members.json`, and
/// `sha256_hex(canonical_bytes())` is sent to main-v3's
/// `update_members_root(tid, new_root)`.
///
/// # Field semantics
///
/// `tailnet_id` is the chain-assigned identifier for the tailnet. It is
/// part of the canonical bytes so that a `members.json` blob sealed at
/// one resource key cannot be replayed against a different tailnet's
/// anchor.
///
/// `ip_salt` is exactly 64 lowercase hex characters (32 random bytes).
/// See the module-level doc for derivation semantics. Validation
/// enforces length and lowercase-hex character set.
///
/// `members` is the (sorted-by-wallet) member set. `canonical_bytes()`
/// sorts the vector before emitting, so callers that mutate it
/// out-of-order produce the same canonical hash. Duplicate wallets are
/// rejected at validation time.
///
/// `effective_epoch` is the chain epoch at which the owner began
/// publishing this member set. Monotonic per tailnet (off-chain
/// invariant — the chain does not enforce monotonicity, only the
/// audit log of `update_members_root` calls does).
///
/// `timestamp_secs` is the wall-clock UNIX seconds at the owner.
/// Strictly informational — the chain has its own epoch counter.
///
/// `unknown` carries any fields a newer encoder added that this version
/// doesn't recognise. They are preserved verbatim through encode →
/// decode → re-encode so the members hash remains stable for upgraded
/// peers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailnetMembers {
    /// Schema version. Starts at 1. See module-level doc for bump policy.
    pub v: u32,

    /// Chain-assigned tailnet identifier this member set belongs to.
    /// Included in canonical bytes so a `members.json` from tailnet A
    /// cannot be replayed against tailnet B's anchor.
    pub tailnet_id: u64,

    /// 64-char lowercase hex of 32 random bytes. Used by clients to
    /// derive per-member tailnet IPs from `(wallet, ip_salt)` so that
    /// chain observers cannot link a tailnet IP back to a wallet
    /// without holding the salt.
    pub ip_salt: String,

    /// Tailnet members. `canonical_bytes()` sorts this vector by
    /// `wallet` (lexicographic byte order) before serializing; the
    /// in-memory order is therefore semantically irrelevant.
    pub members: Vec<Member>,

    /// Chain epoch at which the owner began serving this member set.
    /// Monotonic per tailnet by off-chain convention.
    pub effective_epoch: u64,

    /// Wall-clock timestamp at the tailnet owner (UNIX seconds).
    /// Informational only; skew across owners is expected.
    pub timestamp_secs: u64,

    /// Forward-compatibility bucket. Any JSON keys not recognised by
    /// this decoder land here, and are re-emitted verbatim by
    /// `canonical_bytes()` so the SHA-256 round-trips for v(N+1) data
    /// running through a v(N) verifier. Internal — owners should not
    /// write directly into this map.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Value>,
}

impl TailnetMembers {
    /// Build a v1 `TailnetMembers`. Performs no field validation — call
    /// `validate()` before sealing.
    pub fn new_v1(
        tailnet_id: u64,
        ip_salt: impl Into<String>,
        members: Vec<Member>,
        effective_epoch: u64,
        timestamp_secs: u64,
    ) -> Self {
        Self {
            v: SCHEMA_VERSION_V1,
            tailnet_id,
            ip_salt: ip_salt.into(),
            members,
            effective_epoch,
            timestamp_secs,
            unknown: BTreeMap::new(),
        }
    }

    /// Encode to canonical bytes: sorted-key JSON, no whitespace, UTF-8,
    /// `members` sorted by `wallet`. Two `TailnetMembers` values that
    /// compare semantically equal (same data, possibly different
    /// `members` order) MUST produce identical bytes. This is the input
    /// to `hash_hex()`.
    ///
    /// # Errors
    ///
    /// Returns `V3MembersError::Serde` if `serde_json` cannot represent
    /// the struct — in practice this is unreachable for the v1 shape.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, V3MembersError> {
        // Sort members by wallet before serialising so input order does
        // not change the canonical bytes. Cloning is fine here — this
        // is the encode path, not a hot loop, and the validation rule
        // is that the *output* is sorted, not the in-memory struct.
        let mut sorted = self.clone();
        sorted
            .members
            .sort_by(|a, b| a.wallet.as_bytes().cmp(b.wallet.as_bytes()));
        let value = serde_json::to_value(&sorted)?;
        let mut out = Vec::with_capacity(256);
        crate::v3_canonical::canonical_write(&value, &mut out);
        Ok(out)
    }

    /// SHA-256 of `canonical_bytes()`, rendered as lowercase 64-char
    /// hex. This is the exact value that flows into main-v3's
    /// `tailnet_members_root[tid]`.
    pub fn hash_hex(&self) -> Result<String, V3MembersError> {
        let bytes = self.canonical_bytes()?;
        let digest = Sha256::digest(&bytes);
        Ok(hex::encode(digest))
    }

    /// Decode + validate a canonical JSON blob. Rejects unknown schema
    /// versions; use `decode_lenient` for forward-compat verifiers that
    /// only need the hash to round-trip.
    pub fn decode(bytes: &[u8]) -> Result<Self, V3MembersError> {
        let m: Self = serde_json::from_slice(bytes)?;
        m.validate()?;
        Ok(m)
    }

    /// Field-level invariants. Run on every encode and decode that
    /// touches untrusted data.
    pub fn validate(&self) -> Result<(), V3MembersError> {
        if self.v != SCHEMA_VERSION_V1 {
            return Err(V3MembersError::UnsupportedVersion {
                got: self.v,
                supported: SCHEMA_VERSION_V1,
            });
        }
        validate_common(self)?;
        Ok(())
    }

    /// Decode without enforcing schema-version equality. Verifiers
    /// running against a future `v` use this path to keep the members
    /// hash computation working even when they don't understand new
    /// semantic fields. Field-level invariants on the known fields are
    /// still checked.
    pub fn decode_lenient(bytes: &[u8]) -> Result<Self, V3MembersError> {
        let m: Self = serde_json::from_slice(bytes)?;
        validate_common(&m)?;
        Ok(m)
    }
}

/// Shared field-level invariants used by both strict `validate()` and
/// `decode_lenient()`. Does NOT check the `v` field — callers decide
/// whether to reject unknown versions.
fn validate_common(m: &TailnetMembers) -> Result<(), V3MembersError> {
    check_ip_salt(&m.ip_salt)?;
    // Per-member validation + duplicate detection. We use a BTreeSet
    // keyed by the wallet bytes; on first sight we record the index,
    // on second sight we emit DuplicateWallet with both indices.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (index, member) in m.members.iter().enumerate() {
        if member.wallet.is_empty() {
            return Err(V3MembersError::EmptyWallet { index });
        }
        if !member.wallet.starts_with(WALLET_PREFIX) {
            return Err(V3MembersError::BadWalletPrefix {
                index,
                wallet: member.wallet.clone(),
                prefix: WALLET_PREFIX,
            });
        }
        check_wg_pubkey(index, &member.wg_pubkey_b64)?;
        if let Some(&first) = seen.get(&member.wallet) {
            return Err(V3MembersError::DuplicateWallet {
                wallet: member.wallet.clone(),
                first,
                second: index,
            });
        }
        seen.insert(member.wallet.clone(), index);
    }
    Ok(())
}

/// Validate an `ip_salt` hex string: exactly `IP_SALT_HEX_LEN` chars,
/// all lowercase hex.
fn check_ip_salt(value: &str) -> Result<(), V3MembersError> {
    if value.len() != IP_SALT_HEX_LEN {
        return Err(V3MembersError::BadIpSaltLength { len: value.len() });
    }
    // Lowercase hex only. Uppercase A-F is rejected to match AML's
    // sha256() output discipline (the chain consumes 64-char lowercase
    // hex everywhere; we keep schema-level hex fields aligned with that
    // so verifiers don't have to case-fold).
    if !value
        .bytes()
        .all(|b| (b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err(V3MembersError::BadIpSaltEncoding);
    }
    Ok(())
}

/// Validate a base64 WireGuard public key string for a specific member
/// index. Checks the textual length, the base64 alphabet, and the
/// decoded byte length.
fn check_wg_pubkey(index: usize, value: &str) -> Result<(), V3MembersError> {
    if value.len() != WG_PUBKEY_B64_LEN {
        return Err(V3MembersError::BadWgPubkeyLength {
            index,
            len: value.len(),
        });
    }
    let raw =
        crate::b64::decode(value.as_bytes()).map_err(|e| V3MembersError::BadWgPubkeyEncoding {
            index,
            reason: e.to_string(),
        })?;
    if raw.len() != WG_PUBKEY_RAW_LEN {
        return Err(V3MembersError::BadWgPubkeyDecodedLength {
            index,
            got: raw.len(),
        });
    }
    Ok(())
}

// canonical_write + write_json_string live in `crate::v3_canonical`.
// All three v3 schemas (state_root, policy, members) delegate there so
// the on-chain anchor algorithm has ONE owner.

#[cfg(test)]
mod tests {
    use super::*;

    /// 32-byte WG pubkey as base64. Fixed pattern so fixtures are
    /// deterministic across runs without pulling in a real WG keypair
    /// generator.
    fn wg_pubkey(byte: u8) -> String {
        let raw = [byte; WG_PUBKEY_RAW_LEN];
        crate::b64::encode(raw)
    }

    /// Fixed `ip_salt` value used by every test fixture: 64 hex chars
    /// of `a`. Real producers use 32 random bytes from a CSPRNG.
    fn sample_ip_salt() -> String {
        "a".repeat(IP_SALT_HEX_LEN)
    }

    fn sample_member(addr_suffix: &str, key_byte: u8) -> Member {
        Member {
            wallet: format!("oct{addr_suffix}"),
            wg_pubkey_b64: wg_pubkey(key_byte),
            joined_epoch: 100,
        }
    }

    fn sample() -> TailnetMembers {
        TailnetMembers::new_v1(
            42,
            sample_ip_salt(),
            vec![
                sample_member("alice0000000000000000000000000000000000000", 0x11),
                sample_member("bob0000000000000000000000000000000000000000", 0x22),
                sample_member("carol000000000000000000000000000000000000000", 0x33),
            ],
            7,
            1_705_000_000,
        )
    }

    #[test]
    fn validate_accepts_sample() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn round_trip_through_canonical_bytes() {
        let m = sample();
        let bytes = m.canonical_bytes().expect("encode");
        let back = TailnetMembers::decode(&bytes).expect("decode");
        // Members in `back` are in canonical (sorted) order — compare
        // by hash + by sorted-members equality rather than struct eq.
        assert_eq!(m.hash_hex().unwrap(), back.hash_hex().unwrap());
        let mut expected_sorted = m;
        expected_sorted
            .members
            .sort_by(|a, b| a.wallet.as_bytes().cmp(b.wallet.as_bytes()));
        assert_eq!(expected_sorted, back);
    }

    #[test]
    fn determinism_same_struct_same_bytes() {
        let a = sample().canonical_bytes().expect("encode a");
        let b = sample().canonical_bytes().expect("encode b");
        assert_eq!(a, b);
    }

    #[test]
    fn member_sort_input_order_doesnt_change_hash() {
        // Build two structs with the same data in reverse member order.
        // canonical_bytes() MUST sort members before serialising, so
        // both must produce the same hash.
        let forward = sample();
        let mut reversed = sample();
        reversed.members.reverse();
        // Sanity: the in-memory orders really do differ.
        assert_ne!(forward.members, reversed.members);

        let h1 = forward.hash_hex().expect("hash forward");
        let h2 = reversed.hash_hex().expect("hash reversed");
        assert_eq!(h1, h2);

        // And a third permutation (rotate by 1) also matches.
        let mut rotated = sample();
        rotated.members.rotate_left(1);
        let h3 = rotated.hash_hex().expect("hash rotated");
        assert_eq!(h1, h3);
    }

    #[test]
    fn canonical_bytes_have_no_whitespace() {
        let bytes = sample().canonical_bytes().expect("encode");
        for b in &bytes {
            assert!(
                !b" \n\r\t".contains(b),
                "whitespace byte 0x{b:02x} leaked into canonical encoding"
            );
        }
    }

    #[test]
    fn canonical_bytes_have_sorted_top_level_keys() {
        let bytes = sample().canonical_bytes().expect("encode");
        let s = std::str::from_utf8(&bytes).expect("utf8");
        let expected_order = [
            "effective_epoch",
            "ip_salt",
            "members",
            "tailnet_id",
            "timestamp_secs",
            "v",
        ];
        let mut cursor = 0;
        for key in expected_order {
            let needle = format!("\"{key}\"");
            let idx = s[cursor..]
                .find(&needle)
                .unwrap_or_else(|| panic!("key {key} missing or out of order in {s}"));
            cursor += idx + needle.len();
        }
    }

    #[test]
    fn bad_ip_salt_wrong_length_rejected() {
        let mut m = sample();
        m.ip_salt = "a".repeat(IP_SALT_HEX_LEN - 1);
        match m.validate() {
            Err(V3MembersError::BadIpSaltLength { len }) => {
                assert_eq!(len, IP_SALT_HEX_LEN - 1);
            }
            other => panic!("expected BadIpSaltLength, got {other:?}"),
        }
    }

    #[test]
    fn bad_ip_salt_uppercase_rejected() {
        let mut m = sample();
        // 64 chars but with a single uppercase letter.
        m.ip_salt = format!("A{}", "a".repeat(IP_SALT_HEX_LEN - 1));
        assert!(matches!(
            m.validate(),
            Err(V3MembersError::BadIpSaltEncoding)
        ));
    }

    #[test]
    fn bad_ip_salt_non_hex_rejected() {
        let mut m = sample();
        // 64 chars but with non-hex `z`.
        m.ip_salt = format!("z{}", "a".repeat(IP_SALT_HEX_LEN - 1));
        assert!(matches!(
            m.validate(),
            Err(V3MembersError::BadIpSaltEncoding)
        ));
    }

    #[test]
    fn duplicate_wallet_rejected() {
        let mut m = sample();
        // Append a copy of alice's wallet but with a different key.
        let dup = Member {
            wallet: m.members[0].wallet.clone(),
            wg_pubkey_b64: wg_pubkey(0x44),
            joined_epoch: 200,
        };
        m.members.push(dup);
        match m.validate() {
            Err(V3MembersError::DuplicateWallet {
                wallet,
                first,
                second,
            }) => {
                assert_eq!(wallet, sample().members[0].wallet);
                assert_eq!(first, 0);
                assert_eq!(second, m.members.len() - 1);
            }
            other => panic!("expected DuplicateWallet, got {other:?}"),
        }
    }

    #[test]
    fn bad_wg_pubkey_length_rejected() {
        let mut m = sample();
        m.members[1].wg_pubkey_b64 = "too-short".to_string();
        match m.validate() {
            Err(V3MembersError::BadWgPubkeyLength { index, len }) => {
                assert_eq!(index, 1);
                assert_eq!(len, "too-short".len());
            }
            other => panic!("expected BadWgPubkeyLength, got {other:?}"),
        }
    }

    #[test]
    fn bad_wg_pubkey_encoding_rejected() {
        let mut m = sample();
        // 44 chars but non-base64 alphabet.
        m.members[2].wg_pubkey_b64 = "!".repeat(WG_PUBKEY_B64_LEN);
        match m.validate() {
            Err(V3MembersError::BadWgPubkeyEncoding { index, .. }) => {
                assert_eq!(index, 2);
            }
            other => panic!("expected BadWgPubkeyEncoding, got {other:?}"),
        }
    }

    #[test]
    fn bad_wg_pubkey_decoded_length_rejected() {
        let mut m = sample();
        // 44 chars of "A" decodes to 33 bytes — hits the decoded-length
        // branch (32 expected). Same trick as v3_policy.rs.
        m.members[0].wg_pubkey_b64 = "A".repeat(WG_PUBKEY_B64_LEN);
        match m.validate() {
            Err(V3MembersError::BadWgPubkeyDecodedLength { index, got }) => {
                assert_eq!(index, 0);
                assert_eq!(got, 33);
            }
            other => panic!("expected BadWgPubkeyDecodedLength, got {other:?}"),
        }
    }

    #[test]
    fn empty_wallet_rejected() {
        let mut m = sample();
        m.members[0].wallet = String::new();
        match m.validate() {
            Err(V3MembersError::EmptyWallet { index }) => assert_eq!(index, 0),
            other => panic!("expected EmptyWallet, got {other:?}"),
        }
    }

    #[test]
    fn bad_wallet_prefix_rejected() {
        let mut m = sample();
        m.members[1].wallet = "xyz0000000000000000000000000000000000000000000".to_string();
        match m.validate() {
            Err(V3MembersError::BadWalletPrefix { index, prefix, .. }) => {
                assert_eq!(index, 1);
                assert_eq!(prefix, WALLET_PREFIX);
            }
            other => panic!("expected BadWalletPrefix, got {other:?}"),
        }
    }

    #[test]
    fn unknown_future_fields_preserved_through_round_trip() {
        // Encode a "v2" blob with an extra `acl_root` field and verify
        // the v1 decoder preserves it AND recomputes the same hash.
        let bytes_v1 = sample().canonical_bytes().expect("encode v1");
        let mut value: Value = serde_json::from_slice(&bytes_v1).expect("parse v1 to Value");
        if let Value::Object(map) = &mut value {
            map.insert(
                "acl_root".to_string(),
                Value::String("a".repeat(HEX_HASH_LEN)),
            );
            // Pretend the producer bumped the schema version.
            map.insert("v".to_string(), Value::from(2u32));
        }
        let bytes_v2 = serde_json::to_vec(&value).expect("re-encode v2 Value");

        // Strict decode rejects v=2.
        assert!(matches!(
            TailnetMembers::decode(&bytes_v2),
            Err(V3MembersError::UnsupportedVersion { got: 2, .. })
        ));

        // Lenient decode succeeds and preserves the extra key.
        let m = TailnetMembers::decode_lenient(&bytes_v2).expect("lenient decode");
        assert!(m.unknown.contains_key("acl_root"));

        // Re-encoding emits the unknown field in lex order; the hash is
        // stable across encode → decode_lenient → encode.
        let re_encoded = m.canonical_bytes().expect("re-encode");
        let hash_a = hex::encode(Sha256::digest(&re_encoded));
        let canonical_v2 = {
            // Independent reference: canonical_write the original Value
            // tree (with members already sorted, since the v1 encoder
            // sorted them before producing bytes_v1).
            let mut out = Vec::new();
            crate::v3_canonical::canonical_write(&value, &mut out);
            out
        };
        let hash_b = hex::encode(Sha256::digest(&canonical_v2));
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn omits_unknown_by_default_when_not_flatten_decoded() {
        // A struct built via `new_v1` has an empty `unknown` map; the
        // canonical bytes MUST NOT contain any extra keys beyond the
        // declared schema fields. Verifies our flatten bucket doesn't
        // synthesise placeholders.
        let bytes = sample().canonical_bytes().expect("encode");
        let s = std::str::from_utf8(&bytes).expect("utf8");
        // Known v1 keys only — nothing else at top level.
        for unexpected in ["acl_root", "policy_hash", "extra", "null"] {
            assert!(
                !s.contains(&format!("\"{unexpected}\"")),
                "unexpected key {unexpected} leaked into canonical bytes: {s}"
            );
        }
    }

    #[test]
    fn unicode_in_unknown_round_trips_byte_identical() {
        // The v1 schema has no freeform unicode string field — wallet,
        // wg_pubkey_b64, and ip_salt are all ASCII-constrained. But a
        // forward-compat producer might add a unicode-bearing key (e.g.
        // a `display_name` for the tailnet). Confirm we round-trip such
        // a string byte-identical via the `unknown` bucket.
        let mut m = sample();
        m.unknown.insert(
            "display_name".to_string(),
            Value::String("Zürich—北京".to_string()),
        );
        let bytes_a = m.canonical_bytes().expect("encode a");
        let bytes_b = m.canonical_bytes().expect("encode b");
        assert_eq!(bytes_a, bytes_b);

        let decoded = TailnetMembers::decode_lenient(&bytes_a).expect("lenient decode");
        let bytes_c = decoded.canonical_bytes().expect("re-encode");
        assert_eq!(bytes_a, bytes_c);

        let s = std::str::from_utf8(&bytes_a).expect("utf8");
        assert!(s.contains("Zürich—北京"), "unicode mangled: {s}");
    }

    /// Cross-check: hash a hand-built fixture struct and confirm both
    /// `canonical_bytes()` and `hash_hex()` agree with an independent
    /// `Sha256::digest` call. Catches regressions in either the
    /// canonicalisation walker or the hex encoding step.
    #[test]
    fn cross_check_hash_matches_independent_sha256() {
        let m = sample();
        let bytes = m.canonical_bytes().expect("encode");
        let expected = hex::encode(Sha256::digest(&bytes));
        let got = m.hash_hex().expect("hash");
        assert_eq!(expected, got);
        assert_eq!(expected.len(), HEX_HASH_LEN);
    }

    // -----------------------------------------------------------------
    // Property-based tests. Probe the encoder against a broad strategy
    // space: determinism, reorder-invariance (both top-level Map AND
    // members Vec), hash stability, and a weak form of injectivity.
    // -----------------------------------------------------------------
    use proptest::collection::{btree_map, vec as pvec};
    use proptest::prelude::*;
    use serde_json::Map;

    /// 32-byte WG pubkey from a seed → 44-char base64 (always valid).
    fn wg_b64_from(seed: &[u8; 32]) -> String {
        crate::b64::encode(seed)
    }

    /// 64-char lowercase-hex ip_salt from a 32-byte seed.
    fn ip_salt_from(seed: &[u8; 32]) -> String {
        hex::encode(seed)
    }

    /// Strategy producing arbitrary, well-formed `TailnetMembers`s.
    /// Members are deduplicated by wallet at strategy-build time so
    /// `validate()` always succeeds.
    fn arb_members() -> impl Strategy<Value = TailnetMembers> {
        (
            any::<u64>(),                 // tailnet_id
            any::<[u8; 32]>(),            // ip_salt seed
            pvec("[a-z0-9]{1,16}", 0..8), // wallet suffixes
            pvec(any::<[u8; 32]>(), 8),   // wg pubkey seeds
            pvec(any::<u64>(), 8),        // joined_epochs
            any::<u64>(),                 // effective_epoch
            any::<u64>(),                 // timestamp_secs
            btree_map(
                "x_[a-z]{1,8}",
                prop_oneof![
                    Just(Value::Null),
                    any::<bool>().prop_map(Value::Bool),
                    any::<i64>().prop_map(Value::from),
                    ".{0,16}".prop_map(Value::String),
                ],
                0..4,
            ),
        )
            .prop_map(|(tid, salt, suffixes, keys, epochs, ep, ts, unknown_map)| {
                // Dedup wallet suffixes so we never trip
                // DuplicateWallet at validate() time.
                let mut seen = std::collections::BTreeSet::new();
                let members: Vec<Member> = suffixes
                    .into_iter()
                    .filter(|s| seen.insert(s.clone()))
                    .enumerate()
                    .map(|(i, suffix)| {
                        let wallet = format!("oct{suffix}");
                        let key = wg_b64_from(&keys[i % keys.len()]);
                        let je = epochs[i % epochs.len()];
                        Member {
                            wallet,
                            wg_pubkey_b64: key,
                            joined_epoch: je,
                        }
                    })
                    .collect();
                let mut m = TailnetMembers::new_v1(tid, ip_salt_from(&salt), members, ep, ts);
                let bt: BTreeMap<String, Value> = unknown_map.into_iter().collect();
                m.unknown = bt;
                m
            })
            .prop_filter("well-formed members must validate", |m| {
                m.validate().is_ok()
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 192,
            ..ProptestConfig::default()
        })]

        /// **Determinism.** Two `canonical_bytes()` calls on the same
        /// `TailnetMembers` produce identical bytes.
        #[test]
        fn prop_canonical_bytes_deterministic(m in arb_members()) {
            let a = m.canonical_bytes().expect("encode a");
            let b = m.canonical_bytes().expect("encode b");
            prop_assert_eq!(a, b);
        }

        /// **Member-Vec reorder invariance.** Permuting `members`
        /// changes in-memory order, but `canonical_bytes()` sorts by
        /// wallet before emitting — so the bytes (and the hash) are
        /// identical regardless of input order.
        #[test]
        fn prop_member_vec_reorder_invariance(
            m in arb_members(),
            permutation_seed in any::<u64>(),
        ) {
            let bytes_a = m.canonical_bytes().expect("encode a");
            let hash_a = m.hash_hex().expect("hash a");

            let mut shuffled = m;
            if !shuffled.members.is_empty() {
                let rot = (permutation_seed as usize) % shuffled.members.len();
                shuffled.members.rotate_left(rot);
            }
            shuffled.members.reverse();

            let bytes_b = shuffled.canonical_bytes().expect("encode b");
            let hash_b = shuffled.hash_hex().expect("hash b");
            prop_assert_eq!(bytes_a, bytes_b);
            prop_assert_eq!(hash_a, hash_b);
        }

        /// **Top-level field-reorder invariance.** Shuffling the
        /// top-level `Map` insertion order of the encoded form yields
        /// the same hash when fed back through `canonical_bytes()`.
        #[test]
        fn prop_field_reorder_invariance(m in arb_members()) {
            let original_hash = m.hash_hex().expect("hash");
            let bytes = m.canonical_bytes().expect("encode");
            let Value::Object(map) = serde_json::from_slice::<Value>(&bytes)
                .expect("reparse") else {
                    return Err(TestCaseError::fail("not an object"));
                };
            let mut reversed = Map::new();
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| b.0.cmp(&a.0));
            for (k, v) in entries {
                reversed.insert(k, v);
            }
            let shuffled = serde_json::to_vec(&Value::Object(reversed))
                .expect("encode shuffled");
            let reparsed = TailnetMembers::decode_lenient(&shuffled)
                .expect("lenient decode of reordered");
            let recomputed = reparsed.hash_hex().expect("recompute hash");
            prop_assert_eq!(original_hash, recomputed);
        }

        /// **Hash output stability.** `hash_hex()` is deterministic
        /// and always 64 lowercase hex chars.
        #[test]
        fn prop_hash_hex_is_stable_and_well_formed(m in arb_members()) {
            let h1 = m.hash_hex().expect("hash 1");
            let h2 = m.hash_hex().expect("hash 2");
            prop_assert_eq!(&h1, &h2);
            prop_assert_eq!(h1.len(), HEX_HASH_LEN);
            prop_assert!(h1.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }

        /// **Weak injectivity.** Two member-sets that differ in
        /// `tailnet_id` produce distinct canonical bytes and distinct
        /// hashes.
        #[test]
        fn prop_injectivity_on_distinct_tailnet_ids(
            mut m in arb_members(),
            tid_a in any::<u64>(),
            tid_b in any::<u64>(),
        ) {
            prop_assume!(tid_a != tid_b);
            m.tailnet_id = tid_a;
            let bytes_a = m.canonical_bytes().expect("encode a");
            let hash_a = m.hash_hex().expect("hash a");
            m.tailnet_id = tid_b;
            let bytes_b = m.canonical_bytes().expect("encode b");
            let hash_b = m.hash_hex().expect("hash b");
            prop_assert_ne!(bytes_a, bytes_b);
            prop_assert_ne!(hash_a, hash_b);
        }

        /// Cross-field non-aliasing: `ip_salt` is in the canonical
        /// hash. Otherwise a chain observer who learns the salt can
        /// re-derive tailnet IPs without anchor change.
        #[test]
        fn prop_ip_salt_in_hash(
            mut m in arb_members(),
            sa in any::<[u8; 32]>(),
            sb in any::<[u8; 32]>(),
        ) {
            prop_assume!(sa != sb);
            m.ip_salt = ip_salt_from(&sa);
            let ha = m.hash_hex().expect("ha");
            m.ip_salt = ip_salt_from(&sb);
            let hb = m.hash_hex().expect("hb");
            prop_assert_ne!(ha, hb);
        }

        /// Removing a member changes the hash. Defends against a
        /// regression that hash-caches on member count only.
        #[test]
        fn prop_member_removal_changes_hash(m in arb_members()) {
            prop_assume!(!m.members.is_empty());
            let original = m.hash_hex().expect("original");
            let mut shorter = m;
            shorter.members.pop();
            let trimmed = shorter.hash_hex().expect("trimmed");
            prop_assert_ne!(original, trimmed);
        }

        /// Adding a new (non-duplicate) member changes the hash.
        #[test]
        fn prop_member_addition_changes_hash(
            m in arb_members(),
            new_suffix in "[a-z]{8,16}",
            new_key in any::<[u8; 32]>(),
            joined in any::<u64>(),
        ) {
            let wallet = format!("oct{new_suffix}");
            prop_assume!(!m.members.iter().any(|x| x.wallet == wallet));
            let original = m.hash_hex().expect("original");
            let mut bigger = m;
            bigger.members.push(Member {
                wallet,
                wg_pubkey_b64: crate::b64::encode(new_key),
                joined_epoch: joined,
            });
            bigger.validate().expect("addition validates");
            let with_new = bigger.hash_hex().expect("with new");
            prop_assert_ne!(original, with_new);
        }

        /// `joined_epoch` is part of the canonical encoding. Catches
        /// "members compress to wallet+pubkey only" regressions.
        #[test]
        fn prop_joined_epoch_in_hash(
            m in arb_members(),
            a in any::<u64>(),
            b in any::<u64>(),
        ) {
            prop_assume!(!m.members.is_empty());
            prop_assume!(a != b);
            let mut va = m.clone();
            va.members[0].joined_epoch = a;
            let mut vb = m;
            vb.members[0].joined_epoch = b;
            prop_assert_ne!(va.hash_hex().unwrap(), vb.hash_hex().unwrap());
        }

        /// Cross-field non-aliasing: `effective_epoch` is in the
        /// canonical hash. Otherwise two member sets at different
        /// epochs would share an anchor.
        #[test]
        fn prop_effective_epoch_in_hash(
            mut m in arb_members(),
            a in any::<u64>(),
            b in any::<u64>(),
        ) {
            prop_assume!(a != b);
            m.effective_epoch = a;
            let ha = m.hash_hex().expect("ha");
            m.effective_epoch = b;
            let hb = m.hash_hex().expect("hb");
            prop_assert_ne!(ha, hb);
        }
    }

    #[test]
    fn worked_example_hash_is_stable() {
        // Lock down the worked example used in the schema doc. If
        // anything in canonical_write or member-sort discipline changes,
        // this test will trip and the doc fixture must be updated in
        // lockstep.
        //
        // Fixed WG pubkeys: 32 bytes each of 0x11, 0x22, 0x33 → known
        // base64 forms. Fixed ip_salt: 64 chars of 'a'. This makes the
        // canonical form fully deterministic across machines.
        let alice = Member {
            wallet: "octalice00000000000000000000000000000000000000".to_string(),
            wg_pubkey_b64: wg_pubkey(0x11),
            joined_epoch: 100,
        };
        let bob = Member {
            wallet: "octbob0000000000000000000000000000000000000000".to_string(),
            wg_pubkey_b64: wg_pubkey(0x22),
            joined_epoch: 105,
        };
        let carol = Member {
            wallet: "octcarol00000000000000000000000000000000000000".to_string(),
            wg_pubkey_b64: wg_pubkey(0x33),
            joined_epoch: 110,
        };

        // Build with members in REVERSE wallet order to exercise the
        // sort-on-encode discipline.
        let m = TailnetMembers::new_v1(
            42,
            "a".repeat(IP_SALT_HEX_LEN),
            vec![carol.clone(), bob.clone(), alice.clone()],
            7,
            1_705_000_000,
        );
        m.validate().expect("validate worked example");

        let bytes = m.canonical_bytes().expect("encode");
        let json = std::str::from_utf8(&bytes).expect("utf8");

        // Expected canonical form: outer keys sorted, members sorted by
        // wallet (alice < bob < carol), inner member keys sorted
        // (joined_epoch < wallet < wg_pubkey_b64).
        let expected = format!(
            concat!(
                "{{",
                "\"effective_epoch\":7,",
                "\"ip_salt\":\"{salt}\",",
                "\"members\":[",
                "{{\"joined_epoch\":100,\"wallet\":\"{a_w}\",\"wg_pubkey_b64\":\"{a_k}\"}},",
                "{{\"joined_epoch\":105,\"wallet\":\"{b_w}\",\"wg_pubkey_b64\":\"{b_k}\"}},",
                "{{\"joined_epoch\":110,\"wallet\":\"{c_w}\",\"wg_pubkey_b64\":\"{c_k}\"}}",
                "],",
                "\"tailnet_id\":42,",
                "\"timestamp_secs\":1705000000,",
                "\"v\":1",
                "}}",
            ),
            salt = "a".repeat(IP_SALT_HEX_LEN),
            a_w = alice.wallet,
            a_k = alice.wg_pubkey_b64,
            b_w = bob.wallet,
            b_k = bob.wg_pubkey_b64,
            c_w = carol.wallet,
            c_k = carol.wg_pubkey_b64,
        );
        assert_eq!(json, expected);

        let hash = m.hash_hex().expect("hash");
        // Cross-check against an independent Sha256::digest call.
        let recomputed = hex::encode(Sha256::digest(expected.as_bytes()));
        assert_eq!(hash, recomputed);
        // AML's 64-char invariant.
        assert_eq!(hash.len(), HEX_HASH_LEN);

        // Locked anchor — mirrored verbatim into
        // `docs/v3-members-schema.md` §6. If you changed canonical_write
        // or the member-sort discipline and this trips, the doc fixture
        // is also wrong: update BOTH in lockstep, never just the test.
        //
        // Computed via cargo test the first time; once recorded, do
        // NOT edit this string without also updating the doc.
        let computed_anchor = hash.clone();
        // Sanity: it's lowercase hex of the right length.
        assert!(
            computed_anchor
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "anchor must be lowercase hex"
        );
        // The expected anchor below is the value produced by running
        // the test ONCE against the locked-down canonical form above.
        // It is the same value the schema doc's §6 cites.
        // Locked value — mirrored verbatim into the §6 worked example
        // in `docs/v3-members-schema.md`. If you changed canonical_write
        // or the member-sort discipline and this trips, the doc fixture
        // is also wrong: update BOTH in lockstep, never just the test.
        const EXPECTED_ANCHOR: &str =
            "5a4cd4f99acf35e4fbafa2663710f476a4e5c52c71edf74c40a8d0375160cc15";
        assert_eq!(
            hash, EXPECTED_ANCHOR,
            "worked-example hash drifted from docs/v3-members-schema.md"
        );
        // Suppress unused-variable warning on `computed_anchor` if the
        // assertion above is ever stubbed out during local debugging.
        let _ = computed_anchor;
    }
}
