/-!
# BE-nonce composition — Lean spec & proofs.

Mirrors `nonce_be` + `BeTransport` in
`headscale-rs/headscale-api/src/tailscale_wire/be_transport.rs`
(lines 139-143 and 195-246).

Tailscale's `controlbase` deviates from the Noise spec in exactly one
place: the 12-byte ChaCha20Poly1305 nonce has the 64-bit counter encoded
**big-endian**, not little-endian. The Rust function is:

```rust
fn nonce_be(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    n
}
```

This file proves the composition layer (`buildNonceBE`) correct:

  * the first 4 bytes are zero (`nonce_first_four_bytes_zero`);
  * the trailing 8 bytes are determined by the counter
    (`nonce_be_suffix_is_counter`);
  * distinct counters produce distinct nonces
    (`counter_monotonic_encrypts_distinct_nonces`);
  * advancing the counter is strictly monotonic
    (`counter_advance_strictly_increases`).

The AEAD itself (ChaCha20Poly1305) is treated as an opaque primitive —
the same modeling strategy used by `OctraVPN_Rust/Spec.lean` for the
sealed-envelope AEAD. We do not prove that `to_be_bytes` is a
bijection on `< 2^64` Nats — that's a pure-arithmetic identity
audited at the `u64::to_be_bytes` call site; we record it as a single
axiom (`u64be_injective`) the same way `OctraVPN_Rust/Lemmas.lean`
treats `u32be_injective` / `u64be_injective` (see lines 21-24 of that
file).
-/

namespace OctraVPN.WireProtocol.BeNonce

abbrev ByteString := List UInt8

/-- A 12-byte ChaCha20Poly1305 nonce. We carry it as a fixed-length
    `List UInt8`; length invariant is proven below. -/
abbrev Nonce12 := ByteString

/-- Opaque BE encoding of a `Nat` counter (assumed < 2^64) into
    exactly 8 bytes. Mirrors Rust's `counter.to_be_bytes()`. We
    model the encoder as opaque + axiomatically length 8 + injective,
    matching the modeling style of `OctraVPN_Rust/Spec.lean`. -/
opaque u64be : Nat → ByteString := fun _ => [0,0,0,0,0,0,0,0]

/-- Axiom: `u64be` outputs exactly 8 bytes. (Standard fact about
    `u64::to_be_bytes`; same style as `u32be_length` in the Rust
    primitives module.) -/
axiom u64be_length (n : Nat) : (u64be n).length = 8

/-- Axiom: `u64be` is injective on values `< 2^64`. -/
axiom u64be_injective {a b : Nat} (ha : a < 2^64) (hb : b < 2^64)
    (h : u64be a = u64be b) : a = b

/-- Compose a 12-byte BE nonce from a counter:
    `[0, 0, 0, 0] ++ counter.to_be_bytes()`. Mirrors the Rust:

    ```rust
    fn nonce_be(counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&counter.to_be_bytes());
        n
    }
    ```
-/
def buildNonceBE (counter : Nat) : Nonce12 :=
  [0, 0, 0, 0] ++ u64be counter

/-- Extract the 8-byte counter suffix from a 12-byte BE nonce. -/
def nonceSuffix (n : Nonce12) : ByteString := n.drop 4

/-- A nonce-counter pair witnesses one direction (send or recv) of a
    `BeTransport`. Mirrors the `send_counter` / `recv_counter` fields
    in `be_transport.rs::BeTransport`. -/
structure CounterState where
  counter : Nat
  deriving Repr, DecidableEq, Inhabited

/-- Advance the counter by one. Mirrors
    `be_transport.rs:212-215`'s `checked_add(1)`. We model the
    overflow gate as `counter + 1`; the Rust path returns
    `NonceExhausted` at 2^64 but Lean's `Nat` is unbounded, so the
    monotonicity property below holds without that side-condition. -/
def CounterState.advance (s : CounterState) : CounterState :=
  { counter := s.counter + 1 }

-- ============================================================
-- §1  nonce shape: length 12, first 4 bytes zero
-- ============================================================

/-- `buildNonceBE` always produces a 12-byte nonce. -/
theorem nonce_length (c : Nat) : (buildNonceBE c).length = 12 := by
  unfold buildNonceBE
  rw [List.length_append]
  rw [u64be_length]
  rfl

/-- The first four bytes of a BE nonce are all zero. Mirrors the
    Rust `n[0..4]` zero-prefix that the
    `chacha20poly1305::Nonce::from_slice(&nonce_bytes)` call relies
    on for IETF-AEAD nonce shape. We state this as the prefix being
    `[0, 0, 0, 0]` rather than going byte-by-byte. -/
theorem nonce_first_four_bytes_zero (c : Nat) :
    (buildNonceBE c).take 4 = [0, 0, 0, 0] := by
  unfold buildNonceBE
  -- [0,0,0,0] ++ xs has take 4 = [0,0,0,0] (provided xs is anything).
  rfl

/-- Index-form of `nonce_first_four_bytes_zero`: byte `i < 4` is 0. -/
theorem nonce_byte_zero_at (c : Nat) (i : Nat) (hi : i < 4) :
    (buildNonceBE c).get? i = some 0 := by
  unfold buildNonceBE
  -- (([0,0,0,0] : ByteString) ++ rest).get? i for i < 4 is some 0.
  match i, hi with
  | 0, _ => rfl
  | 1, _ => rfl
  | 2, _ => rfl
  | 3, _ => rfl

-- ============================================================
-- §2  counter ↔ trailing bytes
-- ============================================================

/-- The trailing 8 bytes of a BE nonce equal `u64be counter`. -/
theorem nonce_be_suffix_is_counter (c : Nat) :
    nonceSuffix (buildNonceBE c) = u64be c := by
  unfold buildNonceBE nonceSuffix
  -- drop 4 ([0,0,0,0] ++ xs) = xs
  simp

/-- Injective recovery: two BE nonces are equal iff their counters
    are (within u64 range). Phrased here as: the nonce determines
    the counter. -/
theorem nonce_be_determines_counter
    (c c' : Nat) (h1 : c < 2^64) (h2 : c' < 2^64)
    (h : buildNonceBE c = buildNonceBE c') : c = c' := by
  have hs : u64be c = u64be c' := by
    have e : nonceSuffix (buildNonceBE c) = nonceSuffix (buildNonceBE c') := by
      rw [h]
    rw [nonce_be_suffix_is_counter, nonce_be_suffix_is_counter] at e
    exact e
  exact u64be_injective h1 h2 hs

-- ============================================================
-- §3  Counter distinctness (replay-window correctness)
-- ============================================================

/-- **Counter monotonicity ⇒ distinct nonces.** Different counter
    values (within u64 range) produce different BE nonces. This is the
    composition-level correctness that makes the strict-monotonic
    replay rule sound: every encrypt at a different `send_counter`
    gets a fresh nonce, and every decrypt at a different
    `recv_counter` rejects with AEAD-tag-mismatch. -/
theorem counter_monotonic_encrypts_distinct_nonces
    (c₁ c₂ : Nat) (h1 : c₁ < 2^64) (h2 : c₂ < 2^64) (hne : c₁ ≠ c₂) :
    buildNonceBE c₁ ≠ buildNonceBE c₂ := by
  intro heq
  exact hne (nonce_be_determines_counter c₁ c₂ h1 h2 heq)

/-- **Counter advance is strictly monotonic.** Mirrors the Rust
    semantic that `BeTransport::encrypt` (line 195) and
    `BeTransport::decrypt` (line 228) increment their counter by
    exactly 1 on every success. -/
theorem counter_advance_strictly_increases (s : CounterState) :
    s.advance.counter = s.counter + 1 := rfl

/-- **Replay-window correctness.** Two distinct positions in a
    monotonically advancing send-counter sequence yield distinct
    nonces, so a replayed ciphertext at the receiver (whose
    `recv_counter` has already advanced) will deterministically fail
    AEAD-decrypt. This is the algebraic claim behind the upstream
    "strict monotonic, no sliding window" semantic at
    `be_transport.rs:54-65`. -/
theorem replay_window_distinct_nonces
    (start : Nat) (i j : Nat)
    (h_bound : start + max i j < 2^64) (h_ne : i ≠ j) :
    buildNonceBE (start + i) ≠ buildNonceBE (start + j) := by
  apply counter_monotonic_encrypts_distinct_nonces
  · have h1 : start + i ≤ start + max i j :=
      Nat.add_le_add_left (Nat.le_max_left i j) start
    omega
  · have h2 : start + j ≤ start + max i j :=
      Nat.add_le_add_left (Nat.le_max_right i j) start
    omega
  · intro h; apply h_ne; omega

-- ============================================================
-- §4  Concrete-value anchor
-- ============================================================

/-- Concrete anchor: counter advance from 0 gives counter 1. -/
example :
    ({ counter := 0 } : CounterState).advance.counter = 1 := rfl

/-- Concrete anchor: the BE nonce always has 12 bytes total. -/
example : (buildNonceBE 0).length = 12 := nonce_length 0

end OctraVPN.WireProtocol.BeNonce
