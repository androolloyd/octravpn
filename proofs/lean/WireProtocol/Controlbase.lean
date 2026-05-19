/-!
# Controlbase framing — Lean spec & proofs.

Mirrors the byte layout in
`headscale-rs/headscale-api/src/tailscale_wire/controlbase.rs`
(see lines 19-23 + the `write_initiation` / `write_frame` implementations
at lines 222-272).

## Wire layout

| Header     | Bytes | First byte         | Used by                                   |
| ---------- | ----- | ------------------ | ----------------------------------------- |
| Regular    | 3     | `msg_type ∈ {2,3,4}` | Reply (2), Error (3), Record (4)        |
| Initiation | 5     | `0x00` (version hi) | Initiation (1) — carries protoVersion    |

Regular:  `[msg_type:u8][len:u16be]` + body.
Initiation: `[ver_hi:u8][ver_lo:u8][type=1:u8][len:u16be]` + body.

The Rust reader (`controlbase.rs::Framed::read_frame`, lines 148-220)
disambiguates layouts on the first byte: `0x00` → Initiation (5-byte
header), `0x02 / 0x03 / 0x04` → Regular (3-byte header). This file
proves the matching algebraic round-trip + length invariants for the
pure `encodeHeader` / `decodeHeader` functions.

We do not model the body — the body is opaque payload bytes and the
framing layer simply length-prefixes it. The body round-trip is
covered by the Rust integration test
`crates/octravpn-node/tests/tailscale_wire_integration.rs::ts2021_be_transport_round_trips_record`.

`u16be` (big-endian u16 encode) is treated opaquely with two axioms:
length = 2 and injectivity. This matches the modeling style of
`OctraVPN_Rust/Spec.lean` (`u32be_injective` / `u64be_injective`).
-/

namespace OctraVPN.WireProtocol.Controlbase

abbrev ByteString := List UInt8

/-- Tailscale `controlbase` message type byte. Wire values mirror
    `controlbase.rs::MsgType` (lines 76-93). -/
inductive MsgType where
  | initiation : MsgType
  | reply      : MsgType
  | error      : MsgType
  | record     : MsgType
  deriving DecidableEq, Repr, Inhabited

def MsgType.toByte : MsgType → UInt8
  | .initiation => 1
  | .reply      => 2
  | .error      => 3
  | .record     => 4

def MsgType.fromByte (b : UInt8) : Option MsgType :=
  if b = 1 then some .initiation
  else if b = 2 then some .reply
  else if b = 3 then some .error
  else if b = 4 then some .record
  else none

/-- Round-trip on the type byte. -/
theorem MsgType.fromByte_toByte (mt : MsgType) :
    MsgType.fromByte mt.toByte = some mt := by
  cases mt <;> rfl

/-- Headers come in two layouts. `Initiation` carries a 16-bit
    `protocolVersion`; `Regular` carries the message type. Both
    carry a 16-bit body length. -/
inductive FrameHeader where
  | regular    (msgType : MsgType) (len : UInt16) : FrameHeader
  | initiation (protocolVersion : UInt16) (len : UInt16) : FrameHeader
  deriving Repr, Inhabited

/-- Opaque BE encoding for a `UInt16`. Mirrors Rust's
    `u16::to_be_bytes()`. Same modeling style as `u64be` and
    `OctraVPN_Rust/Spec.lean::u32be`. -/
opaque u16be : UInt16 → ByteString := fun _ => [0, 0]

/-- Axiom: `u16be` outputs exactly 2 bytes. -/
axiom u16be_length (n : UInt16) : (u16be n).length = 2

/-- Axiom: `u16be` is injective. -/
axiom u16be_injective {a b : UInt16} (h : u16be a = u16be b) : a = b

/-- Axiom: the bytes produced by `u16be n` for `n < 256` start with `0`.
    Equivalent to: the high-byte of `n.toNat / 256` is zero when
    `n.toNat < 256`. Used by the initiation-header disambiguation. -/
axiom u16be_lo_first_byte (n : UInt16) (h : n.toNat < 256) :
    (u16be n).headD 0 = 0

/-- Opaque decoder for a 2-byte BE u16. Round-trips with `u16be`. -/
opaque decodeU16BE : ByteString → Option UInt16 := fun _ => none

/-- Axiom: `decodeU16BE` is the inverse of `u16be`. -/
axiom decodeU16BE_u16be (n : UInt16) : decodeU16BE (u16be n) = some n

/-- Initiation frames have `protocol_version < 256`. The Rust reader
    (`controlbase.rs:165-169`) enforces this implicitly via the first-
    byte 0x00 check. We carry it as a well-formedness predicate. -/
def FrameHeader.wellFormed : FrameHeader → Prop
  | .regular mt _    => mt ≠ MsgType.initiation
  | .initiation v _  => v.toNat < 256

/-- Encode a header to its on-the-wire bytes. Mirrors the
    `write_frame` / `write_initiation` paths of `controlbase.rs`. -/
def encodeHeader : FrameHeader → ByteString
  | .regular mt len =>
      [mt.toByte] ++ u16be len
  | .initiation ver len =>
      u16be ver ++ [MsgType.initiation.toByte] ++ u16be len

/-- Decode an Initiation header (5-byte layout). Returns `none`
    unless the bytes match `[0, _, 1, _, _]` exactly. -/
def decodeInitiation (b0 b1 b2 b3 b4 : UInt8) : Option FrameHeader :=
  if b0 = 0 ∧ b2 = MsgType.initiation.toByte then
    match decodeU16BE [b0, b1], decodeU16BE [b3, b4] with
    | some ver, some len => some (.initiation ver len)
    | _, _ => none
  else
    none

/-- Decode a Regular header (3-byte layout). Returns `none` if the
    type byte is invalid or is the Initiation byte. -/
def decodeRegular (b0 b1 b2 : UInt8) : Option FrameHeader :=
  match MsgType.fromByte b0 with
  | some mt =>
      if mt = MsgType.initiation then none
      else
        match decodeU16BE [b1, b2] with
        | some len => some (.regular mt len)
        | none => none
  | none => none

/-- Decode a header from its on-the-wire bytes. Mirrors the
    `read_frame` disambiguation logic (`controlbase.rs:148-220`).
    If the buffer is long enough for an Initiation (5+ bytes) and
    the first byte is 0, parse as Initiation. Otherwise parse the
    first 3 bytes as Regular. -/
def decodeHeader : ByteString → Option FrameHeader
  | (b0 :: b1 :: b2 :: b3 :: b4 :: _) =>
      if b0 = 0 then decodeInitiation b0 b1 b2 b3 b4
      else decodeRegular b0 b1 b2
  | (b0 :: b1 :: b2 :: []) =>
      if b0 = 0 then none else decodeRegular b0 b1 b2
  | _ => none

-- ============================================================
-- §1  encode_header length invariants
-- ============================================================

/-- Regular headers encode to exactly 3 bytes. Mirrors
    `controlbase.rs:236-243` (`hdr = [0u8; 3]`). -/
theorem encode_regular_length (mt : MsgType) (len : UInt16) :
    (encodeHeader (.regular mt len)).length = 3 := by
  unfold encodeHeader
  simp [List.length_append, u16be_length]

/-- Initiation headers encode to exactly 5 bytes. Mirrors
    `controlbase.rs:263-272` (`hdr = [0u8; 5]`). -/
theorem encode_initiation_length (ver len : UInt16) :
    (encodeHeader (.initiation ver len)).length = 5 := by
  unfold encodeHeader
  simp [List.length_append, u16be_length]

/-- A header always encodes to either 3 or 5 bytes. -/
theorem header_length_correct (h : FrameHeader) :
    (encodeHeader h).length = 3 ∨ (encodeHeader h).length = 5 := by
  cases h with
  | regular mt len     => left;  exact encode_regular_length mt len
  | initiation ver len => right; exact encode_initiation_length ver len

/-- Initiation frames are distinguishable on the wire by their
    5-byte header. -/
theorem initiation_distinguishable (h : FrameHeader)
    (hi : ∃ v len, h = .initiation v len) :
    (encodeHeader h).length = 5 := by
  obtain ⟨v, len, rfl⟩ := hi
  exact encode_initiation_length v len

-- ============================================================
-- §2  Type-byte round-trip + distinctness
-- ============================================================

/-- The type byte of a non-Initiation MsgType is nonzero. -/
theorem MsgType.toByte_nonzero_for_regular
    (mt : MsgType) (h : mt ≠ MsgType.initiation) :
    mt.toByte ≠ 0 := by
  cases mt with
  | initiation => exact absurd rfl h
  | reply  => intro; contradiction
  | error  => intro; contradiction
  | record => intro; contradiction

/-- The Initiation type byte equals 1 (literal from upstream). -/
theorem MsgType.initiation_toByte_eq_one :
    MsgType.initiation.toByte = 1 := rfl

-- ============================================================
-- §3  Header round-trip
-- ============================================================

/-- The two-byte `u16be` always has length 2, so destructuring as
    `[b0, b1]` is safe. We surface the head/tail bytes explicitly
    for the round-trip proof. -/
theorem u16be_destruct (n : UInt16) :
    ∃ b0 b1, u16be n = [b0, b1] := by
  have hlen : (u16be n).length = 2 := u16be_length n
  match h : u16be n with
  | [] => exfalso; rw [h] at hlen; simp at hlen
  | [_] => exfalso; rw [h] at hlen; simp at hlen
  | [b0, b1] => exact ⟨b0, b1, rfl⟩
  | _ :: _ :: _ :: _ =>
      exfalso
      rw [h] at hlen
      simp at hlen

/-- **Regular header round-trip.** -/
theorem regular_header_round_trip (mt : MsgType) (len : UInt16)
    (h_wf : mt ≠ MsgType.initiation) :
    decodeHeader (encodeHeader (.regular mt len)) = some (.regular mt len) := by
  obtain ⟨b1, b2, hu⟩ := u16be_destruct len
  have henc : encodeHeader (.regular mt len) = [mt.toByte, b1, b2] := by
    show [mt.toByte] ++ u16be len = _
    rw [hu]; rfl
  rw [henc]
  have hb0_ne : mt.toByte ≠ 0 := MsgType.toByte_nonzero_for_regular mt h_wf
  unfold decodeHeader
  simp only [hb0_ne, if_false]
  unfold decodeRegular
  rw [MsgType.fromByte_toByte]
  simp only [h_wf, if_false]
  have hd : decodeU16BE [b1, b2] = some len := by
    rw [← hu]; exact decodeU16BE_u16be len
  rw [hd]

/-- **Initiation header round-trip.** -/
theorem initiation_header_round_trip (ver len : UInt16)
    (h_wf : ver.toNat < 256) :
    decodeHeader (encodeHeader (.initiation ver len)) = some (.initiation ver len) := by
  obtain ⟨v0, v1, hv⟩ := u16be_destruct ver
  obtain ⟨l0, l1, hl⟩ := u16be_destruct len
  -- first byte v0 must be zero (ver < 256)
  have hv0 : v0 = 0 := by
    have h := u16be_lo_first_byte ver h_wf
    rw [hv] at h
    simp [List.headD] at h
    exact h
  subst hv0
  have henc : encodeHeader (.initiation ver len) =
              [0, v1, MsgType.initiation.toByte, l0, l1] := by
    show u16be ver ++ [MsgType.initiation.toByte] ++ u16be len = _
    rw [hv, hl]; rfl
  rw [henc]
  unfold decodeHeader
  simp only [if_true]
  unfold decodeInitiation
  have htype : MsgType.initiation.toByte = 1 := rfl
  simp [htype]
  have hv_dec : decodeU16BE [0, v1] = some ver := by
    rw [← hv]; exact decodeU16BE_u16be ver
  have hl_dec : decodeU16BE [l0, l1] = some len := by
    rw [← hl]; exact decodeU16BE_u16be len
  rw [hv_dec, hl_dec]

/-- **Header round-trip (combined).** For any well-formed header,
    decoding the encoded bytes recovers the original header. -/
theorem header_round_trip (h : FrameHeader) (hwf : h.wellFormed) :
    decodeHeader (encodeHeader h) = some h := by
  cases h with
  | regular mt len =>
      exact regular_header_round_trip mt len hwf
  | initiation ver len =>
      exact initiation_header_round_trip ver len hwf

/-- Concrete anchor: an Initiation(39, 10) round-trips. 39 is the
    Tailscale wire-protocol version negotiated as of Wall-5. -/
example :
    decodeHeader (encodeHeader (.initiation (39 : UInt16) (10 : UInt16)))
    = some (.initiation (39 : UInt16) (10 : UInt16)) := by
  apply initiation_header_round_trip
  decide

end OctraVPN.WireProtocol.Controlbase
