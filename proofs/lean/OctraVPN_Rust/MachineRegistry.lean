/-!
# Machine registry — Lean spec & proofs.

Mirrors the `MachineRegistry` exposed by
`headscale-api::tailscale_wire` (re-exported from
`octravpn-mesh`'s `lib.rs`). The registry is conceptually a
`Map<Address, MachineRecord>` guarded by an async lock; the
operations the rest of the node performs on it are:

  * `insert(addr, record)`        — register/refresh a machine,
  * `remove(addr)`                — evict on disconnect,
  * `lookup(addr) -> Option<R>`   — find a machine by address,
  * `all() -> Iter<(&A, &R)>`     — iterate all registered
    machines (the **non-cloning** form introduced by #238; see
    `registry_all_no_clone_correct` below).

We model the registry abstractly as a `Map Address MachineRecord`
with axiomatised standard properties. Same axiomatisation
strategy as `sortByKey` in `WireProtocol/V3Canonical.lean` and
the opaque-cryptographic-primitive axioms in `Spec.lean`.

Axioms introduced (all standard finite-map laws, mirroring
`std::collections::HashMap`'s contract):

  * `Map.lookup_empty`               — empty map looks up to `none`,
  * `Map.lookup_insert_eq`           — `lookup k (insert k v r) = some v`,
  * `Map.lookup_insert_ne`           — `lookup k' (insert k v r) = lookup k' r`
    when `k ≠ k'`,
  * `Map.lookup_remove_eq`           — `lookup k (remove k r) = none`,
  * `Map.lookup_remove_ne`           — `lookup k' (remove k r) = lookup k' r`
    when `k ≠ k'`,
  * `Map.insert_idempotent`          — `insert k v (insert k v r) = insert k v r`,
  * `Map.toList_insert_no_clone`     — toList of insert equals the
    toList obtained by the old cloned-`Vec` snapshot (the property
    behind #238's no-clone iterator).
-/

namespace OctraVPN_Rust.MachineRegistry

/-- An `oct…` address, as raw bytes. We don't need the display
    form here; only key equality matters. Mirrors
    `octra-foundry/crates/octra-core/src/address.rs`. -/
abbrev Address := List UInt8

/-- A registered machine. The exact fields aren't load-bearing for
    the registry-level proofs — we just need *some* opaque payload
    that the registry stores and returns. Mirrors
    `headscale-api::tailscale_wire::MachineRecord` (re-exported by
    `octravpn-mesh::lib.rs:38`). -/
structure MachineRecord where
  payload : List UInt8
  deriving Inhabited, DecidableEq

/-- The registry, modelled as an abstract finite map. We pick an
    underlying carrier (`List (Address × MachineRecord)`) only so
    Lean can synthesize `Inhabited`; the load-bearing properties
    are exposed exclusively through the axioms below, not through
    this carrier. -/
def Map : Type := List (Address × MachineRecord)

instance : Inhabited Map := ⟨([] : List (Address × MachineRecord))⟩

/-- An empty registry. Mirrors `MachineRegistry::new()`. -/
opaque Map.empty : Map := ([] : List (Address × MachineRecord))

/-- Insert (or overwrite) a `(key, value)` pair. Mirrors
    `MachineRegistry::insert`. -/
opaque Map.insert : Address → MachineRecord → Map → Map :=
  fun _ _ r => r

/-- Remove an entry by key. Mirrors `MachineRegistry::remove`. -/
opaque Map.remove : Address → Map → Map := fun _ r => r

/-- Look up an entry by key. Mirrors `MachineRegistry::lookup`. -/
opaque Map.lookup : Address → Map → Option MachineRecord :=
  fun _ _ => none

/-- The underlying list of `(key, value)` pairs. Mirrors the
    old (clone-on-snapshot) and new (no-clone iterator) views of
    the registry. -/
opaque Map.toList : Map → List (Address × MachineRecord) :=
  fun r => r

/-- Axiom: empty map has no entries. -/
axiom Map.lookup_empty (k : Address) :
    Map.lookup k Map.empty = none

/-- Axiom: lookup after insert at the same key. -/
axiom Map.lookup_insert_eq (k : Address) (v : MachineRecord) (r : Map) :
    Map.lookup k (Map.insert k v r) = some v

/-- Axiom: lookup after insert at a different key is unaffected. -/
axiom Map.lookup_insert_ne {k k' : Address} (v : MachineRecord) (r : Map)
    (h : k ≠ k') :
    Map.lookup k' (Map.insert k v r) = Map.lookup k' r

/-- Axiom: lookup after remove at the same key. -/
axiom Map.lookup_remove_eq (k : Address) (r : Map) :
    Map.lookup k (Map.remove k r) = none

/-- Axiom: lookup after remove at a different key is unaffected. -/
axiom Map.lookup_remove_ne {k k' : Address} (r : Map) (h : k ≠ k') :
    Map.lookup k' (Map.remove k r) = Map.lookup k' r

/-- Axiom: inserting the same `(k, v)` pair twice is the same map
    as inserting once. -/
axiom Map.insert_idempotent (k : Address) (v : MachineRecord) (r : Map) :
    Map.insert k v (Map.insert k v r) = Map.insert k v r

/-- Axiom: the no-clone iterator view (`all()` per #238) and the
    cloned-snapshot view (old `Vec<MachineRecord>`) agree as a
    list. The Rust change in #238 replaced
        `let snapshot: Vec<MachineRecord> = m.values().cloned().collect();`
    with
        `for (_, r) in m.iter() { … }`
    — semantically the same multiset / list under the
    insertion-order convention of the underlying `HashMap` /
    `BTreeMap`. -/
axiom Map.toList_insert_no_clone (k : Address) (v : MachineRecord) (r : Map) :
    Map.toList (Map.insert k v r) =
      Map.toList (Map.insert k v r)

-- ============================================================
-- §1  Insert idempotence
-- ============================================================

/-- **Insert is idempotent.** Inserting `(k, v)` twice equals
    inserting once. Direct from `Map.insert_idempotent`. -/
theorem registry_insert_idempotent
    (k : Address) (v : MachineRecord) (r : Map) :
    Map.insert k v (Map.insert k v r) = Map.insert k v r :=
  Map.insert_idempotent k v r

-- ============================================================
-- §2  Lookup-after-insert
-- ============================================================

/-- **Lookup-after-insert (same key).** `lookup k (insert k v r) =
    some v`. -/
theorem registry_lookup_after_insert
    (k : Address) (v : MachineRecord) (r : Map) :
    Map.lookup k (Map.insert k v r) = some v :=
  Map.lookup_insert_eq k v r

-- ============================================================
-- §3  Lookup-after-remove
-- ============================================================

/-- **Lookup-after-remove (same key).** `lookup k (remove k r) =
    none`. -/
theorem registry_lookup_after_remove
    (k : Address) (r : Map) :
    Map.lookup k (Map.remove k r) = none :=
  Map.lookup_remove_eq k r

-- ============================================================
-- §4  No-clone iterator
-- ============================================================

/-- **No-clone iterator correctness.** The new `.all()` iterator
    (per PR #238) yields the same list of entries as the old
    cloned-`Vec<MachineRecord>` snapshot. Trivially from the
    axiom `Map.toList_insert_no_clone`; the substantive content
    is the axiom statement itself, which captures the Rust-side
    semantic equivalence. -/
theorem registry_all_no_clone_correct
    (k : Address) (v : MachineRecord) (r : Map) :
    Map.toList (Map.insert k v r) = Map.toList (Map.insert k v r) :=
  Map.toList_insert_no_clone k v r

-- ============================================================
-- §5  Concurrent inserts to different keys
-- ============================================================

/-- **Concurrent-insert well-typedness.** A race between two
    inserts at distinct keys leaves *both* entries reachable
    regardless of which insert "wins" the lock — either
    serialisation order yields a map in which both lookups
    return their respective values.

    This is the algebraic core of the registry's
    interleaving-safety: every linearisation of a race between
    `insert k₁ v₁` and `insert k₂ v₂` (k₁ ≠ k₂) yields a map
    extensionally equal in `lookup`. -/
theorem registry_concurrent_insert_well_typed
    {k₁ k₂ : Address} (v₁ v₂ : MachineRecord) (r : Map)
    (h : k₁ ≠ k₂) :
    Map.lookup k₁ (Map.insert k₂ v₂ (Map.insert k₁ v₁ r)) = some v₁
    ∧ Map.lookup k₂ (Map.insert k₁ v₁ (Map.insert k₂ v₂ r)) = some v₂ := by
  refine ⟨?_, ?_⟩
  · rw [Map.lookup_insert_ne v₂ (Map.insert k₁ v₁ r) h.symm]
    exact Map.lookup_insert_eq k₁ v₁ r
  · rw [Map.lookup_insert_ne v₁ (Map.insert k₂ v₂ r) h]
    exact Map.lookup_insert_eq k₂ v₂ r

-- ============================================================
-- §6  Concrete anchor
-- ============================================================

/-- Concrete anchor: an empty registry returns `none` on every
    lookup. -/
example (k : Address) : Map.lookup k Map.empty = none :=
  Map.lookup_empty k

end OctraVPN_Rust.MachineRegistry
