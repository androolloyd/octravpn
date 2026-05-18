# Real AML Grammar — Reverse-Engineered Reference

Captured 2026-05-13, refreshed 2026-05-17 against the public Circles
release. Built by compiling our placeholder AML against live mainnet
`octra_compileAml` (no auth, no fee, public RPC) and reading
`octra-labs/contract-examples/example_1.aml` and (since 2026-05-15)
`octra-labs/program-examples/*.aml` plus `octra-labs/webcli` commit
`f9c73e1`. All claims below are tested.

This is the authoritative reference for what `program/main.aml` must
look like to compile. Our previous AML used `program`/`implements`/
`interface`/`import` keywords that **do not exist** in real Octra.

## 1. Top-level structure

**One file, one contract.** No imports, no interfaces.

```aml
contract Name {
  // enum declarations
  // struct declarations
  // event declarations
  // const declarations
  // state block
  // constructor
  // fn / view fn definitions
}
```

## 2. Types

| Type           | Notes                                                                 |
| -------------- | --------------------------------------------------------------------- |
| `int`          | Confirmed. Signed integer (negative values shown in `self.active_model = -1`). |
| `address`      | Confirmed. Built-in.                                                   |
| `string`       | Confirmed. Used for FHE ciphertexts, names, etc.                       |
| `bool`         | Confirmed as a return type. `true`/`false` literals.                   |
| `bytes`        | Confirmed (2026-05-17). **Length-counted UTF-8 string**, not raw octets. `len(b) == 32` matches a 32-character string; hex of a 32-byte hash (64 chars) and base64 (44 chars) BOTH fail that predicate. See §7.1. |
| `map[K]V`      | Confirmed. K = int/address/string; V = any type including struct or nested map. |
| `map[K1]map[K2]V` | Confirmed. Nested maps work directly.                              |
| `list[T]`      | NOT confirmed in example. Avoid; use `map[int]T` + counter.            |
| Enum types     | First-class. Reference as `EnumName.Variant`.                         |
| Struct types   | First-class. Use as `map[int]Struct`, access fields via `[i].field`.   |

## 3. Declarations

### Enum

```aml
enum Status { Draft, Active, Deprecated, Locked }
```

Reference: `Status.Active`. Internal representation is `int`.

### Struct

```aml
struct Model {
  num_features: int
  bias: int
  status: int
}
```

Field separators: newlines, no commas. Field access via dot from
either local var or map index: `self.models[id].bias`.

### Event

```aml
event ModelCreated(model_id: int, num_features: int, fee: int)
event WhitelistChanged(addr: address, allowed: int)
```

Emit with `emit EventName(args, ...)`.

### Const

```aml
const MAX_MODELS: int = 64
const FEE_DENOMINATOR: int = 10000
```

### State block

```aml
state {
  owner: address
  models: map[int]Model
  weights: map[int]map[int]int
  whitelist: map[address]int
}
```

### Constructor

```aml
constructor(n: string, features: int) {
  require(features > 0, "zero features")
  self.owner = origin
  // ...
}
```

### Function

```aml
fn create_model(features: int, fee: int): int {
  require(caller == self.owner, "not owner")
  let id = self.model_count
  self.model_count += 1
  return id
}

view fn get_owner(): address {
  return self.owner
}
```

`view fn` indicates a read-only function; `fn` mutates state.
`private fn` — NOT confirmed in example.

### Function modifiers (confirmed 2026-05-17)

`octra-labs/program-examples` added two modifiers used in widespread
production AML after the 2026-05-15 Circles release. Both work
against the live `octra_compileAml`.

```aml
fn register_circle(circle_id: address) payable {
  require(value >= self.min_circle_stake, "bond too low")
  // value is the OU attached to this call
  self.circle_stake[circle_id] = value
  // ...
}

fn settle_session(sid: bytes, bytes_used: int) nonreentrant {
  // re-entrancy guard: contract-to-contract calls inside this fn
  // cannot re-enter the contract via any path.
  let pay = bytes_used * self.circles[sid].price_per_mb
  transfer(self.circles[sid].owner, pay)
  // ...
}
```

- `payable` — entrypoint can accept `value > 0`. Non-payable
  entrypoints reject any tx with `value != 0`.
- `nonreentrant` — guards against re-entry via callbacks. Combined
  with `checkpoint`/`commit`/`rollback` (§6) this is the canonical
  CEI-pattern construction.

Modifiers stack: `fn foo() payable nonreentrant { ... }` is valid.

## 4. Statements & expressions

### Locals

```aml
let id = self.model_count
let st = self.models[id].status
let pk = fhe_load_pk(pk_addr)
```

### Control flow

```aml
if cond { ... }
if cond { ... } else { ... }

// Range-for loop:
for i in 0..n {
  sum += self.weights[mid][i] * mget(2000 + i)
}

// While loops: NOT confirmed in example. Use for/range instead.
```

No parentheses around `if`/`for` conditions.

### Assignment

```aml
self.field = value
self.field += value
self.field -= value
self.field *= value
self.field /= value
```

### Comparisons & logic

```aml
caller == self.owner
st == ModelStatus.Active
mid >= 0 && mid < self.model_count
ptype == 0 || ptype == 1
!ok
```

Operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `!`.

### Return

```aml
return value
return true
```

## 5. Built-in identifiers

Available everywhere:

- `caller` — immediate caller of the current call.
- `origin` — the original signer of the transaction.
- `value` — OU sent along with this call.
- `epoch` — current Octra epoch.
- `self` — the contract instance; access state via `self.field`.

`self_addr` — not seen in example_1.aml; may not exist.

## 6. Host calls (confirmed in example_1.aml)

### Runtime helpers

| Call                              | Returns  | Notes                                                                 |
| --------------------------------- | -------- | --------------------------------------------------------------------- |
| `require(cond, msg)`              | —        | Aborts call with `msg` if `cond` is false.                            |
| `transfer(addr, amount)`          | `bool`   | Sends OU to addr. Returns success.                                    |
| `emit Event(args...)`             | —        | Records an event in the tx receipt.                                   |
| `checkpoint()`                    | —        | Snapshot state for try/rollback.                                      |
| `commit()`                        | —        | Discard the checkpoint (changes persist).                             |
| `rollback()`                      | —        | Revert to the last checkpoint.                                        |
| `concat(s1, s2)`                  | `string` | String concatenation.                                                 |
| `to_string(int)`                  | `string` | Int → decimal string.                                                 |
| `parse_ints(csv_str, mid_offset)` | `int`    | Parses a comma-separated int list; writes ints to "mailbox" memory at `mid_offset..mid_offset+N`. Returns N. |
| `mget(offset)`                    | `int`    | Reads from the "mailbox" memory at offset.                            |

### FHE primitives

All confirmed in example_1.aml:

| Call                                | Returns      | Notes                                                |
| ----------------------------------- | ------------ | ---------------------------------------------------- |
| `fhe_load_pk(addr: string)`         | pk (opaque)  | Loads HFHE pubkey by its registered address.         |
| `fhe_deser(s: string)`              | ct (opaque)  | Deserialise ciphertext from wire format.             |
| `fhe_ser(ct)`                       | `string`     | Serialise to wire format.                            |
| `fhe_add(pk, a, b)`                 | ct           | Encrypted addition.                                  |
| `fhe_sub(pk, a, b)`                 | ct           | Encrypted subtraction.                               |
| `fhe_add_const(pk, ct, k: int)`     | ct           | Add a plaintext to a ciphertext.                     |
| `fhe_scale(pk, ct, k: int)`         | ct           | Multiply a ciphertext by a plaintext scalar.         |
| `fhe_verify_zero(pk, ct, proof)`    | `bool`       | Verify a zero-proof that `ct` encrypts 0.             |

Important nuance: `fhe_load_pk` takes a **string**, not an
`address`. The HFHE pubkey is registered to a string identifier; in
example_1.aml callers pass strings for `pk_addr`.

## 7. What's NOT in real AML (we previously assumed)

Our v0 AML referenced these — none exist in example_1.aml:

| Assumed call                              | Status     | Replacement                                  |
| ----------------------------------------- | ---------- | -------------------------------------------- |
| `verify_ed25519(pk, msg, sig)`            | ❌ NO       | None at AML layer. Move to native-tx layer.  |
| `verify_ed25519_acct(addr, msg, sig)`     | ❌ NO       | Same.                                        |
| `pedersen_add/sub/mul_scalar_g/h/zero`    | ❌ NO       | Replace with FHE.                            |
| `pedersen_verify_eq` / `pedersen_verify_open` | ❌ NO   | Replace with `fhe_verify_zero`.              |
| `emit_private_transfer`                   | ❌ NO       | Two-step: AML `transfer`, then native stealth-tx by wallet. |
| `sha256(bytes)`                           | ❌ NOT SEEN | Use self-incrementing counters for IDs.       |
| `addr_bytes(address)`                     | ❌ NOT SEEN | Use `to_string(addr)` if string needed.       |
| `address_zero()`                          | ❌ NOT SEEN | Compare directly: `self.tailnets[tid].owner == 0x0`? Likely an empty struct default fills with 0. |
| `is_address(x)`                           | ❌ NOT SEEN | Drop these checks.                            |
| `len(s)`                                  | ❌ NOT SEEN | Track counts manually; for strings use `parse_ints` + count. |
| `list[T]`                                 | ❌ NOT SEEN | Use `map[int]T` + a count field.              |
| `bytes` type                              | ✅ CONFIRMED (2026-05-17) — but it's UTF-8 length-counted, not raw octets. See §7.1. |

### 7.1 The `bytes` type — what it actually is

`bytes` is **a length-counted UTF-8 string**, not raw octets. The
runtime checks character count via `len()`. Practical consequences:

- A 32-byte hash has NO single canonical representation that passes
  `require(len(h) == 32, ...)` for arbitrary hash values. Hex
  (64 chars) and base64 (44 chars) both fail. A 32-char ASCII string
  passes but represents a different value.
- For receipt hashes, pass `digest_sha256(...)` output directly
  (which yields the right `bytes` value internally) and never
  round-trip through hex/base64 inside the contract.
- For values that MUST be transmitted as hex (e.g. an off-chain-
  produced signature), pass the hex as `string` and check
  `len(s) == 64` for a 32-byte hash, `len(s) == 128` for a 64-byte
  signature, etc.
- `ed25519_ok(pk, msg, sig)` wants **base64** for `pk` and `sig`,
  not hex (see §9 below). The `bytes` length predicate is a
  separate concern from the encoding the host call expects.

Saved memory `octra_aml_wire_format.md` has the full forensic log.

## 8. Compiling against real Octra

Public RPC method, no auth:

```sh
curl -X POST https://octra.network/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"octra_compileAml","params":["<source>","ContractName"]}'
```

Success returns `{"jsonrpc":"2.0","result":{...bytecode/abi...},"id":1}`.

Failure returns `{"error":{"code":-32000,"message":"..."}}` with a
parser/typechecker message.

Examples of errors observed:
- `compile error: Failure("file not found: main.aml")` — used `compileAmlMulti` with bad path keys.
- `line 1: expected token, got program` — used `program` keyword instead of `contract`.

## 9. Required code structure for OctraVPN

The v1 AML rewrite must:

1. Change `program OctraVPN implements IOctraVPN` to `contract OctraVPN`.
2. Inline the `IOctraVPN` interface into the contract (single file).
3. Replace `sha256(seed)` ID derivation with self-incrementing
   `int` counters (`tailnet_count`, `session_count`).
4. Replace all `bytes` types with `string` (verify `bytes` first if
   we want to keep it).
5. Remove `set_member`/`get_member`/`set_tailnet_exit`/
   `get_tailnet_exit` helpers — use direct map indexing
   `self.members[tid][addr]` (nested map).
6. Drop `address_zero()` / `is_address()` — compare addresses
   directly; the AML's default-zero behavior probably handles unset
   entries.
7. Drop `concat_*` helper functions (we never had to define them —
   they were assumed-as-host-calls; they aren't).
8. `fhe_load_pk` takes a **string**, not an `address` — adapt the
   operator-pubkey storage accordingly.

## 9.1 `ed25519_ok` wire format (confirmed 2026-05-17)

```aml
fn slash_double_sign(
  op: address,
  sid: bytes,
  payload_a: bytes,
  sig_a: bytes,    // base64-encoded 64-byte signature
  payload_b: bytes,
  sig_b: bytes,    // base64-encoded 64-byte signature
) {
  let pk = self.receipt_pk[op]  // bytes — base64-encoded 32-byte pk
  require(ed25519_ok(pk, payload_a, sig_a), "sig_a bad")
  require(ed25519_ok(pk, payload_b, sig_b), "sig_b bad")
  // ...
}
```

Both `pk` and `sig` are **base64** strings, not hex. Earlier drafts
that passed hex failed verification silently (no error — just
`false`). This contradicts the convention in `pvac_hfhe_cpp` (which
uses hex) but matches `octra_pre_client/cli.py` for native tx
signatures.

## 10. Tx envelope canonical form (confirmed 2026-05-17)

The bytes signed for tx authentication are **bare canonical JSON**
over the envelope — no domain prefix, no length tag, no binary
framing. Insertion-ordered fields:

```json
{"from":"<from>","to_":"<to>","amount":"<amt>","nonce":<int>,"ou":"<ou>","timestamp":<float>,"op_type":"<op>"[,"encrypted_data":"<...>"][,"message":"<...>"]}
```

`amount` and `ou` are JSON strings (integer micro-units); `nonce` is
unquoted int; `timestamp` is unquoted float. `signature` and
`public_key` are base64 of 64-byte / 32-byte values and added AFTER
signing, never part of the signed blob.

Aux signed messages (encrypted-balance auth, PVAC register,
view-pubkey register) DO use literal-string domain prefixes — see
`docs/octra-research.md §3`. The tx envelope is the exception.

## 10.1 `deploy_circle` op-type wire format

For Circles deployment (the public 2026-05-15 release), the tx
envelope is:

| Field           | Value                                                                           |
| --------------- | ------------------------------------------------------------------------------- |
| `from`          | deployer wallet address                                                          |
| `to_`           | **predicted** `circle_id` (CREATE2-style, see below)                             |
| `amount`        | `"0"`                                                                            |
| `nonce`         | deployer's next nonce                                                            |
| `ou`            | recommended fee                                                                  |
| `timestamp`     | `now()` as float                                                                 |
| `op_type`       | `"deploy_circle"`                                                                |
| `message`       | canonical JSON of the deploy payload (see below)                                 |

Required fields in the `message` payload: `runtime`, `privacy_class`,
`browser_mode`, `resource_mode`, `limits`, `code_b64`, `policy_hash`,
`members_root`, `export_policy`. Optional: vendor-specific extensions
under a `_ext` key (ignored by chain).

Deterministic `circle_id`:

```
seed       = digest_sha256("octra:circle_deploy_id:v1" || deployer_addr_bytes || u64be(nonce) || payload_hash_hex_bytes)
circle_id  = "oct" + base58(seed)[:44]
```

Computable before submission — registries can predeclare `to_=
circle_id` and assert ownership atomically at registration. Reference
impl: `octra-foundry/crates/octra-core/src/circle.rs`; original
JavaScript: `octra-labs/webcli/static/circles.html` (`f9c73e1`).

### 10.2 `circle_asset_put_encrypted` wire format

For sealed-asset publish:

| Field           | Value                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------- |
| `to_`           | circle_id                                                                                                   |
| `op_type`       | `"circle_asset_put_encrypted"`                                                                              |
| `message`       | `{ "resource_key": <hex32>, "ciphertext": <b64>, "padding_class": 0\|1\|2\|3 }`                              |
| `encrypted_data`| (none — ciphertext is in `message`)                                                                          |

Sealed envelope: AES-GCM-256, PBKDF2-SHA256 with 120k iters, "OCRS1"
magic header, padded to 4k / 16k / 32k / 128k buckets
(`padding_class` 0..3). Key derivation: per-circle, per-path. Path
itself never escapes the client — only `resource_key =
digest_sha256(circle_id || path)` is on chain.

### 10.3 Required vs optional fields summary

For typical contract calls (`op_type = "call"`):

- Required: `from, to_, amount, nonce, ou, timestamp, op_type, message`.
- Optional: `encrypted_data` (for HFHE bundles).

For `deploy_circle`:
- Required (envelope): all of the above PLUS predicted `to_=circle_id`.
- Required (`message` payload): the 9 fields in §10.1.

For `circle_asset_put_encrypted`:
- Required: `resource_key`, `ciphertext`, `padding_class` inside
  `message`.

## 11. Open questions to confirm with Octra team

1. ~~Is `bytes` a valid type?~~ **Resolved 2026-05-17** (§7.1).
2. Does `list[T]` exist? The example uses `map[int]T` + counter.
3. Does `while` exist? The example only uses `for i in 0..n`.
4. Is `private fn` valid for contract-internal helpers?
5. What's the exact comparison for "unset" fields (e.g., a struct
   inside `map[bytes]Tailnet` that was never written)?
6. Is there a way to "delete" a map entry, or do we just write zero?
7. Are there string ops besides `concat`/`to_string` (length, slice,
   compare)?
8. ~~Are `payable` / `nonreentrant` modifiers valid?~~ **Resolved
   2026-05-15** via `octra-labs/program-examples` (§ "Function
   modifiers").

Filing as GitHub issues against the Octra dev-docs repo is the
right next step.
