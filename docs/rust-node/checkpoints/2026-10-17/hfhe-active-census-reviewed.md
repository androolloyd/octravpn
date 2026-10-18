# Active HFHE source census — 2026-10-17

The reviewed Rust node paths already connect private transitions, Circle HFHE and OCTB callbacks, and Single private verification to `octra-hfhe`. Public network/devnet/Single launchers require an explicit crypto pool. Low-level component primitives and the local compatibility backend remain explicit in-process APIs; this source census does not qualify their resource behavior.

The audit authenticates the adopted native revision `7f9be4489870645cfcc95439638cde40f5da9f50`, its 1158-file source catalog, the original audit's unchanged source hashes, and current caller/worker files. The bounded lexical scan covers the catalog's 958 ML/ML-interface files and five named C/OCaml export boundaries. It found no direct interface or ML caller for the eight listed reset/hidden-carrier/reusable symbols. Their C++ definitions and experimental wrappers remain separate library surfaces. This is not a transitive C++ reachability proof or a whole-library equivalence claim.

The released native recrypt transaction is explicitly refused, and the aggregated-range verifier retains its native false policy. The separately exported legacy `ct_recrypt_seeded` FFI is distinguished from the unexported reset/hidden-carrier functions. Optional whole-library work remains open; `switch_completed=false` does not mean the active node HFHE adapter is missing.

The older `pvac-sidecar`/Hub tooling is a separate legacy IPC boundary. Its component evidence does not substitute for modern node cryptography or prepaid custody. This census performs no tests, builds, runtime/Docker/public-process actions, and adds no Rust test cases. It does not establish every-input/profile, side-channel, cross-architecture, public-network or Mainnet qualification.

See the [census data](hfhe-active-census-reviewed.json), [HFHE component record](../../hfhe-parity.json), and [adopted source catalog](../../source-map.json). The original OUT audit and current source hashes are bound in the census data.
