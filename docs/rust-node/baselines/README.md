# Historical fixture provenance

These files preserve inputs to earlier independent native captures. They
are not the current implementation pin. See [candidate.json](../candidate.json)
for the upstream adoption under qualification.

| File | Preserved evidence |
| --- | --- |
| `legacy-migration-7f9.rs.txt` | Original migration harness from repository commit `d84499a36a64dd7bb02401da5836caa1e6e2d50e`, matching the original fixture's harness hash |

New candidate-native fixtures record their own committed upstream source
hashes and generators separately. The registry was rebuilt and all nine cases
recaptured against the pristine candidate Circle host; its WASM digest remains
identical to the historical artifact, with current build inputs recorded.
