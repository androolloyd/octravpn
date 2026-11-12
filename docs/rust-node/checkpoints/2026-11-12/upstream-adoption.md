# November 12 upstream adoption

Candidate: `c49de45cf49ebbc2e5c0697eb956cbcada5845e7`.
Historical reference: `7f9be4489870645cfcc95439638cde40f5da9f50`.
Local core qualification passes. This record does not promote historical
public-network or funded-traffic results to the new build.

## Local results

| Suite | Passed | Ignored entries |
| --- | ---: | ---: |
| Protocol | 209 | 2 |
| Runtime | 328 | 4 |
| Node | 343 | 7 |
| HFHE and PVAC | 52 | 0 |
| Circle host | 287 | 0 |
| Total | 1,219 | 13 |

Counts resolve completed targeted reruns against the initial complete suites;
they do not sum repeated executions. Initial failures and corrected results
remain in the local logs. Strict Clippy passes for both default and private
feature configurations, and changed Rust files pass formatting checks.
The [machine-readable record](upstream-adoption.json) binds source and log
hashes, resolved counts and the ignored entries.

## Changes

- Adopted the staged quorum, round-wait, source-author, proof-key, program-input
  and duty-mark rules, with upstream activation anchors and profile identities.
- Connected vote/value recovery and authenticated relief to the node driver,
  snapshot export and retained history. Peer handshakes, queued writes, queries
  and reply windows now use the upstream admission and resource boundaries.
- Added registered-key private reads, full-key proof binding and cyclic-power
  verification. Public history excludes private transactions before counting
  or pagination, and private response fields remain redacted.
- Updated compiler publication, source validation, metering and VM root
  handling, and adopted the current native Circle host and PVAC sources.

## Independent comparisons

Expected outputs were captured from committed upstream sources, independently
of the Rust implementation. Historical fixtures retain their original pins.
The candidate source inventory contains 1,192 independently checked files;
all 77 vendored PVAC files match the candidate, and the Circle API adaptation
patch reproduces the vendored tree exactly.

| Comparison | Coverage |
| --- | --- |
| Consensus engine | 464 signed traces / 8,755 steps |
| Validator decisions | 1,272 inputs |
| Local vote persistence | 184 traces / 2,718 steps |
| Staged policy and graph | 96 set cases and 512 rule cases |
| Startup profiles | 96 inputs, including 57 valid profiles and 1,491 epoch hashes |
| Bound rule activation | 450 inputs |
| Preview execution rules | 978 inputs, preserving 655 historical negative controls |
| RPC and peer transaction intake | 178 inputs / 1,351 steps |
| Compiler and publication | 101 cases, including the VPN and factory sources |
| VM root conversion | 22 native inputs; 56 historical receipt projections with native emission costs |
| Key-bound cryptography | Native key digests, proof bytes, transcript and malformed-key controls |
| Registry Circle host | Nine freshly captured native scenarios, identical rebuilt WASM, current build provenance |

The compiler and consensus oracles compile unchanged native modules and
explicitly recorded declaration slices where unrelated dependencies are not
available. The VM receipt projection changes only native root encodings and
their emission costs; it is not a complete fresh native epoch replay.

## End-to-end scope

The executable local network test passed transfers, Circle browsing, validator
restart, nonvoting observer catch-up and observer restart. The node suite also
passed genuine shielded purchase/history/recovery checks and private import.
These tests use isolated local chains. Public devnet activation, sustained
public synchronization, funded Linux multi-hop traffic and current deployed
service availability remain separate gates.

No public node, relay, account or deployment was changed. Existing observer
state and unpublished security work were preserved. This is executable local
qualification, not a proof of whole-node equivalence or a formal verification
of the implementation.

Raw commands, initial failures, corrected reruns, native build records and
source fingerprints are retained locally in
`out/upstream-adoption-20261112/`. Full upstream-node build certification and
the native physical-store qualification tests require their separate native
toolchain and retained-store environment. Ignored tests are not passes.
The ignored entries include native-peer interoperability, public manifest and
native-store qualification, retained-store benchmarks, browser fixtures and
controlled child-process helpers. Crash helpers are exercised by their parent
recovery tests; their standalone ignored entry is still listed separately.
