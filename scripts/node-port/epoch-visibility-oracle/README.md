# Epoch visibility component oracle

`main.ml` is the exact oracle that produced the retained native seven-row
fixture. The unchanged adopted `node_runtime/epoch_visibility.ml` is supplied by
the explicit native checkout, checked against the source map and pinned hash,
then copied into a fresh isolated host Dune project. No native file is patched.

With an existing opam switch containing Dune, Lwt and Yojson:

```sh
python3 scripts/node-port/epoch-visibility-oracle/capture.py \
  --native-source /path/to/pristine/adopted-native \
  --out /path/to/fresh/owned-capture
```

The runner installs no packages and uses no Docker or network. It captures actual
stdout/stderr, source hashes before/after, argv, exit status and executable hash.
`stdout.json` is the fixture; answers are never synthesized. A failed capture is
preserved and not promoted. Compare any newly captured fixture in Rust explicitly:

```sh
OCTRA_NATIVE_VISIBILITY_FIXTURE=/path/to/owned-capture/stdout.json \
cargo test --offline --locked --release -p octra-node --all-features \
  --lib epoch_visibility::tests::unchanged_native_visibility_differential_trace
```

Ordinary CI uses the mandatory checked-in
`crates/octra-node/tests/fixtures/epoch-visibility-native.json` without an
environment override. Its test has no ignore attribute. The DTO still rejects
unknown/duplicated fields, missing explicit nulls, invalid types, source identity
drift and files exceeding 64 KiB. The seven rows exercise the native component's
wait, three-attempt generation churn, retried/stable error, queued reads and
cancelled-reader behavior. The write row is a read-dispatch classification counter
control, not a submitted financial transaction or a whole-node qualification.
