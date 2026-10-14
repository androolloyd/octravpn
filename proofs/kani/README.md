# Kani verification

The five required harnesses execute production `SessionId` codecs and the shared
`relay_window` claim/refund/sweep arithmetic over symbolic 64-bit inputs. They
check padding rejection, round trips, strict deadline separation and disjoint
windows, including overflow. They do not establish cryptographic unforgeability.

```sh
cargo install --locked kani-verifier --version 0.68.0
cargo kani setup
cargo kani --manifest-path proofs/kani/Cargo.toml
```

The proof crate is explicitly excluded from the root workspace. Its own lockfile
pins verification dependencies. CI treats installation or proof failures as errors.
The former receipt harnesses were stale and never actually ran; they have been
replaced with these executable checks. Property tests complement verification,
but do not quantify over all inputs.
