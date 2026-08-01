# Cross-implementation fixtures

Copied from `AgePonyAndroid/agepony-core/src/test/resources/fixtures/`. Same
files, same plaintext, so a fixture added on one platform becomes a test on the
other. Regenerate with the Android repo's `generate-fixtures.sh`.

The private keys here are **throwaway test keys**. They are committed
deliberately, exactly as they are in the Android repo. Never put a real identity
in this directory.

Plaintext for every `*_hello.age` file is `hello AgePony`. See
`vectors/agepony-vectors.json` → `cross_impl_files.plaintext`.

## The post-quantum fixture

`pq_hello.age` / `pq_identity.txt` were produced by **this crate**, not by a
reference CLI, because no CLI implements `mlkem768x25519` yet — Go `age` v1.3.0+
does, but `rage` does not. So `pq_fixture_decrypts` is a regression test, not an
interop proof.

The interop proof is in two other places: the known-answer tests in
`tests/vectors.rs`, which check our output byte for byte against the
`filippo.io/hpke` reference vectors, and opening `pq_hello.age` on AgePony iOS
or Android. Do the second one once by hand.

Regenerate with:

```
cargo run -p agepony-core --example make_pq_fixture -- agepony-core/tests/fixtures
```
