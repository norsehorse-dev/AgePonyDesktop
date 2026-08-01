# Fuzzing

Six targets over everything in this crate that touches untrusted bytes: a
pasted recipient, a chosen identity file, a `.age` file from a stranger, a
hand-edited recipient book.

The bar is **never panic**. `panic = "abort"` is set for release, so a panic on
a malformed file closes the whole app rather than showing an error. `bech32`
additionally asserts that anything it accepts round-trips — accepting a string
it cannot reproduce would mean the decoder and the encoder disagree.

Needs nightly, which is a cargo-fuzz requirement, not ours:

```
cargo install cargo-fuzz
cargo +nightly fuzz run bech32
cargo +nightly fuzz run recipient
cargo +nightly fuzz run identity_file
cargo +nightly fuzz run hybrid_key
cargo +nightly fuzz run age_file
cargo +nightly fuzz run book_json
```

`hybrid_key` and `age_file` are slow per case — they do real key generation —
so give those longer runs. `bech32` is the one to run hardest; it is the only
parser here that was written from scratch rather than delegated to a reviewed
crate.

The same functions are also covered by `agepony-core/tests/properties.rs`,
which runs on stable in the normal test suite. That is the regression net;
this is the search.
