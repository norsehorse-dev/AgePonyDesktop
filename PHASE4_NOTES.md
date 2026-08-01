# Phase 4 — post-quantum, done

`mlkem768x25519` / `age1pq1…` is implemented in Rust and verified byte for byte
against the reference vectors. The phase gate from the plan — "PQ file from
phone opens on desktop, PQ file from desktop opens on phone" — is met at the
stanza level; the remaining step is one manual check on a handset, described at
the bottom.

## What was built

```
agepony-core/src/pq/
├── mod.rs      Recipient, Identity, age trait impls, Bech32 encoding
├── xwing.rs    the MLKEM768-X25519 hybrid KEM
├── hpke.rs     RFC 9180 base mode, one suite, single shot
└── bech32.rs   Bech32 with no length limit
```

Ported from `HpkeMlkem768X25519.kt` and `Hybrid.kt` in the Android core, which
are themselves pinned to the `filippo.io/hpke` reference that Go `age` v1.3.0+
uses.

## The evidence

Four tests do the real work, all in `tests/vectors.rs`, all reading
`vectors/agepony-vectors.json`:

| test | what it proves | mirrors |
|---|---|---|
| `pq_public_key_derives_from_seed` | seed → 1216-byte public key matches the reference | `publicKeyDerivedFromSeedMatchesReference` |
| `pq_deterministic_wrap_matches_the_reference_stanza` | with fixed randomness, our `enc` (1120 bytes) and stanza body (32 bytes) are byte-identical to the reference | `deterministicWrapMatchesReferenceVector` |
| `pq_identity_unwraps_the_reference_stanza` | we can read a stanza built from reference bytes, not from our own output | `identityUnwrapsReferenceStanza` |
| `pq_round_trips_a_real_file` | the whole path works through `Encryptor`/`Decryptor` on a real file | `endToEndThroughAgePipeline` |

They passed on the first run, which is the outcome you want from a port: the
construction was already specified precisely enough in the Kotlin that there was
nothing left to guess.

`cargo test --workspace` is 56 tests. `cargo clippy --workspace --all-targets`
is clean.

## The FIPS 203 question, settled

The Android notes flagged this as the one thing that silently breaks interop:
ML-KEM draft (IPD) and final derive **different keys from the same seed**, so a
draft-era implementation produces files the phones cannot open, with no error
anywhere to point at it.

`ml-kem` 0.2.3 is FIPS 203 **final**. `pq_public_key_derives_from_seed` is the
proof and the permanent canary — it compares against a reference-derived public
key, so it fails immediately and unmistakably if the dependency ever regresses.

## Dependency notes

`ml-kem = "0.2"` with `features = ["deterministic"]`, matching what `age` 0.12.1
itself depends on. This matters: **do not bump to `ml-kem` 0.3.** It requires
`kem` 0.3.0, while `ml-kem` 0.2.x pins `kem =0.3.0-pre.0`, and Cargo cannot hold
both in one tree. Trying it resolves `ml-kem` down to 0.2.1 and the build fails
inside the dependency with a wall of trait-mismatch errors that look like your
fault and are not. `age` will have to move first.

Two other version notes:

- `Shake256` left the `sha3` crate in 0.12.0 and lives in the `shake` crate now.
- Bech32 is hand-rolled, in `pq/bech32.rs`. The `bech32` crate enforces the
  BIP-0173 90-character code limit, and an `age1pq1…` recipient is about 1960
  characters, so the crate physically cannot encode one. age applies no length
  limit — the Android core hit the same wall and raised its own decode cap. The
  implementation is checked against the `age` crate by decoding and re-encoding
  a real `age1…` recipient, which catches any disagreement on charset, checksum
  or bit regrouping.

New dependencies: `ml-kem`, `x25519-dalek`, `sha3`, `shake`, `hkdf`, `sha2`,
`chacha20poly1305`, `base64`, `getrandom`. The no-network test still passes —
none of them pull in a networking crate.

## Mixing is blocked in two places

A post-quantum file must not also carry a classical recipient; the weakest
recipient sets the bar. age enforces this itself through stanza labels — our
`wrap_file_key` returns `{"postquantum"}`, and `Encryptor::with_recipients`
rejects any recipient set whose labels differ.

`recipient::parse_all` rejects the mix earlier, so the user gets
"post-quantum recipients cannot be combined with classical recipients" rather
than an `IncompatibleRecipients` from inside the crate. Both layers are tested.

## Interop with the phones: confirmed by hand

Both directions were checked against AgePony Android on 1 August 2026 and pass:

- **desktop → phone** — `pq_identity.txt` imported on Android, `pq_hello.age`
  opened there.
- **phone → desktop** — a file encrypted on Android to a desktop recipient,
  decrypted here.

So the Phase 4 gate from the plan — "PQ file from phone opens on desktop, PQ
file from desktop opens on phone" — is met, across two independent
implementations of the construction (hand-written Rust here, hand-written
Kotlin there), which is a much stronger signal than either passing its own
tests.

**Caveat: AgePony iOS cannot import a post-quantum identity yet.**
`ImportIdentityView.save()` calls `X25519Identity(ageIdentity:)` unconditionally
for the paste-a-string mode; there is no `HybridIdentity` branch, so an
`AGE-SECRET-KEY-PQ-1…` string is rejected by the classic decoder. iOS can
*generate* PQ identities but not import them. Android already routes on the
prefix in `IdentityImport.kt`. Until iOS gains the same branch, the iOS leg of
this check cannot be done.

(Related: `Bech32.swift` reuses `Bech32Error.emptyHRP` for four separate
wrong-HRP guards, so a wrong-prefix failure surfaces to the user as "emptyHRP",
which sends you hunting for a truncated paste when the string is fine.)

## Why CI still cannot close this loop

There is no reference CLI to round-trip against. Go `age` v1.3.0+ implements
this recipient, but `rage` does not, and Go's module proxy was not reachable
from the build environment, so CI cannot close this loop.

That is why the check above had to be done by hand, and why
`agepony-core/tests/fixtures/` carries a PQ fixture produced by the Rust core:

- `pq_identity.txt` — the identity, owner-readable only
- `pq_hello.age` — `hello AgePony` encrypted to its recipient

Regenerate the fixture with:

```
cargo run -p agepony-core --example make_pq_fixture -- agepony-core/tests/fixtures
```

If you later get a machine with Go module access, `go install
filippo.io/age/cmd/...@latest` gives you a PQ-capable CLI and `tests/interop.rs`
can be extended to cover this automatically.

## What the desktop app does with it now

The Identities panel generates both kinds — "Generate classic identity" and
"Generate post-quantum identity" — writes an owner-only identity file, and shows
the resulting recipient with a Copy button. The Encrypt panel accepts `age1pq1…`
recipients in the free-text field and refuses a mixed set with a legible error.

Storing, importing, labelling and setting an active identity are still Phase 3.
