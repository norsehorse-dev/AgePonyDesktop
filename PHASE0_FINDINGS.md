# Phase 0 — the post-quantum question, answered

Section 6 of the planning document called this the largest open item and asked
for it to be resolved before Phase 1 code was written. It is resolved. The
answer is neither of the two options the plan anticipated, and it changes the
shape of Phase 4.

## What the plan assumed

> `age` 0.12 exposes three native recipient module paths: `age::x25519`,
> `age::tag`, `age::tagpq` — the "tagpq" post-quantum recipient type.
>
> 1. Does the mobile PQ implementation emit `tagpq` stanzas, matching what the
>    Rust crate now produces?
> 2. If not, is the mobile format a custom stanza type of your own design?
>
> If (1), Phase 4 is mostly wiring.

## What is actually true

**Neither.** The mobile format is not custom — it is *the standard*. The Rust
crate is the one that does not have it.

| | AgePony iOS + Android | Rust `age::tagpq` 0.12.1 |
|---|---|---|
| stanza tag | `mlkem768x25519` | `mlkem768p256tag` |
| recipient prefix | `age1pq1…` | `age1tagpq1…` |
| identity prefix | `AGE-SECRET-KEY-PQ-1…` | none — no identity type exists |
| hybrid KEM | ML-KEM-768 + **X25519** (X-Wing) | ML-KEM-768 + **P-256** |
| purpose | general post-quantum recipients | hardware keys requiring user presence |
| can the crate decrypt it? | — | **no, encryption-only** |

Three separate facts, each verified:

1. **`age::tagpq` is a different recipient type.** From the crate source at
   `docs.rs/age/0.12.1/src/age/native/tagpq.rs.html`:

   ```rust
   const MLKEM768P256TAG_RECIPIENT_TAG: &str = "mlkem768p256tag";
   const MLKEM768P256TAG_SALT: &str = "age-encryption.org/mlkem768p256tag";
   const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1tagpq");
   ```

   Different stanza, different HRP, P-256 rather than X25519. `age::tag` is
   likewise `p256tag` / `age1tag`. Both are documented as "designed for hardware
   keys where decryption potentially requires user presence" — a plugin-shaped
   use case, not the general PQ recipient.

2. **`age::tagpq` cannot decrypt.** The 0.12.0 changelog entry reads
   "`age::tagpq::Recipient` (encryption-only)". The implementors of the
   `Identity` trait are `scrypt`, `x25519`, `ssh`, `IdentityPluginV1`,
   `encrypted` — neither `tag` nor `tagpq` appears. So even if the stanza had
   matched, the plan's follow-up worry ("confirm `tagpq` identities are wired
   into `Decryptor`") would have been answered *no*.

3. **The Rust crate has no `mlkem768x25519` at all.** `lib.rs` exports exactly
   `scrypt, tag, tagpq, x25519` plus `encrypted, cli_common, plugin, ssh,
   armor`. No feature flag gates a PQ recipient (23 flags, none PQ-related).
   Nothing in the unreleased changelog section either. `rage` 0.12.1 advertises
   support for `age1tag1..` and `age1tagpq1..` and nothing else.

Meanwhile the mobile side is squarely on the standard. `PQC_Phase_Notes.md`
says so, and `Hybrid.kt` confirms it in code:

```kotlin
private const val HYBRID_HRP_PUB    = "age1pq"
private const val HYBRID_HRP_SEC    = "AGE-SECRET-KEY-PQ-"
private const val HYBRID_STANZA_TYPE = "mlkem768x25519"
private const val HYBRID_INFO        = "age-encryption.org/mlkem768x25519"
```

which matches Go `age`'s `pq.go` byte for byte. The iOS side has the same
construction hand-rolled in `HpkeMlkem768X25519.swift`.

## What this means for the phase plan

The good news is that the mobile implementation is not a bespoke format that
would strand the desktop app. It is the interoperable one, and `rage` is the
thing that is behind.

Phase 4 is therefore a **hand-written `Recipient` and `Identity` pair** — the
plan's option (2), for the opposite reason than expected. Three things make
this much less daunting than it sounds:

- The `age` crate exposes `Recipient` and `Identity` as public traits precisely
  so third parties can do this, and a third-party impl plugs straight into
  `Encryptor::with_recipients` and `Decryptor::decrypt`. Unlike `tagpq`, an
  implementation written here *can* decrypt.
- You have already written this construction twice, in Kotlin and in Swift, and
  both are pinned to reference vectors. Phase 4 is a port, not a design.
- The known-answer vectors are already extracted into
  `vectors/agepony-vectors.json` and wired to a failing (`#[ignore]`d) test.

**One correction to the plan's stated action:** "encrypt a test file to a PQ
recipient on AgePony iOS, then run `rage --decrypt` against it" would not have
worked and would have been misleading. `rage` cannot read `mlkem768x25519` at
all, so it would have failed regardless of whether the mobile side was correct.
Use Go `age` v1.3.0+ for that check instead — and note the container used here
had age 1.1.1, which also predates PQ support, so check your local version.

### Suggested Phase 4 shape

1. Add `ml-kem`, `x25519-dalek`, `sha3`, `hkdf`, `chacha20poly1305`.
2. **Verify `ml-kem` is FIPS 203 *final*, not the draft.** The Android notes
   flag this as the single silent interop breaker: draft and final derive
   different keys from the same seed. The KAT in the vectors file catches it —
   `pq_public_key_derives_from_seed` fails immediately if the parameter set is
   wrong. Run that test before writing anything else.
3. Port `HpkeMlkem768X25519.kt` to `agepony-core/src/pq.rs`. The constants,
   sizes and the HPKE suite are already there with doc comments.
4. Return `{"postquantum"}` from `wrap_file_key`'s label set, matching the
   reference. `agepony_core::recipient::parse_all` already rejects a
   classical/PQ mix before it reaches the encryptor, so the user gets a legible
   error rather than an `IncompatibleRecipients` from inside the crate.

### One knock-on for Phase 6

If Phase 4 slips, there is an escape hatch, but it is not a Rust one: Go ships
an `age-plugin-pq` binary, and the `age` crate's `plugin` feature can drive it.
That would mean bundling a Go binary alongside the app, which conflicts with the
"single self-contained binary, no runtime" success criterion. Worth knowing it
exists; better not to need it.

---

# Other findings from the same pass

## `eframe` 0.35.0 has no `App::update`

Section 11 flagged this as a caveat — "recent egui releases have been moving
from `App::update` toward `App::ui`". The move is complete in the pinned
version. The trait is now:

```rust
pub trait App {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut Frame) { }   // optional
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut Frame);           // required
}
```

There is no `update` method at all, so essentially every egui tutorial online
will not compile. Two more renames that go with it:

- `egui::SidePanel` and `egui::TopBottomPanel` are gone; there is one
  `egui::Panel` with `Panel::left(id)`, `::right`, `::top`, `::bottom`.
- `Panel::exact_width` is now `exact_size`; `show_inside` is deprecated in
  favour of `show`.
- `Context::set_style` / `Context::style` are replaced by
  `Context::all_styles_mut` and `style_of`/`set_style_of(theme)`.

The scaffold uses the correct forms throughout, so `app.rs` is a working
reference for what the new shape looks like.

The `logic`/`ui` split is a good fit for the worker-thread design: `logic` runs
before any painting, which is the natural place to drain the channel, so a
frame renders the newest progress rather than the previous frame's.

## Versions

`age = 0.12.1` and `eframe = 0.35.0` both resolve as the plan states — verified
by actually building, not by reading a version page. (crates.io's API summary
still reports 0.34.3 as eframe's max version; Cargo disagrees, and Cargo is the
one that matters.)

The plan's `edition = "2021"` was bumped to `2024`, and `resolver = "2"` to
`"3"`, since the toolchain is well past both. `age` 0.12.1 has **no default
features**, so `armor` and `ssh` are both opted into explicitly.

One thing the plan does not mention that you will hit immediately in Phase 4:
implementing the `Recipient` and `Identity` traits requires the `Stanza` and
`FileKey` types, which live in `age_core::format` and are **not** re-exported
from `age`. `age-core = "=0.12.0"` is therefore a direct dependency of
`agepony-core`. Also note `wrap_file_key` returns
`(Vec<Stanza>, HashSet<String>)` — a `HashSet` of labels, not a `Vec`.

## A latent bug in the Android fixtures

`generate-fixtures.sh` sets:

```bash
PLAINTEXT="hello agepony"
```

but `CrossImplFixtureTests.kt` asserts:

```kotlin
private val expectedPlaintext = "hello AgePony".toByteArray()
```

Different capitalisation. The committed `.age` fixtures decrypt to
`hello AgePony` — confirmed by decrypting `x25519_hello.age` with the committed
identity — so the tests pass today, and because the fixtures are checked into
git a fresh clone is fine too.

It only bites if someone deletes the fixtures and regenerates: the script is
idempotent and skips files that already exist, so the mismatch stayed hidden
when the string was changed. At that point every `CrossImplFixtureTests` case
fails at once, and the failure looks like a crypto bug rather than a typo.

One-character fix in `generate-fixtures.sh`. Worth doing while it is cheap.
