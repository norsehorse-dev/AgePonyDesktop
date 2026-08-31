# AgePony Desktop

Pure Rust. egui/eframe. One binary per platform. Same files, same identities,
same recipients as AgePony iOS and Android.

**Status:** 2.2.0. Feature parity with AgePony iOS and Android. See `RELEASING.md`.

## Getting started

```
cargo test --workspace     # over 200 tests, including property tests
cargo clippy --workspace --all-targets
cargo run -p agepony-desktop
```

Read `PHASE0_FINDINGS.md` first — it answers the post-quantum question that
section 6 of the plan called blocking — then `PHASE4_NOTES.md`, which is the
implementation that followed from that answer.

## Layout

```
AgePonyDesktop/
├── Cargo.toml                  workspace, pinned deps, release profile
├── PHASE0_FINDINGS.md          the PQ answer + API corrections
├── PHASE4_NOTES.md             the post-quantum implementation
├── PORTING.md                  the identity-porting wire format, for the phone half
├── fuzz/                       cargo-fuzz targets for everything taking untrusted bytes
├── RELEASING.md                how a release is cut, and what CI proves
├── SECURITY.md                 reporting, scope, and what to be suspicious of
├── packaging/                  icons, AppRun and the desktop entry
├── tools/
│   ├── make-icons.py           icns/ico/png from the 1024 master
│   └── make-dmg.sh             universal build, sign, notarize, staple, verify
└── .github/workflows/          build.yml on every push; release.yml on a v* tag
├── vectors/
│   └── agepony-vectors.json    shared fixtures for iOS, Android and Desktop
├── agepony-core/               no UI, no egui, no knowledge a GUI exists
│   ├── src/
│   │   ├── lib.rs
│   │   ├── error.rs            typed errors that cross the crate boundary
│   │   ├── identity.rs         generate, parse, store (0600 on Unix)
│   │   ├── recipient.rs        parse classical + PQ, reject mixed sets
│   │   ├── book.rs             recipient book, public key material only
│   │   ├── store.rs            identity store: labels, dates, active identity
│   │   ├── vault.rs            keeps the store and the book consistent
│   │   ├── clock.rs            RFC 3339 timestamps, no date-time dependency
│   │   ├── porting.rs          receiving an identity from a phone
│   │   ├── encrypt.rs          streaming, sibling-dotfile output
│   │   ├── decrypt.rs          streaming, no partial plaintext on failure
│   │   ├── migrate.rs          re-encrypt existing files to a new recipient
│   │   ├── signing/            detached SSHSIG, allowed_signers, key + signer stores
│   │   ├── archive/            compact USTAR and the signed-bundle container
│   │   └── pq/                 mlkem768x25519: X-Wing KEM + HPKE + Bech32
│   └── tests/
│       ├── vectors.rs          shared fixtures + the post-quantum KAT
│       ├── workflow.rs         the Phase 3 gate: store → book → encrypt → decrypt
│       ├── properties.rs       proptest: what holds for any input, not just ours
│       └── vault_invariant.rs  the store/book invariant under random sequences
│       ├── interop.rs          round trips against rage or age on PATH
│       ├── no_network.rs       asserts no networking crate in the tree
│       └── fixtures/           binary fixtures shared with the Android repo
└── agepony-desktop/
    └── src/
        ├── main.rs             eframe bootstrap
        ├── app.rs              the App struct — all persistent UI state
        ├── tasks.rs            worker thread + channel + cancellation
        ├── mark.rs             the shield and horse as vector meshes
        ├── qr.rs               QR codes for the porting flow
        ├── theme.rs            the design system: palette, fonts, components
        └── panels/             files, text, sign, identities, recipients, settings
```

## What works today

- Encrypt and decrypt to x25519 recipients, SSH recipients, or a passphrase
- Post-quantum `age1pq1…` recipients and `AGE-SECRET-KEY-PQ-` identities,
  verified byte for byte against the reference vectors
- ASCII armor
- Streaming, 64 KiB chunks, progress reporting, cancellation
- Identity store in the OS config directory: generate, import, export, rename,
  set active, delete — classic or post-quantum, optionally passphrase protected
- Recipient book with name labels, search, add/edit/delete, and import/export as
  an age recipients file
- Encrypting to recipients picked from the book by name, and decrypting with the
  active identity
- Every identity you hold appears in the recipient book automatically, so
  encrypting a copy to yourself never means copying your own key around
- Identity porting: show this machine's recipient and a QR of it, then import
  the identity a phone encrypted to it — see `PORTING.md`
- Drag and drop, multi-file batches with per-file results, keyboard shortcuts,
  remembered window size and preferences
- The NorseHorse design system: brand palette and components ported from iOS,
  Inter and JetBrains Mono embedded, the shield drawn as vector geometry
- The GUI shell: sidebar, encrypt and decrypt panels, file dialogs, progress bar
- Encrypt and decrypt pasted text, not just files, from the Text screen. The
  decrypted text is held in a zeroizing buffer and cleared on leaving the screen
- Sign and verify files with detached SSHSIG, byte-compatible with `ssh-keygen`
  and the mobile apps. `ssh-ed25519` and `ssh-rsa` produce signatures; ecdsa and
  security-key signatures made elsewhere verify here
- A trusted-signers list that names known keys on a valid signature,
  round-tripping through the OpenSSH `allowed_signers` format
- Generate and import SSH signing keys (ed25519 or RSA-3072) on the Identities
  screen, alongside your age identities
- Bundle several files into one `.tar.age` archive, in a compact USTAR that
  standard `tar` tools open
- Migrate existing age files to a quantum-safe identity in a batch, keeping the
  originals until the new copy is written
- A panic wipe in Settings that deletes every identity, signing key, recipient,
  and trusted signer, and their key files on disk

## Verbs

The app is a GUI. It also answers three read-only verbs, which exist so a
*packaged* build can be verified — a binary can compile, install, and still fail
to start because a shared library is missing on the target or the glibc floor is
too high, and nothing in `cargo test` can see that.

```
agepony version           the version and the compiler that built it
agepony selftest          exercises the crypto in this build; PASS/FAIL per check
agepony list-recipients   prints the book, proving the store opens
```

None of them reads or writes a file you name. For encrypting from a terminal,
use `rage`.

On Windows a GUI-subsystem process has no stdout, so `agepony-cli.exe` ships
alongside as the console-subsystem twin. On macOS and Linux the one binary does
both.

## Hardening

Known-answer tests prove this crate produces the right bytes for valid input.
They say nothing about what it does with garbage — and once it is downloadable,
garbage is what it will be handed. Three layers cover that:

**Property tests** (`tests/properties.rs`, runs on stable in the normal suite).
Every parser that touches untrusted bytes must survive any input without
panicking: `panic = "abort"` in release means a panic closes the app rather
than showing an error. Plus the properties worth stating outright — Bech32
round-trips anything it encodes and rejects every single-character
substitution, and any single bit flipped anywhere in a ciphertext is detected
*and* leaves no partial plaintext on disk.

**A stateful invariant test** (`tests/vault_invariant.rs`). Random sequences of
generate, import, rename, delete and reconcile, with the store/book invariant
checked after every step rather than at the end.

**Fuzz targets** (`fuzz/`, needs nightly). Six, aimed at the same surfaces. See
`fuzz/README.md`.

The hand-rolled Bech32 decoder gets the most attention of any of them, because
it is the only parser here written from scratch rather than delegated to a
reviewed crate.

### On secret hygiene

`ml-kem`, `x25519-dalek`, `chacha20poly1305` and `sha3` all ship a `zeroize`
feature and none of them enable it by default. Output is byte-identical either
way, so no correctness test can notice — the difference is only whether an
ML-KEM decapsulation key, an AEAD cipher state or a hash buffer is wiped when
it drops. All four are enabled here, and the intermediate X-Wing shared secrets
are held in `Zeroizing` rather than the bare arrays the APIs hand back.

## The design system

`agepony-desktop/src/theme.rs` is the desktop counterpart of the iOS
`DesignSystem` folder — same brand ramp, same 14pt buttons pressing from
`tealCore` to `tealDeep` over 0.08s, same 6%-fill / 18%-border key block. Two
deliberate departures are documented in the module: there is no blur (egui has
none, and the desktop never displays a secret anyway), and spacing is tighter
because a pointer does not need thumb-sized targets.

`mark.rs` holds the shield and horse **traced out of the app icon into polygon
meshes**, triangulated ahead of time. That means the mark is crisp at any size,
tintable, and usable as a real design element rather than a pasted-in raster:
the sidebar lockup, the drag-and-drop overlay where the shield fills with the
brand gradient, the ghosted shield behind empty states, and the window icon —
which is rasterised at startup from the same vertex data, so it can never drift
from what is drawn on screen.

Fonts are Inter and JetBrains Mono, subset to Latin plus the symbols this UI
draws: 1.5 MB of source faces down to 188 KB shipped. egui's own fonts stay in
the family as fallback, so a file path with characters outside the subset still
renders. JetBrains Mono is not decoration — long Bech32 recipients get checked
by eye, and character disambiguation matters.

Subsetting makes glyph coverage a real constraint, and a missing glyph fails
quietly: it renders as an empty box that survives all the way to a screenshot.
`theme::GLYPHS` declares every non-ASCII character the UI draws, and two tests
close the loop — one checks the shipped fonts can draw everything declared, the
other scans string literals for anything rendered but undeclared.

## Keyboard

| | |
|---|---|
| `⌘1`…`⌘6` | switch tabs (Files, Text, Sign, Identities, Recipients, Settings) |
| `⌘O` | choose files for the current tab |
| `⌘↩` | run the current screen: encrypt or decrypt on Files, encrypt or decrypt text on Text |
| `Esc` | cancel the batch, clear the Text screen, or back out of whatever is open |

`⌘` is `Ctrl` on Windows and Linux.

## Design invariants

These are load-bearing. Changing one is a decision, not a refactor.

**`agepony-core` never imports the UI crate.** It does not know a GUI exists.

**No partial output, ever.** Every write goes to a sibling dotfile in the
destination directory and renames on success. `TempOut`'s `Drop` deletes the
partial file on any failure or unwind. Never `/tmp` — a temp file on another
filesystem turns the rename into a copy, which puts plaintext somewhere the user
did not choose. Two tests enforce this: `a_failed_decrypt_leaves_no_output_file`
and `a_flipped_payload_byte_is_detected_and_leaves_no_output`.

**Streaming, not slurping.** `Encryptor::wrap_output` and `Decryptor::decrypt`
with real readers and writers. The convenience `age::encrypt`/`age::decrypt`
helpers are in-memory and wrong for a 4 GB video.

**Plaintext never reaches the UI.** The core writes to a file and stops. egui
keeps text buffers alive across frames with no way to clear them. Decrypt
buffers are `Zeroizing`.

**A recipient never outlives its private key.** Every identity in the store has
exactly one entry in the book, and deleting the identity takes the entry with
it. A recipient left behind after its key is gone still encrypts perfectly well,
and produces a file nobody can ever open — a worse failure than a missing
recipient, because it fails silently and much later. `vault::reconcile` runs at
startup and repairs the two if they are ever edited apart.

**Nothing secret reaches `identities.json` or `recipients.json`.** Key material
lives in separate `0600` files; the two JSON files hold labels, public
recipients and dates, so they are safe to sync, back up or paste into a bug
report. Enforced by `nothing_secret_reaches_the_index_or_the_book`.

**Output never overwrites.** `unique_path` inserts ` (2)` before the extension
when the destination exists. This is not politeness: encrypting `notes.txt`
twice would otherwise destroy the first `notes.txt.age`, and decrypting
`notes.txt.age` defaults to `notes.txt` — straight over the original plaintext
if it is still there. Batches turn both from "unlikely" into "eventually".

**One bad file does not abort a batch.** A failure is recorded and the worker
moves on; only cancellation stops everything, and the summary always states the
failure count.

**Ported key material never touches the filesystem.** Porting decrypts into a
`Zeroizing` buffer and writes only into the store's own `0600` file. Enforced by
`opening_a_ported_file_writes_no_plaintext_anywhere`, which snapshots the
directory before and after.

**Passphrase-protected identity files are ordinary age files.** They use age's
own passphrase encryption, so `age -d` and the mobile apps can open them. No
bespoke wrapper.

**No `unwrap` on user input.** `agepony-core` denies `clippy::unwrap_used`,
`expect_used` and `panic` in production paths; tests opt out explicitly.

**No network.** `no_network.rs` fails the build if a networking crate appears
anywhere in either dependency tree.

**`panic = "abort"` in release.** A panic mid-decrypt should kill the process
rather than unwind through code holding plaintext.

## Shared vectors

`vectors/agepony-vectors.json` is the file all three platforms load. A vector
added there becomes a test everywhere. It currently holds the `mlkem768x25519`
known-answer vector (seed, expected public key, deterministic encapsulation,
expected stanza body) extracted from the Android `HybridRecipientTests`, plus the
metadata for the binary cross-implementation fixtures.

`pq_public_key_derives_from_seed` is also the permanent FIPS 203 canary: ML-KEM
draft and final derive different keys from the same seed, so if the `ml-kem`
dependency ever regressed to the draft, that test fails immediately rather than
producing files the phones silently cannot open.

## Licence

Apache License 2.0 — see `LICENSE`, and `NOTICE` for third-party attributions,
which section 4(d) requires redistributors to carry.

Apache rather than MIT because this repository contains hand-written
implementations of standardised cryptographic algorithms, and Apache-2.0 grants
an express patent licence where MIT grants copyright rights only. It also
matches BurnPonyDesktop and PGPonyDesktop, so there is one licence question
across the family rather than four.
