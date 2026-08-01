# Security

AgePony Desktop encrypts files. If something here is wrong, someone's data is readable when they
believed it was not — so this document exists, and it is the first of its kind in the pony family.

## Reporting

Report privately, not as a public issue: **NorseHorse@norsehor.se**, or through GitHub's private
vulnerability reporting on this repository.

Encrypt anything sensitive to the release key, which is also the key that signs every artifact:

```
A0CBC8F65AACE56F1C5B767753F9798E4919DE62
```

No bounty, and no fixed response time — this is a free tool with one maintainer. What is promised is
that a credible report gets read and answered.

## Scope

**In scope:** anything that makes a file readable by someone who should not read it, or unreadable
by someone who should. Wrong ciphertext, a recipient that does not match the identity it claims,
plaintext or key material reaching disk where it should not, a parser that can be made to crash or
misbehave on hostile input, an interoperability break with AgePony iOS, AgePony Android, `rage` or
Go `age`.

**Out of scope:** an attacker who already has code execution as the user. The app decrypts files
with keys that user holds; nothing here defends against a process that can read that user's memory
or files.

## What this app does and does not do

- **No network.** The binary makes zero outbound connections. There is a test that fails the build
  if a networking crate appears anywhere in the dependency tree.
- **No telemetry, no accounts, no server.** There is nothing to opt out of.
- **Plaintext never renders in the UI.** Decryption writes to a file and stops there. egui keeps
  text buffers alive across frames with no way to clear them, so plaintext is never given to one.
- **Key material is never in the two JSON files.** `identities.json` and `recipients.json` hold
  labels, public recipients and dates. Private keys live in separate files, mode `0600` on Unix.
  There is a test for this.
- **A failed decrypt leaves no output.** Every write goes to a sibling dotfile and renames on
  success; a failure or an unwind removes it. A truncated, unauthenticated plaintext on disk would
  be worse than an error.
- **Passphrase-protected identity files are ordinary age files**, so `age -d` and the mobile apps
  can open them. No bespoke wrapper.

## The cryptography

Encryption is the [`age`](https://crates.io/crates/age) crate, by the author of `rage`.

The **post-quantum** recipient — `mlkem768x25519`, `age1pq1…` — is **implemented in this project**,
because the Rust `age` crate does not have it. Its `tagpq` is a different construction
(`mlkem768p256tag`, P-256, hardware-key oriented, encryption-only). So `agepony-core/src/pq/` is
first-party code: X-Wing (ML-KEM-768 + X25519) and HPKE RFC 9180 base mode, ported from the Kotlin
implementation in AgePony Android and pinned to the `filippo.io/hpke` reference vectors that Go
`age` v1.3.0 uses.

**That code deserves the most scrutiny in this repository.** It is verified byte-for-byte against
reference vectors, checked again inside every shipped binary by `agepony selftest`, and fuzzed — but
it is hand-written cryptography, which is exactly the thing one should be suspicious of.

The Bech32 decoder is also first-party, for a duller reason: the `bech32` crate enforces the
BIP-0173 90-character limit and a post-quantum recipient is about 1960 characters. It is the most
heavily fuzzed thing here.

## Verifying a download

Every release ships a `SHA256SUMS` and a detached signature for it and for each artifact, all made
with the key above.

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS      # shasum -a 256 -c on macOS
```

The Windows MSI is **unsigned**; SmartScreen will warn. Check the hash rather than trusting the
dialog.

The signing key never reaches CI. Linux and Windows artifacts are built by GitHub Actions, but
everything is signed on a machine that holds the key, and the macOS build never touches hosted
infrastructure at all.
