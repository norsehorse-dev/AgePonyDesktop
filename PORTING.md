# Identity porting — the wire format

The desktop half is built. This is what the phone half has to do, written so
implementing it on iOS or Android is a small, unambiguous change.

## The flow

```text
desktop                                phone
-------                                -----
show recipient + QR   ──────────────►  scan it
                                       encrypt this phone's identity to it
import the file       ◄──────────────  hand the file over
decrypt in memory, install
```

No OTP, no server, no pairing ceremony. The desktop's own identity *is* the
channel: only the machine holding that private key can read what the phone
sends. Nothing on either side touches a network.

## What the phone must produce

An **ordinary age file**, encrypted to the recipient the desktop displays. No
AgePony-specific container. On the wire this is exactly what
`age -r <desktop-recipient>` produces, and any age implementation can make it.

The **plaintext** is an age identity file:

```text
# agepony-port: v1
# name: Phone key
AGE-SECRET-KEY-1QQQ…
```

- Both comment lines are **optional**. Every age implementation ignores `#`
  lines, and the desktop imports a payload that is nothing but the secret key
  string. The `# name:` line only supplies a default label so the user does not
  have to retype it.
- The key line is a classic `AGE-SECRET-KEY-1…` or a post-quantum
  `AGE-SECRET-KEY-PQ-1…`. The desktop routes on the prefix and stores the right
  kind, exactly as `IdentityImport.kt` does on Android.
- Binary or ASCII-armored ciphertext, both accepted.

Constants live in `agepony-core/src/porting.rs` as `MARKER` and `NAME_PREFIX`.

## Reading the recipient off the screen

The desktop shows the recipient as text and as a QR code, and can save it to a
file. **The QR encodes the recipient uppercased.**

That is not cosmetic. Bech32 is case-insensitive, and QR's alphanumeric mode
covers `0-9 A-Z` at 5.5 bits per character against byte mode's 8. An uppercase
age recipient is pure `A-Z0-9`, so it qualifies. Measured on a real
post-quantum recipient — 1960 characters, because the hybrid public key is 1216
bytes:

| | QR version | modules |
|---|---|---|
| as-is, byte mode | 33 | 149 × 149 |
| uppercased, alphanumeric | 26 | 121 × 121 |

Two whole versions, free. A classic `age1…` recipient is 62 characters and
lands at version 3 either way.

**So the phone's scanner must accept an uppercase recipient.** Feeding
`AGE1PQ1…` to a decoder that only tests a lowercase prefix will reject a
perfectly good key. This bit the desktop: `recipient::parse` tested
`starts_with("age1pq1")` against the raw string and would not parse its own QR
output. Fixed there, with `an_uppercase_post_quantum_recipient_parses` guarding
it. Check the mobile parsers before wiring up a scanner.

A 121-module code is dense. The desktop says so, sizes it generously, and
offers "Save to file" as the alternative — AirDrop or a shared folder is often
easier than holding a phone steady against a laptop screen.

## Rules the desktop follows, and the phone should too

**Prefer a post-quantum receiving identity.** The transfer carries a private
key. Someone who records it today and keeps it has a harvest-now-decrypt-later
opportunity that lasts as long as the key does. If the active identity is
classic the desktop warns in the panel; the phone should say something similar
when it sees a classic `age1…` target.

**Never write the plaintext to disk.** The desktop decrypts into a `Zeroizing`
buffer and writes only into the store's own `0600` file — `decrypt_to_memory`,
not `decrypt_file`. There is a test, `opening_a_ported_file_writes_no_plaintext_anywhere`,
that snapshots the directory before and after and fails if anything appears or
changes. Whatever the phone does, it should not leave the received identity in
a cache or a temp directory.

**Tell the user to delete the transfer file.** It is a private key encrypted to
one specific machine — not dangerous to keep, but no reason to.

**Detect a repeat port.** `Store::find_by_recipient` catches importing the same
phone twice and says where it already is, rather than making a duplicate.

## Tests to port along with the feature

`agepony-core/src/porting.rs` and `tests/workflow.rs` carry five between them.
The two worth mirroring on mobile:

- `a_payload_without_the_comment_lines_still_imports` — pins the promise that
  the comments are optional, so a bare `age -r` payload is valid.
- `an_identity_ported_from_a_phone_can_decrypt_what_that_phone_could` — the one
  that matters. Encrypt a file to the phone's identity *before* porting, then
  check the ported copy still opens it on the other machine. A port that
  installs something which does not decrypt the old files is worse than no port
  at all.
