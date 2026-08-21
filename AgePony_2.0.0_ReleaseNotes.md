# AgePony Desktop 2.0.0

AgePony Desktop reaches feature parity with AgePony for iOS and Android. What the
phones do with age files, the desktop now does too, and the files, identities,
and signatures move between all three without conversion.

## New

**Text.** Encrypt and decrypt pasted text, not just files. The output is armored
and ready to copy. A decrypted note is held in a zeroizing buffer and cleared
when you leave the screen or press Escape.

**Sign.** Sign and verify files with detached SSHSIG. Signatures are
byte-compatible with `ssh-keygen` and the mobile apps: an `ssh-ed25519` or
`ssh-rsa` key signs, and a signature made elsewhere with an ecdsa or security key
verifies here. A trusted-signers list names the keys you recognise and
round-trips through the OpenSSH `allowed_signers` file, so a list built here
drops onto a machine's `ssh-keygen -Y verify` and back.

**SSH signing keys on Identities.** Generate an ed25519 or RSA-3072 signing key,
or import an existing OpenSSH key, on the Identities screen alongside your age
identities.

**Bundling.** Encrypt several files into one `.tar.age`. The archive is a compact
USTAR that any standard `tar` tool opens.

**Quantum-safe migration.** Re-encrypt a batch of existing age files to a
post-quantum identity from Settings. AgePony decrypts each with your identities,
or a passphrase for passphrase-encrypted files, and writes the new copies to a
folder you choose. The originals are left alone.

**Panic wipe.** A confirmed action in Settings that deletes every identity,
signing key, recipient, and trusted signer, and their key files on disk.

## Interoperability

Files, signatures, and bundles are byte-compatible across AgePony on iOS,
Android, and desktop. SSHSIG signatures verify against `ssh-keygen` and the
reverse; the tar bundles open with standard `tar`; post-quantum recipients match
the shared reference vectors.

## Notes

- The Sign screen's third tab is the trusted-signers list. Signing keys are
  generated and managed on Identities.
- RSA signing works around a bug in the `ssh-key` library that would otherwise
  reject a valid key. A test flags it if a future version fixes the bug, so the
  workaround can be dropped then.
