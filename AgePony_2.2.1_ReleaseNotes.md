# AgePony Desktop 2.2.1

A fix for one field report on 2.2.0.

## Fixed

**Importing an mldsa44-ed25519 public key works.** 2.2.0 could generate, sign, and
verify with its own post-quantum signing keys, but adding someone else's
mldsa44-ed25519 public key as a trusted signer failed with a recipient error, so you
could not check their signatures. You can now paste or import one under Identities, see
its fingerprint, and verify that signer's messages the same as any other SSH key.
