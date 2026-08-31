# AgePony Desktop 2.2.0

Native post-quantum SSH signing, plus one fix and three refinements from field reports.

## Fixed

**SSHSIG Sign and Verify are independent again.** Switching between Files and Text no longer also
flips between Sign and Verify. The two rows of tabs are separate controls now, so you can sign a
file and verify text, not only the reverse.

## New

**Post-quantum SSH signing, built in.** You can now generate an `mldsa44-ed25519` signing key on the
Identities screen and sign with it on the SSHSIG screen. It is the composite algorithm OpenSSH added
in 10.4 — ML-DSA-44 (the FIPS-204 post-quantum scheme) and Ed25519 together, so a signature only
verifies if both hold. Keys and signatures are the standard `ssh-mldsa44-ed25519@openssh.com` format
and interoperate with OpenSSH's own `ssh-keygen`, with no external tools or network involved.

**Verify against a chosen signer.** The Verify screen has an Expected signer list. Leave it empty to
accept a valid signature from any trusted signer, as before, or check the people you expect and a
valid signature from anyone else is flagged as not from an expected signer. With no trusted signers
yet, the list points you to where to add them.

**SSH public keys are visible and exportable.** Each SSH signing key on the Identities screen now
shows its OpenSSH public line, with Copy and Export buttons, so you can hand it out for others to
verify your signatures.

**A header on every tab.** The AGE and Identities tabs now open with a short description of what the
tab does, matching SSHSIG and Settings.
