# AgePony Desktop 2.1.0

A round of changes driven by field reports, plus a redesigned navigation that
groups the app by what you are doing rather than by screen.

## New

**One rail, three destinations.** The sidebar is now AGE, SSHSIG, and Identities,
plus Settings. AGE splits into Encrypt and Decrypt, each with a Files and a Text
side. SSHSIG splits into Sign and Verify. Identities holds your age keys and
recipients under AGE, and your signing keys and trusted signers under SSHSIG.
Everything the old flat rail did is still here, grouped by task.

**Text signing.** Sign and verify pasted text with SSHSIG, not just files. Paste
text, sign it, and copy the armored signature; or paste a message and its
signature to verify. Same trust verdict as the file path.

**A namespace field for SSHSIG.** Sign and verify under a namespace you choose,
so a signature is interoperable with any `ssh-keygen -n` namespace. Verification
accepts AgePony's own namespaces automatically and anything you add.

**Recycle bin for identities.** Deleting an identity now moves it to Recently
deleted, where you can restore it, private key and all, for 30 days. Removing it
for good, or letting the 30 days pass, is the only way its key material leaves.
An identity's recipient comes back with it on restore.

**Identicons.** Each identity and recipient gets a small coloured initial badge
derived from its key, so a renamed key keeps its colour and two similar names
still read apart. Matches the AgePony mobile look.

**More on Settings.** A Help section, a plain-language explainer of how AgePony
protects your files, and the open-source license list.

## Fixed

**Keyboard focus is visible again.** Buttons show a focus ring when you tab to
them, so the app is navigable without a mouse. Reported against 1.0.0.

**Windows upgrades keep your install location.** Updating with the `.msi` no
longer silently relocates the app to `C:\Program Files`. It remembers where you
installed it and reinstalls there. This takes effect from 2.1.0 onward, so an
install that predates it moves once on the next upgrade and then stays put.

## Interoperability

SSHSIG signatures stay byte-compatible with `ssh-keygen` and with AgePony on iOS
and Android. Desktop signs under the `agepony` namespace by default and verifies
both that and the domain-qualified form, so signatures keep verifying across the
family. The default moves to the domain-qualified namespace once the mobile apps
accept both.
