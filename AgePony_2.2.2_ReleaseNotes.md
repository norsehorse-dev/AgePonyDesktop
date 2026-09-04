# AgePony Desktop 2.2.2

A fix for one field report on 2.2.1.

## Fixed

**Verifying signatures from the mobile apps and ssh-keygen works.** AgePony Desktop
rejected a valid Ed25519 or RSA signature made by the AgePony mobile apps or by
ssh-keygen, reporting "not a valid SSH signature," while it accepted its own. Those
signers wrap the armored signature at 70 columns and the desktop parser only accepted
64, so it turned away signatures it should have read. It now accepts any line width, the
same as ssh-keygen. Signatures made on the desktop were never affected.
