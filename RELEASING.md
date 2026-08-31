# Releasing AgePony Desktop

Each release ships eight artifacts — a signed and notarized **`.dmg`** (macOS, **universal**), an
**`.msi`** (Windows, x64), and six for Linux: a **`.deb`**, a portable **`.tar.gz`** and an
**`.AppImage`**, each for both **x86_64** and **ARM64** — plus a detached `.asc` for every one of
them and a signed `SHA256SUMS` covering the lot. Nine signatures.

Both architectures carry an explicit suffix. AgePony has never shipped, so there are no links to
preserve and the names are symmetric.

The work is split because the signing credentials must never reach a hosted runner:

| Where | What |
| --- | --- |
| **CI**, on a tag push | the six Linux artifacts + the `.msi`, into a **draft** release |
| **Your Mac** | the `.dmg`, notarization, every PGP signature, and publishing the draft |

**This repository holds no secrets.** The Developer ID certificate never reaches a hosted runner,
and neither does the PGP release key. A compromised Actions run cannot sign anything.

## What differs from BurnPony and PGPony

Those are Compose Multiplatform, packaged by `jpackage`. The release *shape* here is theirs
deliberately — same trigger, same draft flow, same naming, same signing scheme — but four things are
different on purpose, and three of them are corrections rather than preferences:

- **The macOS build is universal.** The family is arm64-only, and that was never a decision:
  jpackage builds for its host and the host is an Apple-silicon Mac, so Intel Macs are unserved.
  Rust makes `lipo` cheap. **The download page copy across the family says "Apple silicon" and needs
  changing for this one.**
- **CI builds on `ubuntu-22.04`, not `ubuntu-latest`.** A bundled JVM makes the host's glibc
  irrelevant; a Rust binary inherits it. `ubuntu-latest` is 24.04, glibc 2.39, which would produce
  artifacts that refuse to start on Debian 12 or Ubuntu 22.04. 22.04 is glibc 2.35.
- **The release workflow runs the test suite** before building anything. BurnPony relies on this
  document telling you to run them locally, and on its first release that step got skipped.
- **The binary installs to `/usr/bin`**, not `/opt`. jpackage puts nothing on `PATH` and the family
  documents the tarball as the workaround; `cargo-deb` has no such limitation.

## 0. First release only — the repository does not exist yet

```sh
git init
git add -A
git commit -m "AgePony Desktop 1.0.0"
gh repo create norsehorse-dev/AgePonyDesktop --public --source=. --push
```

**Check `.gitignore` first.** It covers `/target`, `_to_delete/`, `__pycache__/` and — the one that
matters — `*-release-env`. `.pgpony-release-env` holds `NOTARIZATION_PASSWORD`, and committing it
once puts an Apple app-specific password in the history permanently. `git status` should not list
it; confirm with `git check-ignore -v .pgpony-release-env` before that first `git add -A`.

Push `main` before the first tag. The release workflow triggers only on `v*`, so pushing `main`
gives you a free syntax check of `build.yml` in the Actions tab. **The release workflow cannot be
dry-run**, and BurnPony's first tag took three attempts.

## 1. Before tagging

**One number, one place.** `version` in the workspace `Cargo.toml` feeds `agepony version`, the deb,
the MSI and the Info.plist. Nothing else declares it.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo run --release --bin agepony -- selftest
git status --short
git push
```

A tag on a tree with uncommitted work produces a release that does not contain it.

If the icons changed, regenerate them and commit the result — the master lives in the iOS repo:

```sh
tools/make-icons.py
```

## 2. Tag — CI builds the seven

```sh
git tag v1.0.0
git push origin v1.0.0
sleep 15
gh run watch $(gh run list --workflow=release.yml --limit 1 \
  --json databaseId --jq '.[0].databaseId')
```

The `sleep` matters: `gh run list` fires before the new run registers and hands you the *previous*
run's id, which then reports success for work you are not watching.

Three build jobs — `linux (x86_64)`, `linux (aarch64)` and `windows`. The two Linux legs are one
matrix job deliberately: an ARM lane maintained as a copy of the x86_64 lane drifts, and a lane that
drifts is a lane whose assertions quietly stop covering it.

CI runs checks a green build would otherwise hide. Read the log rather than the checkmark the first
time:

- **the deb's identity** — `Package` must be `agepony`, lowercase, `Architecture` must match the
  lane, and `Depends` must be non-empty and mention `libc6`. An empty `Depends` means `$auto` did
  not scan the ELF, and the deb installs onto a machine with no GL and fails at launch.
- **the desktop entry** — passes `desktop-file-validate`, has a real `Categories`, and carries **no**
  `MimeType`. The last one is a tripwire: AgePony implements no handler for an opened file, so if
  associations are added later this fails and forces the `.desktop` and the routing code to land
  together.
- **`selftest` passes in the shipped binary**, on all three platforms and both architectures —
  including the post-quantum reference vector. That last check is the only thing that would catch
  ML-KEM behaving differently on aarch64, which a test suite running only on the build machine
  cannot see.
- **`list-recipients` opens the store** — the only check that touches the config directory and the
  JSON outside a dev environment.
- **on Windows, both binaries exist, `agepony-cli.exe` prints, and `agepony.exe` does not.** The
  last one is not redundant: if `windows_subsystem = "windows"` were dropped, the GUI would flash a
  console window on every launch and nothing else would notice.

## 3. On the Mac — the dmg

The four values live in a file outside the repo, `chmod 600`, shared with the other pony desktops
because the Apple credentials are account-level.

```sh
source ~/.pgpony-release-env      # MACOS_SIGN_IDENTITY, NOTARIZATION_{APPLE_ID,PASSWORD,TEAM_ID}
tools/make-dmg.sh
```

The script builds both architectures, `lipo`s them together, writes and **reads back** the
`Info.plist`, signs with the hardened runtime, notarizes, staples, and then verifies the app inside
the mounted image. Expect several minutes of apparent inactivity at the notarization step — that is
Apple's service, not a hang.

Gotchas, all inherited and all still current:

- `MACOS_SIGN_IDENTITY` is the certificate **name**, not its SHA-1 hash.
- Only **one** `Developer ID Application` certificate may be in the keychain, or codesign reports
  "multiple matching certificates". List with `security find-identity -v -p codesigning`, delete
  keyless extras with `security delete-certificate -Z <hash>`.
- **The dmg container is deliberately unsigned.** The `.app` is signed and notarized and the ticket
  is stapled to the image. `spctl -a -t open --context context:primary-signature` therefore
  **rejects a perfectly good release** with `source=no usable signature`, because it is asking an
  unsigned container a signature question. `make-dmg.sh` runs the checks that mean something —
  `spctl -a -t exec` on the app inside the mounted image, and then actually running it. The hardened
  runtime restricts library loading at runtime, so a clean notarization does not imply a working app.

Confirm `lipo -info` reported **both** `x86_64` and `arm64`, and that `selftest` printed
`PASS - all 6 checks`.

## 4. Assemble, sign, publish

Pull CI's seven down beside your dmg, then sign all eight together so `SHA256SUMS` covers the exact
bytes that ship.

```sh
rm -rf ~/agepony-release && mkdir -p ~/agepony-release && cd ~/agepony-release
gh release download v1.0.0 --repo norsehorse-dev/AgePonyDesktop --dir . --clobber
cp /Users/kevinstewart/Apps/AgePonyDesktop/dist/AgePony-macOS.dmg .
```

**Before signing, confirm the bytes are this release.** A stale binary left in the staging dir from a
prior cycle gets signed as if it belonged to this one, and a good signature over the wrong version is
still the wrong version. Both bit 2.1.0. The `rm -rf` and `--clobber` above prevent the stale dir; this
catches it if it slips through. The Linux and Windows binaries do not run on the Mac, so check the
version string they embed (substitute the version you are shipping):

```sh
rm -rf /tmp/ap-vc && mkdir /tmp/ap-vc
tar -xzf AgePony-linux-x86_64.tar.gz -C /tmp/ap-vc
strings "$(find /tmp/ap-vc -type f -name agepony)" | grep 'AgePony Desktop 1.0.0'
```

That line must print. If it shows an older version, the staging dir was not clean; start this section
over. Then assemble and sign:

```sh
FILES=(
  AgePony-macOS.dmg
  AgePony-linux-x86_64.deb
  AgePony-linux-x86_64.tar.gz
  AgePony-x86_64.AppImage
  AgePony-linux-arm64.deb
  AgePony-linux-aarch64.tar.gz
  AgePony-aarch64.AppImage
  AgePony-windows.msi
)

shasum -a 256 $FILES > SHA256SUMS
cat SHA256SUMS
for f in $FILES SHA256SUMS; do
  gpg -u A0CBC8F65AACE56F1C5B767753F9798E4919DE62 --armor --detach-sign "$f"
done
for f in $FILES SHA256SUMS; do
  gpg --verify "$f.asc" "$f"
done
shasum -a 256 -c SHA256SUMS
```

The same NorseHorse release key signs BurnPony, PGPony and RelayPony. One key to publish, one
fingerprint for users to learn, one revocation to handle if it ever comes to that.

An **array**, not a space-separated string. This shell is zsh, and zsh does not word-split an
unquoted `$var` the way bash does — `FILES="a b c"` followed by `shasum $FILES` passes one filename
made of all three joined, and every command in the block then fails in a way that looks like the
files are missing.

The explicit `-u` is not decoration either: a bare `gpg --detach-sign` failed with "no default secret
key" during PGPony's 1.0.1 cycle. Count **nine** `Good signature` lines before going any further.

Verify before publishing, not after. A signature that does not check out is worse than none.

```sh
gh release upload v1.0.0 AgePony-macOS.dmg *.asc SHA256SUMS \
  --repo norsehorse-dev/AgePonyDesktop
gh release edit v1.0.0 --draft=false --latest --repo norsehorse-dev/AgePonyDesktop
```

`--latest` is load-bearing. `releases/latest/download/…` — the stable, versionless URLs handed out in
a README or used by anyone scripting an install — resolve to whichever release carries the "latest"
flag, not to the newest tag. Published without it, those links point at the previous version
silently and indefinitely; on a first release, at nothing.

## 5. Mirror to agepony.com — the Tor and I2P channel

The GitHub release is not the only download channel. `agepony.com` self-hosts every
artifact under `public/downloads/`, and that self-hosted copy is what Tor and I2P users
pull: they browse the hidden-service mirror of the same site and download from it, because
GitHub over Tor is slow and frequently blocked. The clearnet site and the hidden services
share one docroot, so a single deploy serves all three.

The download page (`public/desktop.php`) reads the version, the notes, and the per-artifact
SHA-256 hashes from `public/downloads/desktop.json`. Nothing on the page is hardcoded per
release, so the manifest is the one file that has to be right.

The site lives in the PonyHTML repo. Layout under `public/downloads/`:

```
desktop.json
norsehorse-release-key.asc
latest/
v1.0.0/
v2.0.0/
```

Each `vX.Y.Z/` holds the eight artifacts, their eight `.asc`, `SHA256SUMS` and
`SHA256SUMS.asc` — the same eighteen files the GitHub release carries. `latest/` is a copy
of the current version's files, for the versionless `downloads/latest/...` URLs.

### Stage the release into the site

Working from the release directory assembled in section 4. Point `SITE` at your PonyHTML
checkout's `public/downloads`.

```
SITE="$HOME/Apps/PonyHTML/agepony/public/downloads"
mkdir -p "$SITE/v2.0.0"
cp ~/agepony-release/* "$SITE/v2.0.0/"
cp "$SITE/v2.0.0"/* "$SITE/latest/"
ls "$SITE/v2.0.0" | wc -l
```

That prints `18`. Filenames are identical across versions, so copying over `latest/` leaves
nothing stale.

### Update the manifest

Edit `desktop.json`: set `current.version`, `released`, `tag` and `dir`; replace every
`sha256` from the `SHA256SUMS` you just copied; write the notes; and move the outgoing
`current` object into the `previous` array so the old version stays listed. Validate before
deploying.

```
python3 -c "import json;json.load(open('$SITE/desktop.json'))" && echo ok
```

### Deploy

`/var/www` needs root, so stage to your home on the host and place with sudo. `apps` is the
web host alias.

```
ssh apps 'mkdir -p ~/agepony-deploy'
scp -r "$SITE/v2.0.0" "$SITE/desktop.json" apps:~/agepony-deploy/
ssh apps 'sudo mkdir -p /var/www/agepony/public/downloads/v2.0.0 /var/www/agepony/public/downloads/latest && sudo cp ~/agepony-deploy/v2.0.0/* /var/www/agepony/public/downloads/v2.0.0/ && sudo cp ~/agepony-deploy/v2.0.0/* /var/www/agepony/public/downloads/latest/ && sudo cp ~/agepony-deploy/desktop.json /var/www/agepony/public/downloads/desktop.json && sudo chmod -R a+rX /var/www/agepony/public/downloads && rm -rf ~/agepony-deploy'
```

Only `v2.0.0` and the manifest cross the wire; `latest/` is filled from them on the host, so
the artifacts upload once, not twice. The older `vX.Y.Z/` directories are already on the host
and are left alone.

### Confirm it is live

```
curl -s https://agepony.com/downloads/desktop.json | grep -m1 version
curl -sI https://agepony.com/downloads/latest/AgePony-macOS.dmg | head -1
curl -s https://agepony.com/downloads/latest/SHA256SUMS | head -1
```

The version reads the new release, the dmg returns `200`, and the SHA line matches the dmg's
entry in `SHA256SUMS`. The `.onion` and `.i2p` addresses (see `public/mirrors.php`) serve the
same bytes off the same docroot, so there is nothing separate to push for them.

Gotchas:

- **The manifest is the whole page.** A stale hash there shows a checksum that will not match
  the download, which a careful user reports as tampering. Copy the hashes from `SHA256SUMS`;
  do not retype them.
- **`latest/` must be overwritten every release.** Its filenames are identical across
  versions, so if it is not refreshed it silently serves the previous binaries under the
  versionless URLs.
- **Ownership on the host is your web user.** `chmod a+rX` keeps the files world-readable
  whatever owns them; if your server expects a specific owner, add a `chown`.

## 6. Verification checklist

Artifacts:

- [ ] `gpg --verify` each `.asc`, and `SHA256SUMS.asc` against `SHA256SUMS` — nine in total
- [ ] `shasum -a 256 -c SHA256SUMS` passes (macOS has no `sha256sum`; the format is identical, so
      Linux users can verify later with `sha256sum -c`)
- [ ] the tarball extracts and `AgePony/agepony version` prints, once by hand on a real ARM machine
- [ ] the AppImage is executable and runs, and double-clicking it opens the GUI on a desktop with FUSE
- [ ] `selftest` reports `PASS - all 6 checks` from the **installed** artifact on every OS
- [ ] `selftest`'s version line reports the same rustc on all three platforms. The dmg is the
      artifact at risk, because it is the only one CI does not build
- [ ] `list-recipients` prints "No recipients on this machine." on a machine with no config

macOS:

- [ ] `lipo -info` on the installed binary reports both architectures
- [ ] `xcrun stapler validate` on the dmg
- [ ] `spctl -a -t exec -vv` on the app inside the mounted dmg says `Notarized Developer ID`
- [ ] a quarantined dmg opens with no dialog, and the app launches from `/Applications` without a prompt
- [ ] **the Dock icon is inset and squircle-cornered**, not a hard-edged square sitting larger than
      its neighbours. macOS does not mask, so this is `tools/make-icons.py`'s 824/1024 grid being
      right, and it is only visible in the Dock
- [ ] test on an **Intel** Mac if one is reachable — this is the family's first universal build and
      nothing else has ever exercised that half

Windows:

- [ ] the MSI installs on a clean machine and the Start Menu entry appears
- [ ] `agepony.exe` opens the GUI with **no console window flashing behind it**
- [ ] `agepony-cli.exe selftest` prints and exits 0
- [ ] SmartScreen behaviour recorded for the release notes — the MSI is unsigned

Every OS:

- [ ] encrypt and decrypt a real file through the GUI, with a classic identity, a post-quantum one,
      and a passphrase
- [ ] a file encrypted on AgePony iOS or Android opens here, and one encrypted here opens there
- [ ] the GUI opens in both light and dark mode and nothing is clipped

## 7. Not set up yet — known gaps

Listed so they are decisions rather than oversights:

- **The download-page body copy.** `desktop.php` reads the version, notes and hashes from the
  manifest, so those update themselves (section 5), but any feature copy written into the page
  body is hand-maintained and does not. Check it still describes the current feature set.
- **winget.** No manifest. Note for whenever this starts: `ProductCode` is **not** the `UpgradeCode`
  in `wix/main.wxs` — different GUIDs, and confusing them bit PGPony's manifest.
- **AUR.** No `agepony-bin` PKGBUILD. It would need to be pushed **after** the release is published,
  because a PKGBUILD pointing at a draft gives every user a 404.
- **The MSI is the least-verified artifact.** `wix/main.wxs` was generated by `cargo wix init` and
  hand-edited for the product name, description and icon, and none of that has been through WiX.
  CI installs the MSI and runs the binary out of it, so a broken source fails the tag rather than a
  user — but expect the first tag to be where this is found.
