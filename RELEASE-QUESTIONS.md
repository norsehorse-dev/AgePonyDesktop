# Questions for the session that can see the other pony repos

Context to give that session: I'm setting up Phase 6 packaging for **AgePony
Desktop**, a pure-Rust egui app. The house pattern is already established in the
other pony apps — a notarized macOS DMG built locally from a `.pgpony-release-env`
file, and `.deb` (x86_64 + aarch64), `.msi`, AppImage and `.tar.gz`
(x86_64 + aarch64) built in CI. I want to mirror that rather than invent a new
shape. Windows will be **unsigned**.

> **Do not paste any secret values.** Variable and secret *names* only. If a file
> contains credentials, redact the right-hand side.

---

## 1. The files themselves — most valuable, ask for these first

Paste the full contents of whichever exist, from the pony app whose release
setup is most current:

- [ ] `.github/workflows/release.yml` (or whatever the release workflow is called)
- [ ] Any other workflow the release depends on (a reusable/called workflow, a build matrix include file)
- [ ] The local macOS script that builds, signs, notarizes and staples the DMG
- [ ] `Cargo.toml` sections relevant to packaging — `[package.metadata.deb]`, `[package.metadata.wix]`, `[package.metadata.bundle]`, `[workspace.metadata.dist]`
- [ ] Any `.wxs` / WiX source, AppImage recipe or `AppDir` template, `.desktop` file, `Info.plist` template, entitlements plist
- [ ] The variable **names** in `.pgpony-release-env` (I already know four: `MACOS_SIGN_IDENTITY`, `NOTARIZATION_APPLE_ID`, `NOTARIZATION_PASSWORD`, `NOTARIZATION_TEAM_ID` — confirm whether the other apps use more)

If the workflow is long, the whole thing verbatim is still better than a summary.

## 2. Release mechanics

- [ ] What triggers a release — pushing a `v*` tag, a manual `workflow_dispatch`, a release branch?
- [ ] Exact tag/version format (`v1.0.0`, `1.0.0`, `agepony-v1.0.0`)?
- [ ] Does CI **create** the GitHub Release, or does it upload to one made by hand?
- [ ] The DMG is built locally — is it attached to the GitHub Release manually, or does a script upload it?
- [ ] Where do release notes come from — a file in the repo, the tag message, hand-written in the GitHub UI?
- [ ] Are artifacts also copied anywhere else (agepony.com download page, an S3 bucket)? How?

## 3. Artifact naming

- [ ] The exact naming scheme, with a real example of each. For instance is it
      `AgePony-1.0.0-macos-universal.dmg` or `agepony_1.0.0_amd64.deb` or something else?
- [ ] Is there a `SHA256SUMS` file, or per-artifact `.sha256`? Signed (minisign / GPG) or plain?

## 4. macOS specifics

- [ ] Universal binary (`arm64` + `x86_64` via `lipo`), or separate DMGs per architecture?
- [ ] How is the `.app` bundle built — `cargo-bundle`, a hand-rolled script, `create-dmg`?
- [ ] Which `Info.plist` keys are set (bundle id format, category, minimum system version)?
- [ ] Hardened runtime and which entitlements?
- [ ] `notarytool` or the older `altool`? Is the result stapled?
- [ ] How is the `.icns` produced — checked into the repo, or generated from a PNG by `iconutil`?
- [ ] **Confirm the Developer ID Application certificate exists** and is distinct from the App Store one. This is the item most likely to block a release.

## 5. Linux specifics

- [ ] **aarch64: native ARM runners, or cross-compiling from x86_64?** This is the one I most need decided. Note AgePony Desktop uses `eframe`, which pulls in X11, Wayland and GL system libraries — cross-compiling needs those in the target sysroot, which is usually where it goes wrong. Native ARM runners are the safer default.
- [ ] `.deb` built with `cargo-deb`, or by hand? What are the `Depends`, package name, maintainer, section, and where do the `.desktop` file and icon get installed?
- [ ] AppImage tooling — `linuxdeploy`, `appimagetool`, plugins used? How are the icon and `.desktop` file supplied?
- [ ] Minimum glibc / which container or runner image, so the binaries stay portable?
- [ ] Is the `.tar.gz` just the bare binary, or binary plus README/LICENSE/desktop file?

## 6. Windows specifics

Confirmed unsigned, so mainly:

- [ ] MSI built with `cargo-wix`, WiX directly, or something else? Which WiX version?
- [ ] How is the upgrade GUID managed across versions?
- [ ] Default install location and Start Menu entry?
- [ ] Is a plain `.zip` shipped alongside the MSI?

## 7. CI environment

- [ ] Which runner images (`macos-14`, `ubuntu-22.04`, `windows-latest`)?
- [ ] Is the Rust toolchain pinned in CI, and how — `rust-toolchain.toml`, `dtolnay/rust-toolchain@stable`, a specific version?
- [ ] Which caching action, if any?
- [ ] The **names** of the GitHub secrets the workflow reads (values redacted)?
- [ ] Does CI also run tests and clippy before building artifacts, or is that a separate workflow?

## 8. Repo

- [ ] Repo name for this one — the plan lists `AgePonyDesktop` vs `AgePonyRust` as an open question. Which did you settle on?
- [ ] Public from the first commit, or private until 1.0?
- [ ] Is there a standard `LICENSE`, `NOTICE`, `SECURITY.md` or issue-template set copied between pony repos that this should have too?
