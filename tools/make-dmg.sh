#!/bin/bash
# Build, sign, notarize and staple the macOS disk image.
#
# The first real signing script in the pony family. BurnPony and PGPony are
# Compose Multiplatform, where `./gradlew notarizeDmg` does all of this inside
# the build plugin; there is nothing to copy for a Rust app, so this is written
# from the steps that plugin performs.
#
#   source ~/.pgpony-release-env
#   tools/make-dmg.sh
#
# Produces dist/AgePony-macOS.dmg. RELEASING.md has the rest.

set -euo pipefail

APP="AgePony"
BUNDLE_ID="app.agepony.desktop"
CATEGORY="public.app-category.utilities"
MIN_MACOS="11.0"
DIST="dist"
BUNDLE="$DIST/$APP.app"

: "${MACOS_SIGN_IDENTITY:?source ~/.pgpony-release-env first}"
: "${NOTARIZATION_APPLE_ID:?source ~/.pgpony-release-env first}"
: "${NOTARIZATION_PASSWORD:?source ~/.pgpony-release-env first}"
: "${NOTARIZATION_TEAM_ID:?source ~/.pgpony-release-env first}"

VERSION=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$VERSION" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }
echo "AgePony Desktop $VERSION"

# Only ONE Developer ID Application certificate may be in the keychain, or codesign reports
# "multiple matching certificates". List with: security find-identity -v -p codesigning
# Delete keyless extras with: security delete-certificate -Z <hash>
#
# MACOS_SIGN_IDENTITY is the certificate NAME, not its SHA-1 hash.
echo "signing identity: $MACOS_SIGN_IDENTITY"

# ── universal binary ────────────────────────────────────────────────────────
#
# The rest of the family is arm64-only, and that was never a decision -- jpackage
# builds for its host and the host is Apple silicon, so Intel Macs are unserved.
# Rust makes this cheap, so AgePony does it properly.
echo "==> building both architectures"
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --target aarch64-apple-darwin --bin agepony
cargo build --release --target x86_64-apple-darwin --bin agepony

rm -rf "$DIST"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"

lipo -create -output "$BUNDLE/Contents/MacOS/$APP" \
  target/aarch64-apple-darwin/release/agepony \
  target/x86_64-apple-darwin/release/agepony
lipo -info "$BUNDLE/Contents/MacOS/$APP"

cp packaging/agepony.icns "$BUNDLE/Contents/Resources/$APP.icns"

# jpackage writes the literal string "Unknown" for the category and defaults the
# minimum system version to 10.13, which is nonsense. Nothing generates this
# plist, so set both honestly and read the result back below.
cat > "$BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>$APP</string>
    <key>CFBundleDisplayName</key><string>$APP</string>
    <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
    <key>CFBundleExecutable</key><string>$APP</string>
    <key>CFBundleIconFile</key><string>$APP.icns</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSApplicationCategoryType</key><string>$CATEGORY</string>
    <key>LSMinimumSystemVersion</key><string>$MIN_MACOS</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

echo "==> the plist that was actually written"
plutil -p "$BUNDLE/Contents/Info.plist"
# Read it back rather than trusting the heredoc. This is the check BurnPony's
# build file has a comment demanding and no automation for.
test "$(plutil -extract LSApplicationCategoryType raw "$BUNDLE/Contents/Info.plist")" = "$CATEGORY"
test "$(plutil -extract LSMinimumSystemVersion raw "$BUNDLE/Contents/Info.plist")" = "$MIN_MACOS"

# ── sign ────────────────────────────────────────────────────────────────────
#
# --options runtime is the hardened runtime, which notarization requires. An egui
# app needs no entitlements: the JIT and unsigned-memory exceptions that force
# them are JVM and Electron problems.
echo "==> signing"
codesign --force --deep --options runtime --timestamp \
  --sign "$MACOS_SIGN_IDENTITY" "$BUNDLE"
codesign --verify --deep --strict --verbose=2 "$BUNDLE"

# ── disk image ──────────────────────────────────────────────────────────────
echo "==> building the disk image"
STAGE="$DIST/stage"
mkdir -p "$STAGE"
cp -R "$BUNDLE" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
DMG="$DIST/$APP-macOS.dmg"
hdiutil create -volname "$APP" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
rm -rf "$STAGE"

# ── notarize ────────────────────────────────────────────────────────────────
#
# Expect several minutes of apparent inactivity. That is Apple's service, not a
# hang. Unlike Compose, notarytool takes the team id directly.
echo "==> notarizing (this takes a few minutes)"
xcrun notarytool submit "$DMG" \
  --apple-id "$NOTARIZATION_APPLE_ID" \
  --password "$NOTARIZATION_PASSWORD" \
  --team-id "$NOTARIZATION_TEAM_ID" \
  --wait

xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"

# ── verify what actually ships ──────────────────────────────────────────────
#
# The DMG container is deliberately unsigned -- the .app is signed and notarized
# and the ticket is stapled to the image. So
# `spctl -a -t open --context context:primary-signature` REJECTS a perfectly good
# release with `source=no usable signature`, because it is asking an unsigned
# container a signature question. The checks that mean something are on the app
# inside a mounted image.
echo "==> verifying the app inside the mounted image"
MOUNT=/tmp/ageponydmg
hdiutil attach "$DMG" -nobrowse -mountpoint "$MOUNT"
trap 'hdiutil detach "$MOUNT" >/dev/null 2>&1 || true' EXIT

spctl -a -t exec -vv "$MOUNT/$APP.app"

# The hardened runtime restricts library loading at RUNTIME, so a clean
# notarization does not imply a working app. Running the real signed binary out
# of the mounted image is the only check that does -- and it is the macOS
# counterpart of what CI asserts on the other two platforms, on the one artifact
# no CI job builds.
"$MOUNT/$APP.app/Contents/MacOS/$APP" version
"$MOUNT/$APP.app/Contents/MacOS/$APP" selftest

hdiutil detach "$MOUNT"
trap - EXIT

echo
echo "done: $DMG"
echo "next: RELEASING.md section 4 — assemble, sign, publish"
