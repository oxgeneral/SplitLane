#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

: "${SPLITLANE_NOTARY_PROFILE:?Set the notarytool Keychain profile name}"
./build.sh release
./build.sh test
./build-engine.sh test

destination="$PWD/.build/release"
stage="$(mktemp -d "$destination/package.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/package"
app="$stage/package/SplitLane.app"
ditto "$destination/SplitLane.app" "$app"
ditto -c -k --sequesterRsrc --keepParent "$app" "$stage/notarization.zip"
xcrun notarytool submit "$stage/notarization.zip" --keychain-profile "$SPLITLANE_NOTARY_PROFILE" --wait
xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict "$app"
spctl --assess --type execute "$app"

cp INSTALL.txt "$stage/package/"
name="SplitLane-$SPLITLANE_RELEASE_VERSION-$SPLITLANE_BUILD_NUMBER-mac-$(uname -m).zip"
ditto -c -k --sequesterRsrc "$stage/package" "$stage/$name"
mv "$stage/$name" "$destination/$name"
printf '%s\n' "$destination/$name"
