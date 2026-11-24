#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

mode="${1:-adhoc}"
case "$mode" in
    adhoc)
        build_mode=adhoc
        [[ "$(uname -m)" == arm64 ]] || { echo "Build the public test package on Apple Silicon." >&2; exit 1; }
        ;;
    notarized)
        : "${SPLITLANE_NOTARY_PROFILE:?Set the notarytool Keychain profile name}"
        build_mode=release
        ;;
    *) echo "Usage: ./release.sh [adhoc|notarized]" >&2; exit 2 ;;
esac
./build.sh "$build_mode"
./build.sh test
./build-engine.sh test

destination="$PWD/.build/$build_mode"
stage="$(mktemp -d "$destination/package.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/package"
app="$stage/package/SplitLane.app"
ditto "$destination/SplitLane.app" "$app"
if [[ "$mode" == notarized ]]; then
    ditto -c -k --sequesterRsrc --keepParent "$app" "$stage/notarization.zip"
    xcrun notarytool submit "$stage/notarization.zip" --keychain-profile "$SPLITLANE_NOTARY_PROFILE" --wait
    xcrun stapler staple "$app"
    xcrun stapler validate "$app"
    spctl --assess --type execute "$app"
fi
codesign --verify --deep --strict "$app"

cp INSTALL.txt THIRD_PARTY_NOTICES.txt GPL-3.0.txt "$stage/package/"
name="SplitLane-$SPLITLANE_RELEASE_VERSION-$SPLITLANE_BUILD_NUMBER-mac-$(uname -m)"
files=("$name.zip")
ditto -c -k --sequesterRsrc "$stage/package" "$stage/$name.zip"
if [[ "$mode" == adhoc ]]; then
    ln -s /Applications "$stage/package/Applications"
    hdiutil create -quiet -volname SplitLane -srcfolder "$stage/package" -format UDZO "$stage/$name.dmg"
    hdiutil verify -quiet "$stage/$name.dmg"
    files+=("$name.dmg")
fi
(cd "$stage" && shasum -a 256 "${files[@]}" > SHA256SUMS.txt)
for file in "${files[@]}" SHA256SUMS.txt; do
    mv "$stage/$file" "$destination/$file"
    printf '%s\n' "$destination/$file"
done
