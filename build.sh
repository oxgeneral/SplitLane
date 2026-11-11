#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

mode="${1:-preview}"
case "$mode" in
    preview|test|signed|tun|local|standalone) ;;
    *) echo "Usage: ./build.sh [preview|test|signed|tun|local|standalone]" >&2; exit 2 ;;
esac

mkdir -p .build
compiler=(xcrun swiftc -swift-version 5 -target "$(uname -m)-apple-macos15.0")
if [[ "$mode" == test ]]; then
    "${compiler[@]}" Sources/Shared/*.swift Tests/Check.swift -o .build/check
    .build/check
    exit
fi

app_id="local.splitwebonmac.preview"
if [[ "$mode" == signed ]]; then
    : "${SPLITWEB_SIGN_IDENTITY:?Set the Developer ID Application signing identity}"
    : "${SPLITWEB_APP_PROFILE:?Set the path to the app provisioning profile}"
    : "${SPLITWEB_EXTENSION_PROFILE:?Set the path to the extension provisioning profile}"
    : "${SPLITWEB_BUNDLE_ID:?Set the registered app bundle identifier}"
    : "${SPLITWEB_TEAM_ID:?Set the Apple developer team ID}"
    app_id="$SPLITWEB_BUNDLE_ID"
    [[ -f "$SPLITWEB_APP_PROFILE" && -f "$SPLITWEB_EXTENSION_PROFILE" ]]
    [[ "$app_id" =~ ^[a-zA-Z0-9.-]+$ && "$SPLITWEB_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]
fi

out="$(mktemp -d "$PWD/.build/staging.XXXXXX")"
trap 'rm -rf "$out"' EXIT
app="$out/SplitWebOnMac.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
plist="$app/Contents/Info.plist"

bundle_info() {
    cat > "$1" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>$2</string>
  <key>CFBundleExecutable</key><string>$3</string>
  <key>CFBundleName</key><string>SplitWebOnMac</string>
  <key>CFBundlePackageType</key><string>$4</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>15.0</string>
</dict></plist>
PLIST
}

bundle_info "$plist" "$app_id" SplitWebOnMac APPL
cp Sources/App/Resources/AppIcon.icns "$app/Contents/Resources/"
plutil -insert CFBundleIconFile -string AppIcon.icns "$plist"
"${compiler[@]}" Sources/Shared/*.swift Sources/App/*.swift -o "$app/Contents/MacOS/SplitWebOnMac"
"${compiler[@]}" -module-name SplitWebProxy Sources/Shared/*.swift Sources/Extension/*.swift -o "$out/SplitWebProxy"

if [[ "$mode" == tun || "$mode" == local || "$mode" == standalone ]]; then
    engine_stamp=.build/engines/sing-box-local.stamp
    if [[ ! -x .build/engines/sing-box-local || ! -f "$engine_stamp" || build-engine.sh -nt "$engine_stamp" ||
          Sources/Engine/vpn_app_darwin.go -nt "$engine_stamp" || Sources/Engine/webkit_darwin.go -nt "$engine_stamp" ||
          Sources/Engine/amnezia_darwin.go -nt "$engine_stamp" ]]; then
        ./build-engine.sh
    fi
    cp .build/engines/sing-box-local "$app/Contents/Resources/sing-box"
    cp Sources/Engine/run-tun.sh "$app/Contents/Resources/run-tun.sh"
    engine_sha="$(shasum -a 256 "$app/Contents/Resources/sing-box" | awk '{print $1}')"
    plutil -insert SplitWebEngineSHA -string "$engine_sha" "$plist"
    if [[ "$mode" != tun ]]; then
        "${compiler[@]}" -parse-as-library Sources/Tools/ProxyOverlay.swift -o "$app/Contents/Resources/proxy-overlay"
        cp Sources/Engine/run-proxy.sh Sources/Engine/run-engine.sh Sources/Engine/proxy-permission.sh "$app/Contents/Resources/"
        helper_sha="$(shasum -a 256 "$app/Contents/Resources/proxy-overlay" | awk '{print $1}')"
        plutil -insert SplitWebProxyOverlaySHA -string "$helper_sha" "$plist"
    fi
fi

if [[ "$mode" == standalone ]]; then
    : "${SPLITWEB_AMNEZIA_APP:?Set the path to the packaged AmneziaVPN for SplitWeb.app}"
    codesign --verify --deep --strict "$SPLITWEB_AMNEZIA_APP"
    [[ -x "$SPLITWEB_AMNEZIA_APP/Contents/MacOS/splitweb-awg" &&
       -d "$SPLITWEB_AMNEZIA_APP/Contents/Frameworks/QtCore.framework" ]]
    mkdir -p "$app/Contents/Helpers"
    ditto "$SPLITWEB_AMNEZIA_APP" "$app/Contents/Helpers/AmneziaVPN for SplitWeb.app"
fi

if [[ "$mode" == signed ]]; then
    extension_id="$app_id.proxy"
    group="$SPLITWEB_TEAM_ID.$app_id"
    extension="$app/Contents/Library/SystemExtensions/$extension_id.systemextension"
    extension_plist="$extension/Contents/Info.plist"
    mkdir -p "$extension/Contents/MacOS"
    mv "$out/SplitWebProxy" "$extension/Contents/MacOS/$extension_id"
    bundle_info "$extension_plist" "$extension_id" "$extension_id" SYSX

    plutil -insert SplitWebRoutingBuild -bool YES "$plist"
    plutil -insert NSSystemExtensionUsageDescription -string 'Назначает сетевые маршруты выбранным приложениям.' "$extension_plist"
    /usr/libexec/PlistBuddy -c 'Add :NetworkExtension dict' \
        -c "Add :NetworkExtension:NEMachServiceName string $group.service" \
        -c 'Add :NetworkExtension:NEProviderClasses dict' \
        -c 'Add :NetworkExtension:NEProviderClasses:com.apple.networkextension.app-proxy string SplitWebProxy.Provider' \
        "$extension_plist"

    entitlements() {
        cat > "$1" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.application-identifier</key><string>$SPLITWEB_TEAM_ID.$2</string>
  <key>com.apple.developer.team-identifier</key><string>$SPLITWEB_TEAM_ID</string>
  <key>com.apple.developer.networking.networkextension</key><array><string>app-proxy-provider-systemextension</string></array>
  <key>com.apple.security.application-groups</key><array><string>$group</string></array>
</dict></plist>
PLIST
    }
    entitlements "$out/app.entitlements" "$app_id"
    entitlements "$out/extension.entitlements" "$extension_id"
    /usr/libexec/PlistBuddy -c 'Add :com.apple.developer.system-extension.install bool true' "$out/app.entitlements"
    cp "$SPLITWEB_APP_PROFILE" "$app/Contents/embedded.provisionprofile"
    cp "$SPLITWEB_EXTENSION_PROFILE" "$extension/Contents/embedded.provisionprofile"
    codesign --force --timestamp --options runtime --sign "$SPLITWEB_SIGN_IDENTITY" --entitlements "$out/extension.entitlements" "$extension"
    codesign --force --timestamp --options runtime --sign "$SPLITWEB_SIGN_IDENTITY" --entitlements "$out/app.entitlements" "$app"
else
    codesign --force --sign - "$app"
fi
codesign --verify --deep --strict "$app"

destination="$PWD/.build/$mode"
mkdir -p "$destination"
rm -rf "$destination/SplitWebOnMac.app"
mv "$app" "$destination/"
printf '%s\n' "$destination/SplitWebOnMac.app"
