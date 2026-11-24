#!/bin/bash
set -euo pipefail

if [[ $# != 5 ]]; then
    echo "Usage: bash package-macos.sh AMNEZIA_APP AWG_HELPER QT_DIR QML_DIR OUTPUT_APP" >&2
    exit 2
fi

source_app=$1
helper=$2
qt=$3
qml=$4
output=$5
[[ ! -e "$output" && -x "$helper" && -x "$qt/bin/macdeployqt" && -d "$qml" ]]
mkdir -p "$output/Contents/MacOS"
cp "$source_app/Contents/Info.plist" "$output/Contents/"
cp "$source_app/Contents/MacOS/AmneziaVPN" "$output/Contents/MacOS/"
cp "$helper" "$output/Contents/MacOS/splitlane-awg"
ditto "$source_app/Contents/Resources" "$output/Contents/Resources"
plist="$output/Contents/Info.plist"
plutil -replace CFBundleIdentifier -string local.splitlane.amnezia "$plist"
plutil -replace CFBundleName -string "AmneziaVPN for SplitLane" "$plist"
plutil -replace CFBundleDisplayName -string "AmneziaVPN for SplitLane" "$plist"
if plutil -extract LSEnvironment xml1 -o - "$plist" >/dev/null 2>&1; then
    plutil -remove LSEnvironment "$plist"
fi
"$qt/bin/macdeployqt" "$output" "-qmldir=$qml" -no-strip -verbose=1
for driver in libqsqlmimer.dylib libqsqlodbc.dylib libqsqlpsql.dylib; do
    plugin="$output/Contents/PlugIns/sqldrivers/$driver"
    if [[ -f "$plugin" ]]; then rm "$plugin"; fi
done
codesign --force --deep --sign - "$output"
codesign --verify --deep --strict "$output"
