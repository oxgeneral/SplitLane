#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

mode="${1:-build}"
case "$mode" in
    build|test) ;;
    *) echo "Usage: ./build-engine.sh [build|test [go test flags]]" >&2; exit 2 ;;
esac
if [[ $# -gt 0 ]]; then shift; fi

mkdir -p .build/engines
out="$PWD/.build/engines"
upstream_version=v1.14.1
source_dir="$(go mod download -json "github.com/sagernet/sing-box@$upstream_version" | plutil -extract Dir raw -o - -)"
stage="$(mktemp -d "$out/source.XXXXXX")"
trap 'chmod -R u+w "$stage"; rm -rf "$stage"' EXIT
ditto "$source_dir" "$stage/sing-box"
chmod -R u+w "$stage/sing-box"
/usr/bin/patch -F 0 -p1 -d "$stage/sing-box" < Sources/Engine/darwin-udp-owner.patch
/usr/bin/patch -F 0 -p1 -d "$stage/sing-box" < Sources/Engine/darwin-udp-scope.patch
/usr/bin/patch -F 0 -p1 -d "$stage/sing-box" < Sources/Engine/darwin-dns.patch
cp Tests/DarwinUDPOwner_test.go "$stage/sing-box/common/process/"
cp Tests/DarwinDNS_test.go "$stage/sing-box/dns/transport/local/systemconfig/"
cp Sources/Engine/udp_owner_guard.go Tests/UDPOwnerGuard_test.go "$stage/sing-box/route/"
cp Sources/Engine/webkit_darwin.go "$stage/sing-box/common/process/splitweb_webkit_darwin.go"
lookup="$stage/sing-box/common/process/searcher_darwin_shared.go"
grep -Fq 'owner.ProcessPath = processPath' "$lookup"
sed -i '' 's/owner.ProcessPath = processPath/owner.ProcessPath = resolveWebKitOwner(entry.pid, processPath)/' "$lookup"
cp Sources/Engine/vpn_app_darwin.go "$stage/sing-box/common/dialer/splitweb_vpn_app_darwin.go"
cp Tests/VPNServiceBinding_test.go "$stage/sing-box/common/dialer/"
cp Sources/Engine/udp_scope_darwin.go Tests/UDPScope_test.go "$stage/sing-box/common/dialer/"
dialer="$stage/sing-box/common/dialer/default.go"
grep -Fq 'control.BindToInterface(interfaceFinder, options.BindInterface, -1)' "$dialer"
sed -i '' 's/control.BindToInterface(interfaceFinder, options.BindInterface, -1)/splitWebBindInterface(interfaceFinder, options.BindInterface)/' "$dialer"
cp Sources/Engine/amnezia_darwin.go "$stage/sing-box/common/dialer/splitweb_amnezia_darwin.go"
factory="$stage/sing-box/common/dialer/dialer.go"
grep -Fq 'func New(ctx context.Context, options option.DialerOptions, remoteIsDomain bool) (N.Dialer, error) {' "$factory"
sed -i '' '/^func New(ctx context.Context, options option.DialerOptions, remoteIsDomain bool) (N.Dialer, error) {$/a\
	if local := splitWebAmneziaDialer(options.BindInterface); local != nil { return local, nil }\
' "$factory"
(
    cd "$stage/sing-box"
    export MACOSX_DEPLOYMENT_TARGET=15.0
    export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }-mmacosx-version-min=15.0"
    export CGO_LDFLAGS="${CGO_LDFLAGS:+$CGO_LDFLAGS }-mmacosx-version-min=15.0"
    export CGO_ENABLED=1
    if [[ "$mode" == test ]]; then
        go test ./common/process ./route ./common/dialer ./dns/transport/local/systemconfig \
            -run 'Test(DarwinUDPOwner|DarwinTCPOwner|DarwinResolveAppOwner|DarwinScopedDNS|UDPOwnerGuard|SplitWebVPN|UDPScope)' "$@"
    else
        go build -buildvcs=false -trimpath -tags 'with_gvisor,with_wireguard' \
            -ldflags "-X github.com/sagernet/sing-box/constant.Version=${upstream_version#v}-splitweb" \
            -o "$stage/sing-box-local" ./cmd/sing-box
    fi
)
if [[ "$mode" == test ]]; then exit 0; fi
minimum="$(xcrun vtool -show-build "$stage/sing-box-local" | awk '$1 == "minos" { print $2 }')"
if [[ "$minimum" != 15.0 ]]; then
    printf 'Expected a macOS 15.0 engine, got minimum version %s.\n' "${minimum:-unknown}" >&2
    exit 1
fi
mv "$stage/sing-box-local" "$out/sing-box-local"
touch "$out/sing-box-local.stamp"
