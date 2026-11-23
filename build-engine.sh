#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p .build/engines
out="$PWD/.build/engines"
source_dir="$(go mod download -json github.com/sagernet/sing-box@v1.14.1 | plutil -extract Dir raw -o - -)"
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
    CGO_ENABLED=1 go test ./common/process ./route ./common/dialer ./dns/transport/local/systemconfig -run 'Test(DarwinUDPOwner|DarwinTCPOwner|DarwinResolveAppOwner|DarwinScopedDNS|UDPOwnerGuard|SplitWebVPN|UDPScope)'
    CGO_ENABLED=1 go build -trimpath -tags 'with_gvisor,with_wireguard' -o "$stage/sing-box-local" ./cmd/sing-box
)
mv "$stage/sing-box-local" "$out/sing-box-local"
touch "$out/sing-box-local.stamp"
