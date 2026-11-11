import Foundation

struct ProxyRoutingConfiguration: Sendable {
    static let port: UInt16 = 39878
    let data: Data

    static func make(rules apps: [AppRule]) throws -> ProxyRoutingConfiguration {
        guard !apps.isEmpty else { throw TunConfiguration.failure("Сначала добавь хотя бы одно правило.") }
        var outbounds: [[String: Any]] = [["type": "direct", "tag": "system"]]
        var dns: [[String: Any]] = [["type": "local", "tag": "system-dns"]]
        var endpoints: [[String: Any]] = []
        var rules: [[String: Any]] = []
        let available = Set(physicalInterfaces().map(\.id))
        let userID = Int(getuid())
        var routeTags: [Route: String] = [:]
        var wireguardTags: [String: String] = [:]

        for (index, app) in apps.sorted(by: { $0.path.count > $1.path.count }).enumerated() {
            let url = URL(fileURLWithPath: app.path).resolvingSymlinksInPath()
            guard let executable = Bundle(url: url)?.executableURL?.resolvingSymlinksInPath() else {
                throw TunConfiguration.failure("Не удалось найти приложение \(app.name).")
            }
            let bundle = executable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            let pattern = "^" + NSRegularExpression.escapedPattern(for: bundle.path) + "/"
            var tag = "app-\(index)"
            if let existing = routeTags[app.route] {
                tag = existing
            } else if app.route.kind == .wireguard {
                guard let interface = app.route.interface, available.contains(interface) else {
                    throw TunConfiguration.failure("Выбранное подключение WireGuard недоступно.")
                }
                let file = URL(fileURLWithPath: app.route.target).resolvingSymlinksInPath()
                let key = file.path + "\n" + interface
                if let existing = wireguardTags[key] {
                    tag = existing
                } else {
                    let profile = try WireGuardProfile.read(file, tag: tag, interface: interface)
                    wireguardTags[key] = tag
                    endpoints.append(profile.endpoint)
                    dns.append(["type": "udp", "tag": "dns-\(tag)", "server": profile.dns, "detour": tag])
                }
            } else if app.route.kind == .vpnApp {
                let providers = vpnApplicationProviderIDs(bundleID: app.route.target).sorted()
                let dnsTag = "dns-\(tag)"
                outbounds.append(["type": "direct", "tag": tag,
                                  "bind_interface": "splitweb-vpn:" + providers.joined(separator: "|")])
                // shortcut: encrypted public DNS until the selected VPN's resolver can be tracked per connection.
                dns.append(["type": "https", "tag": dnsTag, "server": "1.1.1.1", "detour": tag,
                            "tls": ["enabled": true, "server_name": "cloudflare-dns.com"]])
            } else if app.route.kind == .amnezia {
                outbounds.append(["type": "http", "tag": tag, "server": "127.0.0.1", "server_port": 1,
                                  "bind_interface": "splitweb-amnezia"])
            } else {
                var outbound = try TunConfiguration.makeOutbound(for: app)
                outbound["tag"] = tag
                outbounds.append(outbound)
            }
            routeTags[app.route] = tag
            if app.route.kind == .wireguard || app.route.kind == .vpnApp {
                rules.append(["process_path_regex": pattern, "user_id": userID, "action": "resolve", "server": "dns-\(tag)"])
            }
            rules.append(["process_path_regex": pattern, "user_id": userID, "action": "route", "outbound": tag])
        }
        let config: [String: Any] = [
            "log": ["level": "warn"],
            "inbounds": [["type": "mixed", "listen": "127.0.0.1", "listen_port": port]],
            "outbounds": outbounds,
            "endpoints": endpoints,
            "dns": ["servers": dns, "final": "system-dns", "independent_cache": true],
            "route": ["rules": rules, "final": "system", "default_domain_resolver": "system-dns"]
        ]
        return ProxyRoutingConfiguration(data: try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]))
    }
}
