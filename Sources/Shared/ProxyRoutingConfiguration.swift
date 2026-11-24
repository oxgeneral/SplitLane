import Foundation

struct ProxyRoutingConfiguration: Sendable {
    static let port = ProxyOverlaySettings.port
    static let proxyTag = "system-proxy"
    private static let webKitNetworkingPattern =
        #"/com\.apple\.WebKit\.Networking\.xpc/Contents/MacOS/com\.apple\.WebKit\.Networking$"#
    let data: Data
    let packetRules: [PacketRoutingRule]

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
        var packetRules: [PacketRoutingRule] = []
        var relayUsers: [[String: String]] = []

        for (index, app) in apps.sorted(by: { $0.path.count > $1.path.count }).enumerated() {
            let path = try canonicalAppBundlePath(for: app.path, name: app.name)
            let pattern = "^" + NSRegularExpression.escapedPattern(for: path) + "/"
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
            } else if app.route.kind == .vpn {
                outbounds.append(["type": "direct", "tag": tag, "bind_interface": "splitlane-vpn-service:" + app.route.target])
                dns.append(["type": "https", "tag": "dns-\(tag)", "server": "1.1.1.1", "detour": tag,
                            "tls": ["enabled": true, "server_name": "cloudflare-dns.com"]])
            } else if app.route.kind == .vpnApp {
                let providers = vpnApplicationProviderIDs(bundleID: app.route.target).sorted()
                let dnsTag = "dns-\(tag)"
                outbounds.append(["type": "direct", "tag": tag,
                                  "bind_interface": "splitlane-vpn:" + providers.joined(separator: "|")])
                // shortcut: encrypted public DNS until the selected VPN's resolver can be tracked per connection.
                dns.append(["type": "https", "tag": dnsTag, "server": "1.1.1.1", "detour": tag,
                            "tls": ["enabled": true, "server_name": "cloudflare-dns.com"]])
            } else if app.route.kind == .amnezia {
                outbounds.append(["type": "http", "tag": tag, "server": "127.0.0.1", "server_port": 1,
                                  "bind_interface": "splitlane-amnezia"])
            } else {
                var outbound = try TunConfiguration.makeOutbound(for: app)
                outbound["tag"] = tag
                outbounds.append(outbound)
                if app.route.kind == .direct {
                    dns.append(["type": "local", "tag": "dns-\(tag)", "bind_interface": app.route.target,
                                "udp_fragment": true])
                }
            }
            routeTags[app.route] = tag
            if app.usesTUNInProxyMode {
                let relayID = UUID()
                let user = relayID.uuidString
                relayUsers.append(["username": user, "password": user])
                packetRules.append(PacketRoutingRule(path: path, blockUDP: app.blocksUDPInProxyMode, relayID: relayID))
                rules.append(["inbound": PacketRoutingConfiguration.relayTag, "auth_user": user,
                              "action": "route", "outbound": tag])
            } else if app.blocksUDPInProxyMode {
                packetRules.append(PacketRoutingRule(path: path, blockUDP: true, relayID: nil))
            }
            if [.wireguard, .vpnApp, .vpn, .direct].contains(app.route.kind) {
                rules.append(["inbound": proxyTag, "process_path_regex": pattern, "user_id": userID,
                              "action": "resolve", "server": "dns-\(tag)"])
            }
            rules.append(["inbound": proxyTag, "process_path_regex": pattern, "user_id": userID,
                          "action": "route", "outbound": tag])
        }
        // Fail closed on the local system proxy when process attribution is missing or unresolved WebKit.
        rules.append(["type": "logical", "mode": "and", "rules": [
            ["inbound": proxyTag], ["process_path_regex": ".+", "invert": true]
        ], "action": "reject"])
        rules.append(["inbound": proxyTag, "user_id": userID,
                      "process_path_regex": webKitNetworkingPattern, "action": "reject"])

        var inbounds: [[String: Any]] = [["type": "mixed", "tag": proxyTag, "listen": "127.0.0.1", "listen_port": port]]
        if !relayUsers.isEmpty {
            inbounds.append(["type": "socks", "tag": PacketRoutingConfiguration.relayTag,
                             "listen": "127.0.0.1", "listen_port": PacketRoutingConfiguration.relayPort,
                             "users": relayUsers])
            rules.append(["inbound": PacketRoutingConfiguration.relayTag, "action": "reject"])
        }
        let config: [String: Any] = [
            "log": ["level": "warn"],
            "inbounds": inbounds,
            "outbounds": outbounds,
            "endpoints": endpoints,
            "dns": ["servers": dns, "final": "system-dns"],
            "route": ["rules": rules, "final": "system", "default_domain_resolver": "system-dns"]
        ]
        return ProxyRoutingConfiguration(data: try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]),
                                         packetRules: packetRules)
    }
}
