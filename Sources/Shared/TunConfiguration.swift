import Foundation
import Network

struct TunConfiguration: Sendable {
    static let probeAddress = "1.0.0.1"
    static let ipv4Address = "172.31.250.1"
    static let ipv6Address = "fd9e:7345:2b1c::1"
    let data: Data
    let interfaces: [String]
    let systemIPv4: String
    let systemIPv6: String?

    static func make(rules apps: [AppRule], probe: Bool = false) throws -> TunConfiguration {
        try RuleConfiguration.validateLocalUDPPolicy(apps)
        guard !apps.isEmpty else { throw failure("Сначала добавь хотя бы одно правило.") }
        guard let systemInterface = try routeInterface(arguments: probe
            ? ["-n", "get", probeAddress] : ["-n", "get", "-inet", "default"]) else {
            throw failure("Не удалось определить системный маршрут IPv4.")
        }
        let systemIPv6 = probe ? nil : try routeInterface(arguments: ["-n", "get", "-inet6", "default"])
        if !probe, DefaultNetwork.isTunnelInterface(systemInterface) ||
            systemIPv6.map(DefaultNetwork.isTunnelInterface) == true ||
            DefaultNetwork.activeVPNInterface() != nil {
            // shortcut: keep the original VPN available until full-tunnel coexistence is verified.
            throw failure("Полный режим выключен: macOS уже направляет интернет через системный VPN.")
        }
        var interfaces: Set<String> = [systemInterface]
        var outbounds: [[String: Any]] = [["type": "direct", "tag": "system", "bind_interface": systemInterface]]
        var rules: [[String: Any]] = []
        let transports = probe ? [] : try VPNTransport.active()
        for (index, transport) in transports.enumerated() {
            let tag = "vpn-transport-\(index)"
            interfaces.insert(transport.interface)
            outbounds.append(["type": "direct", "tag": tag, "bind_interface": transport.interface])
            rules.append(["process_path": transport.path, "action": "route", "outbound": tag])
        }

        for (index, app) in apps.sorted(by: { $0.path.count > $1.path.count }).enumerated() {
            let tag = "\(index + 1) \(app.name)"
            let bundlePath = try canonicalAppBundlePath(for: app.path, name: app.name)
            let pattern = "^" + NSRegularExpression.escapedPattern(for: bundlePath) + "/"
            rules.append(["process_path_regex": pattern, "action": "route", "outbound": tag])
            var outbound = try makeOutbound(for: app)
            if let interface = outbound["bind_interface"] as? String { interfaces.insert(interface) }
            outbound["tag"] = tag
            outbounds.append(outbound)
        }

        if let systemIPv6 {
            interfaces.insert(systemIPv6)
            outbounds.append(["type": "direct", "tag": "system-ipv6", "bind_interface": systemIPv6])
            rules.append(["ip_version": 6, "action": "route", "outbound": "system-ipv6"])
        } else if !probe {
            rules.append(["ip_version": 6, "action": "reject"])
        }

        let addresses = probe ? ["\(ipv4Address)/30"] : ["\(ipv4Address)/30", "\(ipv6Address)/126"]
        let routes = probe ? ["\(probeAddress)/32"] : ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
        let reserved = probe ? [] : ["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
                                        "::1/128", "fe80::/10", "ff00::/8"]
        let exclusions = Set(reserved + transports.flatMap(\.excludedRoutes)).sorted()
        let config: [String: Any] = [
            "log": ["level": probe ? "info" : "warn"],
            "inbounds": [["type": "tun", "tag": "splitweb-tun", "address": addresses, "mtu": 1400,
                          "auto_route": true, "route_address": routes, "route_exclude_address": exclusions,
                          "dns_mode": "disabled", "stack": "gvisor"]],
            "outbounds": outbounds,
            "dns": ["servers": [["type": "local", "tag": "system-dns"]], "final": "system-dns"],
            "route": ["rules": rules, "final": "system", "default_interface": systemInterface,
                      "default_domain_resolver": "system-dns"]
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
        return TunConfiguration(data: data, interfaces: interfaces.sorted(),
                                systemIPv4: systemInterface, systemIPv6: systemIPv6)
    }

    static func makeOutbound(for app: AppRule) throws -> [String: Any] {
        let route = app.route
        switch route.kind {
        case .amnezia:
            throw failure("Отдельный выход AmneziaVPN доступен в локальной сборке.")
        case .wireguard:
            throw failure("Отдельный WireGuard доступен в режиме совместной работы с VPN.")
        case .direct, .vpn, .vpnApp:
            let interface: String?
            switch route.kind {
            case .direct: interface = route.target
            case .vpnApp: interface = vpnApplicationInterface(bundleID: route.target)
            default: interface = vpnInterface(profileID: route.target)
            }
            guard let interface, if_nametoindex(interface) != 0 else {
                throw failure("Маршрут для \(app.name) сейчас недоступен.")
            }
            return ["type": "direct", "bind_interface": interface]
        case .socks5, .http, .https:
            guard case .hostPort(let host, let port)? = route.proxyEndpoint else {
                throw failure("Проверь адрес и порт прокси для \(app.name).")
            }
            let server = host.debugDescription
            var outbound: [String: Any] = [
                "type": route.kind == .socks5 ? "socks" : "http",
                "server": server,
                "server_port": port.rawValue
            ]
            if route.kind == .socks5 { outbound["version"] = "5" }
            if route.kind == .https { outbound["tls"] = ["enabled": true] }
            if ["127.0.0.1", "::1", "localhost"].contains(server) { outbound["bind_interface"] = "lo0" }
            if let id = route.proxyCredentialID {
                let credentials = try ProxyCredentials.load(id)
                guard credentials.isValid(for: route.kind) else {
                    throw failure("Проверь логин и пароль прокси для \(app.name).")
                }
                outbound["username"] = credentials.username
                outbound["password"] = credentials.password
            }
            return outbound
        }
    }

    private static func routeInterface(arguments: [String]) throws -> String? {
        let text = try runCommand("/sbin/route", arguments)
        guard let row = text.split(whereSeparator: \.isNewline).first(where: { $0.contains("interface:") }),
              let name = row.split(whereSeparator: \.isWhitespace).last,
              if_nametoindex(String(name)) != 0 else { return nil }
        return String(name)
    }

    static func failure(_ description: String) -> NSError {
        NSError(domain: "SplitWebOnMac.TUN", code: 1, userInfo: [NSLocalizedDescriptionKey: description])
    }
}
