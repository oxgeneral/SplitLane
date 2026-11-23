import Darwin
import Foundation
import SystemConfiguration

struct DynamicStoreServiceInfo: Equatable, Sendable {
    let id: String
    let name: String
    let interface: String
    let isVPN: Bool
}

enum DefaultNetwork {
    private static let ipv4Probes = ["1.0.0.1", "9.9.9.9", "208.67.222.222", "198.41.0.4"]
    private static let ipv6Probes = ["2606:4700:4700::1111", "2620:fe::fe", "2001:4860:4860::8888"]
    private static let tunnelPrefixes = ["utun", "ppp", "ipsec", "tun"]

    static func isTunnelInterface(_ name: String) -> Bool {
        tunnelPrefixes.contains { name.hasPrefix($0) }
    }

    static func splitWebCaptureInterfaces() -> Set<String> {
        let reserved: Set<String> = [
            TunConfiguration.ipv4Address,
            TunConfiguration.ipv6Address,
            PacketRoutingConfiguration.ipv4,
            PacketRoutingConfiguration.ipv6
        ]
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let list else { return [] }
        defer { freeifaddrs(list) }
        var result: Set<String> = []
        var next: UnsafeMutablePointer<ifaddrs>? = list
        while let item = next {
            let entry = item.pointee
            next = entry.ifa_next
            let name = String(cString: entry.ifa_name)
            guard name.hasPrefix("utun"), let address = entry.ifa_addr,
                  [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family)) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count),
                           nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(String(cString: host).prefix { $0 != "%" })
                if reserved.contains(ip) {
                    result.insert(name)
                }
            }
        }
        return result
    }

    static func selectDominantInterface(from probeResults: [String?], fallback: String?,
                                        excluded: Set<String> = []) -> String? {
        func usable(_ candidate: String?) -> String? {
            guard let candidate, !candidate.isEmpty, candidate != "lo0", !excluded.contains(candidate) else { return nil }
            return candidate
        }
        var counts: [String: Int] = [:]
        var order: [String] = []
        for candidate in probeResults.compactMap(usable) {
            if counts[candidate] == nil { order.append(candidate) }
            counts[candidate, default: 0] += 1
        }
        if let best = order.max(by: { counts[$0, default: 0] < counts[$1, default: 0] }) {
            let bestCount = counts[best, default: 0]
            if bestCount >= 2 || counts.count == 1 {
                return best
            }
            if let fallback = usable(fallback), counts[fallback] == bestCount {
                return fallback
            }
            return best
        }
        return usable(fallback)
    }

    static func currentInterface(family: String = "-inet",
                                 excludedInterfaces: Set<String> = splitWebCaptureInterfaces()) -> String? {
        let probes = family == "-inet6" ? ipv6Probes : ipv4Probes
        let results = probes.map { routeInterface(arguments: ["-n", "get", family, $0]) }
        let fallback = routeInterface(arguments: ["-n", "get", family, "default"])
        return selectDominantInterface(from: results, fallback: fallback, excluded: excludedInterfaces)
    }

    static func activeVPNInterface(excludedInterfaces: Set<String> = splitWebCaptureInterfaces()) -> String? {
        for family in ["-inet", "-inet6"] {
            if let iface = currentInterface(family: family, excludedInterfaces: excludedInterfaces),
               isTunnelInterface(iface) {
                return iface
            }
        }
        return nil
    }

    static func describeCurrent(interfaces: [NetworkChoice], vpns: [NetworkChoice], vpnApps: [NetworkChoice],
                                profileInterfaces: [String: String], appInterfaces: [String: Set<String>]) -> String? {
        let excluded = splitWebCaptureInterfaces()
        let systemInterface = currentInterface(family: "-inet", excludedInterfaces: excluded)
            ?? currentInterface(family: "-inet6", excludedInterfaces: excluded)
        let dynamicServices = activeDynamicStoreServices()
        let tunnelOwner: String?
        if let systemInterface, isTunnelInterface(systemInterface) {
            let lines = (try? runCommand("/bin/ps", ["-axo", "args="]))?
                .split(whereSeparator: \.isNewline).map(String.init) ?? []
            tunnelOwner = detectTunnelOwner(interface: systemInterface, processLines: lines)
        } else {
            tunnelOwner = nil
        }
        let foreignProxy = foreignSystemProxyDescription()
        return resolveDescription(interface: systemInterface, interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
                                  profileInterfaces: profileInterfaces, appInterfaces: appInterfaces,
                                  dynamicServices: dynamicServices, tunnelOwner: tunnelOwner,
                                  foreignProxy: foreignProxy)
    }

    static func resolveDescription(interface systemInterface: String?,
                                   interfaces: [NetworkChoice],
                                   vpns: [NetworkChoice],
                                   vpnApps: [NetworkChoice],
                                   profileInterfaces: [String: String],
                                   appInterfaces: [String: Set<String>],
                                   dynamicServices: [DynamicStoreServiceInfo],
                                   tunnelOwner: String?,
                                   foreignProxy: String?) -> String? {
        let base: String?
        if let systemInterface {
            if let app = vpnApps.first(where: { appInterfaces[$0.id]?.contains(systemInterface) == true }) {
                base = "VPN \(app.name)"
            } else if let profile = vpns.first(where: { profileInterfaces[$0.id] == systemInterface }) {
                base = "VPN \(profile.name)"
            } else if let service = dynamicServices.first(where: { $0.interface == systemInterface }) {
                if service.isVPN {
                    base = service.name.hasPrefix("VPN ") ? service.name : "VPN \(service.name)"
                } else {
                    base = "\(service.name) (\(systemInterface))"
                }
            } else if let physical = interfaces.first(where: { $0.id == systemInterface }) {
                base = physical.name
            } else if isTunnelInterface(systemInterface) {
                base = tunnelOwner.map { "VPN \($0) (\(systemInterface))" } ?? "VPN (\(systemInterface))"
            } else {
                base = systemInterface
            }
        } else {
            base = nil
        }

        if let foreignProxy {
            return base.map { "\($0) · \(foreignProxy)" } ?? foreignProxy
        }
        return base
    }

    static func detectTunnelOwner(interface: String, processLines: [String]) -> String? {
        guard !interface.isEmpty else { return nil }
        let knownBinaries: [(token: String, name: String)] = [
            ("amneziawg-go", "AmneziaVPN"),
            ("AmneziaVPN", "AmneziaVPN"),
            ("tailscaled", "Tailscale"),
            ("wireguard-go", "WireGuard"),
            ("openvpn", "OpenVPN"),
            ("mihomo", "Clash"),
            ("clash", "Clash"),
            ("warp-svc", "Cloudflare WARP"),
            ("mullvad-daemon", "Mullvad"),
            ("sing-box", "sing-box"),
            ("tun2socks", "VPN")
        ]
        for line in processLines {
            guard mentionsInterface(line, interface: interface) else { continue }
            if let appName = appName(inCommandLine: line) {
                return appName
            }
            for entry in knownBinaries where line.localizedCaseInsensitiveContains(entry.token) {
                return entry.name
            }
        }
        return nil
    }

    static func foreignProxyDescription(from proxies: [String: Any], ownPort: UInt16 = ProxyOverlaySettings.port) -> String? {
        if ProxyOverlaySettings.isLocalProxy(proxies, port: ownPort) {
            return nil
        }
        if (proxies["ProxyAutoConfigEnable"] as? Int ?? 0) != 0 {
            return "прокси PAC"
        }
        if (proxies["ProxyAutoDiscoveryEnable"] as? Int ?? 0) != 0 {
            return "автопрокси WPAD"
        }
        for (enableKey, hostKey, portKey, label) in [
            ("SOCKSEnable", "SOCKSProxy", "SOCKSPort", "SOCKS"),
            ("HTTPSEnable", "HTTPSProxy", "HTTPSPort", "HTTPS"),
            ("HTTPEnable", "HTTPProxy", "HTTPPort", "HTTP")
        ] {
            guard (proxies[enableKey] as? Int ?? 0) != 0,
                  let host = proxies[hostKey] as? String, !host.isEmpty else { continue }
            if let port = proxies[portKey] as? Int, port > 0 {
                return "прокси \(label) \(host):\(port)"
            }
            return "прокси \(label) \(host)"
        }
        return nil
    }

    private static func foreignSystemProxyDescription() -> String? {
        guard let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return nil }
        return foreignProxyDescription(from: proxies)
    }

    private static func activeDynamicStoreServices() -> [DynamicStoreServiceInfo] {
        guard let store = SCDynamicStoreCreate(nil, "SplitWebOnMac.default" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/(IPv4|IPv6)" as CFString) as? [String]
        else { return [] }
        var seen: Set<String> = []
        var result: [DynamicStoreServiceInfo] = []
        for key in keys {
            let parts = key.split(separator: "/")
            guard parts.count == 5 else { continue }
            let id = String(parts[3])
            guard !seen.contains(id),
                  let state = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  let iface = state["InterfaceName"] as? String, !iface.isEmpty else { continue }
            seen.insert(id)
            let setupService = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(id)" as CFString) as? [String: Any]
            let setupInterface = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(id)/Interface" as CFString) as? [String: Any]
            let type = setupInterface?["Type"] as? String ?? ""
            let hasVPNState = SCDynamicStoreCopyValue(store, "State:/Network/Service/\(id)/VPN" as CFString) != nil
                || SCDynamicStoreCopyValue(store, "State:/Network/Service/\(id)/PPP" as CFString) != nil
                || SCDynamicStoreCopyValue(store, "State:/Network/Service/\(id)/IPSec" as CFString) != nil
            let isVPN = ["VPN", "PPP", "IPSec"].contains(type) || hasVPNState || isTunnelInterface(iface)
            let name = (setupService?["UserDefinedName"] as? String)
                ?? (setupInterface?["UserDefinedName"] as? String)
                ?? ""
            guard !name.isEmpty else { continue }
            result.append(DynamicStoreServiceInfo(id: id, name: name, interface: iface, isVPN: isVPN))
        }
        return result
    }

    private static func mentionsInterface(_ line: String, interface: String) -> Bool {
        let escaped = NSRegularExpression.escapedPattern(for: interface)
        let pattern = "(^|[^A-Za-z0-9_.-])\(escaped)([^A-Za-z0-9_.-]|$)"
        return line.range(of: pattern, options: .regularExpression) != nil
    }

    private static func appName(inCommandLine line: String) -> String? {
        guard let range = line.range(of: ".app/") else { return nil }
        let prefix = line[..<range.lowerBound]
        guard let slash = prefix.lastIndex(of: "/") else { return nil }
        let name = String(prefix[prefix.index(after: slash)...]).trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? nil : name
    }

    private static func routeInterface(arguments: [String]) -> String? {
        guard let text = try? runCommand("/sbin/route", arguments),
              let row = text.split(whereSeparator: \.isNewline).first(where: { $0.contains("interface:") }),
              let name = row.split(whereSeparator: \.isWhitespace).last,
              if_nametoindex(String(name)) != 0 else { return nil }
        return String(name)
    }
}
