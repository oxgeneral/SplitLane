import Darwin
import Foundation

struct PacketRoutingRule: Codable, Equatable, Sendable {
    let path: String
    let blockUDP: Bool
    let relayID: UUID?
}

enum PacketRoutingConfiguration {
    static let manifest = "packet-rules.json"
    static let relayPort: UInt16 = 39879
    static let relayTag = "group-tun"
    static let ipv4 = "172.31.252.1"
    static let ipv6 = "fd9e:7345:2b1c:252::1"
    private static let webKitNetworkingPattern =
        #"/com\.apple\.WebKit\.Networking\.xpc/Contents/MacOS/com\.apple\.WebKit\.Networking$"#

    static func addressSnapshot(in interfaces: String) -> [String] {
        var name: Substring?
        var addresses = Set<String>()
        for line in interfaces.split(separator: "\n") {
            let parts = line.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 2 else { continue }
            if line.first?.isWhitespace == false {
                name = parts[0].hasSuffix(":") ? parts[0].dropLast() : nil
            } else if let name, ["inet", "inet6"].contains(parts[0]) {
                addresses.insert("\(name) \(parts[0]) \(parts[1])")
            }
        }
        return addresses.sorted()
    }

    static func liveAddressSnapshot() -> [String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let list else { return [] }
        defer { freeifaddrs(list) }
        var addresses = Set<String>()
        var next: UnsafeMutablePointer<ifaddrs>? = list
        while let item = next {
            let entry = item.pointee
            next = entry.ifa_next
            guard let address = entry.ifa_addr else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count),
                              nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let name = String(cString: entry.ifa_name)
            let familyName = family == AF_INET ? "inet" : "inet6"
            addresses.insert("\(name) \(familyName) \(String(cString: host))")
        }
        return addresses.sorted()
    }

    static func make(apps: [PacketRoutingRule]) throws -> Data {
        var outbounds: [[String: Any]] = [
            ["type": "direct", "tag": "original-scope", "bind_interface": "splitlane-original-scope"]
        ]
        var rules: [[String: Any]] = []
        for app in apps.sorted(by: { $0.path.count > $1.path.count }) {
            let pattern = "^" + NSRegularExpression.escapedPattern(for: app.path) + "/"
            if app.blockUDP {
                rules.append(["network": "udp", "process_path_regex": pattern, "action": "reject", "method": "drop"])
            }
            if let id = app.relayID?.uuidString {
                outbounds.append(["type": "socks", "tag": id, "server": "127.0.0.1", "server_port": relayPort,
                                  "version": "5", "username": id, "password": id])
                rules.append(["process_path_regex": pattern, "action": "route", "outbound": id])
            }
        }

        // An unattributed packet or unresolved WebKit Networking flow could belong to any group.
        rules.append(["type": "logical", "mode": "and", "rules": [
            ["network": "udp"], ["process_path_regex": ".+", "invert": true]
        ], "action": "reject", "method": "drop"])
        rules.append(["type": "logical", "mode": "and", "rules": [
            ["network": "tcp"], ["process_path_regex": ".+", "invert": true]
        ], "action": "reject"])
        rules.append(["network": "udp",
                      "process_path_regex": webKitNetworkingPattern,
                      "action": "reject", "method": "drop"])
        rules.append(["network": "tcp",
                      "process_path_regex": webKitNetworkingPattern,
                      "action": "reject"])

        rules.append(["action": "route", "outbound": "original-scope"])
        return try JSONSerialization.data(withJSONObject: [
            "log": ["level": "warn"],
            "inbounds": [["type": "tun", "tag": "packet-capture", "address": ["\(ipv4)/30", "\(ipv6)/126"],
                          "mtu": 1400, "stack": "gvisor", "auto_route": false, "dns_mode": "disabled"]],
            "outbounds": outbounds,
            "route": ["rules": rules, "final": "original-scope"]
        ], options: [.sortedKeys])
    }

    static func filter(owner: UInt32, interface: String?, capturesTCP: Bool) -> String {
        var rules = """
            table <splitlane_webrtc_exempt4> const { 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32 }
            table <splitlane_webrtc_exempt6> const { ::1/128, fe80::/10, ff00::/8 }
            table <splitlane_local_addresses> const { self }

            """
        for (family, peer, loopback, exempt) in [
            ("inet", "172.31.252.2", "127.0.0.1", "splitlane_webrtc_exempt4"),
            ("inet6", "fd9e:7345:2b1c:252::2", "::1", "splitlane_webrtc_exempt6")
        ] {
            guard let interface else {
                if capturesTCP {
                    rules += "block drop out quick on ! lo0 \(family) proto tcp from any to ! <\(exempt)> user = \(owner)\n"
                }
                rules += "block drop out quick on ! lo0 \(family) proto udp from any to ! <\(exempt)> user = \(owner)\n"
                continue
            }
            let redirect = "route-to (\(interface) \(peer)) \(family)"
            if capturesTCP {
                // PF re-evaluates route-to packets on the capture TUN interface.
                rules += "pass out quick on \(interface) \(family) proto tcp no state\n"
                // Loopback delivery satisfies macOS's receive-interface check across VPN and physical interfaces.
                rules += "pass in quick on \(interface) route-to (lo0 \(loopback)) \(family) proto tcp from any to <splitlane_local_addresses> no state\n"
                // Capture new TCP connections across all non-loopback interfaces (including half-route VPNs and scoped sockets).
                rules += "pass out quick on ! lo0 \(redirect) proto tcp from any to ! <\(exempt)> user = \(owner) flags S/SA keep state (if-bound)\n"
            }
            // PF evaluates route-to packets again on the TUN interface.
            rules += "pass out quick on \(interface) \(family) proto udp tagged splitlane_udp no state\n"
            rules += "pass in quick on \(interface) route-to (lo0 \(loopback)) \(family) proto udp from any to <splitlane_local_addresses> no state\n"
            rules += "pass out quick on ! lo0 \(redirect) proto udp from any to ! <\(exempt)> user = \(owner) tag splitlane_udp no state\n"
        }
        return rules
    }
}
