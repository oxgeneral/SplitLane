import Foundation
import Network

struct WireGuardProfile {
    let endpoint: [String: Any]
    let dns: String

    init(contents: String, tag: String, interface: String) throws {
        var sections: [[String: String]] = []
        for line in contents.split(whereSeparator: \.isNewline) {
            let text = line.prefix { $0 != "#" && $0 != ";" }.trimmingCharacters(in: .whitespaces)
            if text.isEmpty { continue }
            if text.lowercased() == "[interface]", sections.isEmpty {
                sections.append([:])
            } else if text.lowercased() == "[peer]", sections.count == 1 {
                sections.append([:])
            } else {
                let parts = text.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard parts.count == 2, !sections.isEmpty else { throw Self.invalid }
                let key = parts[0].lowercased()
                guard sections[sections.count - 1].updateValue(parts[1], forKey: key) == nil else { throw Self.invalid }
            }
        }
        guard sections.count == 2 else { throw Self.invalid }
        let local = sections[0]
        let peer = sections[1]
        let addresses = Self.list(local["address"])
        let allowed = Self.list(peer["allowedips"])
        guard Set(local.keys).isSubset(of: ["address", "privatekey", "dns", "mtu"]),
              Set(peer.keys).isSubset(of: ["publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"]),
              !addresses.isEmpty, addresses.allSatisfy(Self.isCIDR),
              !allowed.isEmpty, allowed.allSatisfy(Self.isCIDR),
              let privateKey = Self.key(local["privatekey"]), let publicKey = Self.key(peer["publickey"]),
              let server = peer["endpoint"], let colon = server.lastIndex(of: ":"),
              let port = UInt16(server[server.index(after: colon)...]), port > 0 else { throw Self.invalid }
        let host = server[..<colon].trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let serverRoute = Route(kind: .socks5, target: host, port: String(port))
        guard serverRoute.proxyEndpoint != nil else { throw Self.invalid }

        var peerConfig: [String: Any] = ["address": host, "port": port, "public_key": publicKey, "allowed_ips": allowed]
        if let psk = peer["presharedkey"] {
            guard let key = Self.key(psk) else { throw Self.invalid }
            peerConfig["pre_shared_key"] = key
        }
        if let interval = peer["persistentkeepalive"], interval.lowercased() != "off" {
            guard let seconds = UInt16(interval) else { throw Self.invalid }
            peerConfig["persistent_keepalive_interval"] = seconds
        }

        let dnsServers = Self.list(local["dns"])
        guard dnsServers.allSatisfy(Self.isIP) else { throw Self.invalid }
        dns = dnsServers.first ?? "1.1.1.1"
        var config: [String: Any] = ["type": "wireguard", "tag": tag, "system": false, "address": addresses,
                                     "private_key": privateKey, "peers": [peerConfig],
                                     "bind_interface": interface, "domain_resolver": "system-dns"]
        if let value = local["mtu"] {
            guard let mtu = UInt16(value), mtu >= 576, mtu <= 9000 else { throw Self.invalid }
            config["mtu"] = mtu
        }
        endpoint = config
    }

    static func read(_ url: URL, tag: String, interface: String) throws -> WireGuardProfile {
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        guard let data = try file.read(upToCount: 65_537), data.count <= 65_536,
              let contents = String(data: data, encoding: .utf8) else { throw invalid }
        return try WireGuardProfile(contents: contents, tag: tag, interface: interface)
    }

    private static var invalid: NSError {
        TunConfiguration.failure("Нужен WireGuard .conf с одним [Peer], адресом, ключами и Endpoint. Дополнительные скрипты и системные параметры не поддерживаются.")
    }

    private static func list(_ value: String?) -> [String] {
        (value ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private static func key(_ value: String?) -> String? {
        guard let value, Data(base64Encoded: value)?.count == 32 else { return nil }
        return value
    }

    private static func isIP(_ value: String) -> Bool {
        IPv4Address(value) != nil || IPv6Address(value) != nil
    }

    private static func isCIDR(_ value: String) -> Bool {
        let fields = value.split(separator: "/")
        guard fields.count == 2, let prefix = UInt8(fields[1]) else { return false }
        let ip = String(fields[0])
        return (IPv4Address(ip) != nil && prefix <= 32) || (IPv6Address(ip) != nil && prefix <= 128)
    }
}
