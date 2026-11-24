import Foundation
import Network
import SystemConfiguration

struct VPNTransport {
    let path: String
    let interface: String
    let excludedRoutes: [String]

    static func active() throws -> [VPNTransport] {
        guard let preferences = SCPreferencesCreate(nil, "SplitLane" as CFString, nil),
              let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] else { return [] }
        let profileIDs = Set(vpnProfiles().map(\.id))
        let active = services.compactMap { service -> (SCNetworkInterface, String, [String: Any])? in
            guard let id = SCNetworkServiceGetServiceID(service), profileIDs.contains(id as String),
                  let connection = SCNetworkConnectionCreateWithServiceID(nil, id, nil, nil),
                  SCNetworkConnectionGetStatus(connection) == .connected,
                  let interface = SCNetworkServiceGetInterface(service) else { return nil }
            let name = SCNetworkServiceGetName(service) as String? ?? "VPN"
            let status = SCNetworkConnectionCopyExtendedStatus(connection) as? [String: Any] ?? [:]
            return (interface, name, status)
        }
        guard !active.isEmpty else { return [] }

        let physical = physicalAddresses()
        let processes = try runCommand("/bin/ps", ["-axo", "pid=,comm="]).split(whereSeparator: \.isNewline)
        return try active.map { interface, name, status in
            let config = SCNetworkInterfaceGetConfiguration(interface) as? [String: Any]
            let provider = config?["NEProviderBundleIdentifier"] as? String
            let transports = try processes.compactMap { row -> VPNTransport? in
                let fields = row.split(maxSplits: 1, whereSeparator: \.isWhitespace)
                guard fields.count == 2, Int32(fields[0]) != nil,
                      let provider, fields[1].contains(".appex/Contents/MacOS/") ||
                        fields[1].contains(".systemextension/Contents/MacOS/") else { return nil }
                let file = URL(fileURLWithPath: String(fields[1])).resolvingSymlinksInPath()
                let bundle = file.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                guard Bundle(url: bundle)?.bundleIdentifier == provider else { return nil }

                let names = try runCommand("/usr/sbin/lsof", ["-nP", "-a", "-p", String(fields[0]), "-i", "-Fn"])
                var peers = Set<String>()
                var interfaces = Set<String>()
                for line in names.split(whereSeparator: \.isNewline) where line.hasPrefix("n") {
                    let socket = line.dropFirst().components(separatedBy: "->")
                    guard socket.count == 2, let local = socketAddress(socket[0]),
                          let iface = physical[local], let remote = socketAddress(socket[1]) else { continue }
                    interfaces.insert(iface)
                    peers.insert(remote + (remote.contains(":") ? "/128" : "/32"))
                }
                guard interfaces.count == 1, let physical = interfaces.first, !peers.isEmpty else { return nil }
                return VPNTransport(path: file.path, interface: physical,
                                    excludedRoutes: Array(peers.union(systemExclusions(status))).sorted())
            }
            guard transports.count == 1, let transport = transports.first else {
                throw TunConfiguration.failure("Не удалось определить служебное соединение VPN \(name). Правила выключены.")
            }
            return transport
        }
    }

    static func socketAddress(_ endpoint: String) -> String? {
        guard let end = endpoint.lastIndex(of: ":") else { return nil }
        let host = endpoint[..<end].trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return normalizedIP(host)
    }

    private static func normalizedIP(_ host: String) -> String? {
        let address = String(host.prefix { $0 != "%" })
        return IPv4Address(address)?.debugDescription ?? IPv6Address(address)?.debugDescription
    }

    private static func systemExclusions(_ status: [String: Any]) -> [String] {
        ["IPv4", "IPv6"].flatMap { family -> [String] in
            let config = status[family] as? [String: Any]
            let excluded = config?["ExcludedRoutes"] as? [[String: Any]] ?? []
            return excluded.compactMap { route in
                guard let destination = route["DestinationAddress"] as? String,
                      let address = normalizedIP(destination) else { return nil }
                if let mask = route["SubnetMask"] as? String, let bits = subnetPrefix(mask), bits > 0 {
                    return "\(address)/\(bits)"
                }
                if let bits = route["PrefixLength"] as? Int, (1...128).contains(bits) {
                    return "\(address)/\(bits)"
                }
                return nil
            }
        }
    }

    static func subnetPrefix(_ mask: String) -> Int? {
        guard let address = IPv4Address(mask) else { return nil }
        let inverse = ~address.rawValue.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard inverse & (inverse &+ 1) == 0 else { return nil }
        return inverse.leadingZeroBitCount
    }

    private static func physicalAddresses() -> [String: String] {
        let names = Set(physicalInterfaces().map(\.id))
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let list else { return [:] }
        defer { freeifaddrs(list) }
        var result: [String: String] = [:]
        var next: UnsafeMutablePointer<ifaddrs>? = list
        while let item = next {
            let entry = item.pointee
            next = entry.ifa_next
            let name = String(cString: entry.ifa_name)
            guard names.contains(name), let address = entry.ifa_addr,
                  [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family)) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count),
                           nil, 0, NI_NUMERICHOST) == 0, let ip = normalizedIP(String(cString: host)) {
                result[ip] = name
            }
        }
        return result
    }
}

func runCommand(_ executable: String, _ arguments: [String]) throws -> String {
    try autoreleasepool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        defer {
            try? output.fileHandleForReading.close()
            try? output.fileHandleForWriting.close()
        }
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return process.terminationStatus == 0 ? String(decoding: data, as: UTF8.self) : ""
    }
}
