import AppKit
import Foundation
import Network
import SystemConfiguration

enum RouteKind: String, Codable, CaseIterable, Identifiable, Sendable {
    case direct, vpn, vpnApp, amnezia, wireguard, socks5, http, https

    var id: Self { self }
    var isProxy: Bool { self == .socks5 || self == .http || self == .https }
    var title: String {
        switch self {
        case .direct: "Напрямую"
        case .vpn: "Активный VPN macOS"
        case .vpnApp: "Приложение VPN"
        case .amnezia: "AmneziaVPN"
        case .wireguard: "Отдельный WireGuard"
        case .socks5: "SOCKS5"
        case .http: "HTTP CONNECT"
        case .https: "HTTPS CONNECT"
        }
    }
}

struct Route: Codable, Hashable, Sendable {
    var kind: RouteKind = .direct
    var target = ""
    var port = ""
    var interface: String?
    var proxyCredentialID: UUID?

    var proxyEndpoint: NWEndpoint? {
        let host = target.trimmingCharacters(in: .whitespacesAndNewlines)
        let address = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        let validName = !address.isEmpty && address.utf8.count <= 253 &&
            address.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) ||
                (97...122).contains($0) || $0 == 45 || $0 == 46 }
        guard validName || IPv6Address(address) != nil,
              let number = UInt16(port), number > 0,
              let endpointPort = NWEndpoint.Port(rawValue: number) else { return nil }
        return .hostPort(host: NWEndpoint.Host(address), port: endpointPort)
    }

    var isValid: Bool {
        guard proxyCredentialID == nil || kind.isProxy else { return false }
        switch kind {
        case .direct, .vpn, .vpnApp: return !target.isEmpty
        case .amnezia: return target.isEmpty && port.isEmpty && interface == nil
        case .wireguard: return target.hasPrefix("/") && !(interface ?? "").isEmpty
        case .socks5, .http, .https: return proxyEndpoint != nil
        }
    }
}

struct AppRule: Identifiable, Codable, Equatable, Sendable {
    var id: String { path }
    let name: String
    let path: String
    let signingID: String
    var route = Route()
    var blockUDP: Bool?
    var useTUN: Bool?

    // Older signed configurations blocked UDP for every assigned app.
    var blocksUDPInExtension: Bool { blockUDP != false }
    // Proxy mode enables full isolation (TUN + WebRTC/UDP blocking) unless explicitly opted out.
    var blocksUDPInProxyMode: Bool { blockUDP != false }
    var usesTUNInProxyMode: Bool { useTUN != false }

    static func match(signingID: String, executablePath: String?, rules: [AppRule]) -> AppRule? {
        if let executablePath {
            return rules.filter { executablePath == $0.path || executablePath.hasPrefix($0.path + "/") }
                .max { $0.path.count < $1.path.count }
        }
        return rules.first { $0.signingID == signingID }
    }
}

struct NetworkChoice: Identifiable, Equatable, Sendable {
    let id: String
    let name: String
}

func physicalInterfaces() -> [NetworkChoice] {
    (SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] ?? []).compactMap { interface in
        guard let type = SCNetworkInterfaceGetInterfaceType(interface),
              [kSCNetworkInterfaceTypeIEEE80211, kSCNetworkInterfaceTypeEthernet].contains(type),
              let id = SCNetworkInterfaceGetBSDName(interface) as String? else { return nil }
        let name = SCNetworkInterfaceGetLocalizedDisplayName(interface) as String? ?? id
        return NetworkChoice(id: id, name: "\(name) (\(id))")
    }
}

func vpnProfiles() -> [NetworkChoice] {
    vpnServices().map(\.choice).sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
}

private func vpnServices() -> [(choice: NetworkChoice, provider: String?)] {
    guard let preferences = SCPreferencesCreate(nil, "SplitWebOnMac" as CFString, nil),
          let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] else { return [] }
    let vpnTypes = ["VPN" as CFString, kSCNetworkInterfaceTypePPP, kSCNetworkInterfaceTypeIPSec]
    return services.compactMap { service in
        guard let interface = SCNetworkServiceGetInterface(service),
              let type = SCNetworkInterfaceGetInterfaceType(interface),
              vpnTypes.contains(type),
              let id = SCNetworkServiceGetServiceID(service),
              let connection = SCNetworkConnectionCreateWithServiceID(nil, id, nil, nil),
              SCNetworkConnectionGetStatus(connection) != .invalid else { return nil }
        let settings = SCNetworkInterfaceGetConfiguration(interface) as? [String: Any]
        let choice = NetworkChoice(id: id as String, name: SCNetworkServiceGetName(service) as String? ?? id as String)
        return (choice, settings?["NEProviderBundleIdentifier"] as? String)
    }
}

func vpnApplications() -> [NetworkChoice] {
    Set(vpnServices().compactMap(\.provider)).reduce(into: [String: NetworkChoice]()) { applications, provider in
        var candidate = provider
        while let separator = candidate.lastIndex(of: ".") {
            candidate = String(candidate[..<separator])
            guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: candidate),
                  vpnProviders(in: url).contains(provider) else { continue }
            let name = FileManager.default.displayName(atPath: url.path)
            applications[candidate] = NetworkChoice(id: candidate, name: name.hasSuffix(".app") ? String(name.dropLast(4)) : name)
            break
        }
    }.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
}

func vpnApplicationProviderIDs(bundleID: String) -> Set<String> {
    guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { return [] }
    return vpnProviders(in: url)
}

private func vpnProviders(in url: URL) -> Set<String> {
    let folders = ["Contents/PlugIns", "Contents/Library/SystemExtensions", "WrappedBundle/PlugIns"]
    return Set(folders.flatMap { folder in
        let contents = try? FileManager.default.contentsOfDirectory(at: url.appendingPathComponent(folder),
                                                                    includingPropertiesForKeys: nil)
        return (contents ?? []).compactMap { plugIn -> String? in
            guard ["appex", "systemextension"].contains(plugIn.pathExtension) else { return nil }
            return Bundle(url: plugIn)?.bundleIdentifier
        }
    })
}

func vpnApplicationInterfaces(bundleID: String) -> Set<String> {
    let providers = vpnApplicationProviderIDs(bundleID: bundleID)
    guard !providers.isEmpty else { return [] }
    return Set(vpnServices().compactMap { service -> String? in
        guard let provider = service.provider, providers.contains(provider) else { return nil }
        return vpnInterface(profileID: service.choice.id)
    })
}

func vpnApplicationInterface(bundleID: String) -> String? {
    let interfaces = vpnApplicationInterfaces(bundleID: bundleID)
    return interfaces.count == 1 ? interfaces.first : nil
}

func canonicalAppBundlePath(for path: String, name: String) throws -> String {
    let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
    guard Bundle(url: url)?.executableURL != nil else {
        throw TunConfiguration.failure("Не удалось найти приложение \(name).")
    }
    let resolved = url.withUnsafeFileSystemRepresentation { fileSystemPath -> String in
        guard let fileSystemPath, let real = realpath(fileSystemPath, nil) else { return url.path }
        defer { free(real) }
        return String(cString: real)
    }
    guard resolved.hasPrefix("/"), resolved.hasSuffix(".app") else {
        throw TunConfiguration.failure("Не удалось определить пакет приложения \(name).")
    }
    return resolved
}

func vpnInterface(profileID: String) -> String? {
    guard let connection = SCNetworkConnectionCreateWithServiceID(nil, profileID as CFString, nil, nil),
          SCNetworkConnectionGetStatus(connection) == .connected,
          let status = SCNetworkConnectionCopyExtendedStatus(connection) as? [String: Any] else { return nil }

    // shortcut: VPN clients without an interface in SystemConfiguration need their own integration.
    for key in ["IPv4", "IPv6", "VPN"] {
        if let interface = (status[key] as? [String: Any])?["InterfaceName"] as? String,
           !interface.isEmpty {
            return interface
        }
    }
    return nil
}

func tcpParameters(for route: Route, interfaces: [NWInterface]) -> NWParameters? {
    let parameters = NWParameters.tcp
    switch route.kind {
    case .wireguard, .amnezia:
        return nil
    case .direct, .vpn, .vpnApp:
        let interfaceName: String?
        switch route.kind {
        case .direct: interfaceName = route.target
        case .vpnApp: interfaceName = vpnApplicationInterface(bundleID: route.target)
        default: interfaceName = vpnInterface(profileID: route.target)
        }
        guard let interface = interfaces.first(where: { $0.name == interfaceName }) else { return nil }
        if route.kind == .direct, interface.type != .wifi && interface.type != .wiredEthernet { return nil }
        parameters.requiredInterface = interface
    case .socks5, .http, .https:
        guard route.proxyCredentialID == nil, let endpoint = route.proxyEndpoint else { return nil }
        var proxy: ProxyConfiguration
        if route.kind == .socks5 {
            proxy = ProxyConfiguration(socksv5Proxy: endpoint)
        } else {
            let tls = route.kind == .https ? NWProtocolTLS.Options() : nil
            proxy = ProxyConfiguration(httpCONNECTProxy: endpoint, tlsOptions: tls)
        }
        proxy.allowFailover = false
        let context = NWParameters.PrivacyContext(description: "SplitWebOnMac")
        context.proxyConfigurations = [proxy]
        parameters.setPrivacyContext(context)
    }
    return parameters
}

enum RuleConfiguration {
    static let key = "rules"
    static let defaultsKey = "appRules"

    static func validateLocalUDPPolicy(_ rules: [AppRule]) throws {
        if let app = rules.first(where: { $0.blockUDP == true }) {
            throw TunConfiguration.failure("Блокировка UDP для «\(app.name)» требует сборки с сетевым расширением.")
        }
    }

    static func encode(_ rules: [AppRule]) throws -> Data {
        try validate(rules)
        return try JSONEncoder().encode(rules)
    }

    static func decode(_ data: Data) throws -> [AppRule] {
        let rules = try JSONDecoder().decode([AppRule].self, from: data)
        try validate(rules)
        return rules
    }

    static func validate(_ rules: [AppRule]) throws {
        guard Set(rules.map(\.path)).count == rules.count,
              rules.allSatisfy({ $0.path.hasPrefix("/") && $0.path.hasSuffix(".app") &&
                  !$0.signingID.isEmpty && $0.route.isValid }) else {
            throw NSError(domain: "SplitWebOnMac", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "В списке есть дубликат или правило с неверными параметрами."
            ])
        }
    }
}
