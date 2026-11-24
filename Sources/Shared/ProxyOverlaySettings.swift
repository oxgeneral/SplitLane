import Foundation

enum ProxyOverlaySettings {
    static let port: UInt16 = 39878
    static let lock = "/var/run/local.splitlane.lock"
    static let proxyJournal = URL(fileURLWithPath: "/var/db/local.splitlane.proxy-restore.plist")
    static let packetJournal = URL(fileURLWithPath: "/var/db/local.splitlane.pf-token")

    static var recoveryPending: Bool {
        [proxyJournal.path, packetJournal.path, SystemTimeZoneCommand.journal].contains {
            FileManager.default.fileExists(atPath: $0)
        }
    }

    private static let schemes = ["HTTP", "HTTPS"]
    private static let otherFlags = ["SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable",
                                     "FTPEnable", "GopherEnable", "RTSPEnable"]
    private static let exceptions = ["localhost", "127.0.0.1", "::1", "*.local"]

    static func hasProxy(_ settings: [String: Any]) -> Bool {
        (schemes.map { $0 + "Enable" } + otherFlags).contains { (settings[$0] as? Int ?? 0) != 0 }
    }

    static func isLocalProxy(_ settings: [String: Any], port: UInt16) -> Bool {
        schemes.allSatisfy {
            settings[$0 + "Enable"] as? Int == 1 && settings[$0 + "Proxy"] as? String == "127.0.0.1" &&
                settings[$0 + "Port"] as? Int == Int(port)
        } && !otherFlags.contains { (settings[$0] as? Int ?? 0) != 0 }
    }

    static func baseline(_ settings: [String: Any], state: [String: Any], port: UInt16) -> [String: Any]? {
        guard hasProxy(settings) || hasProxy(state) else { return settings }
        guard port == Self.port, isLocalProxy(settings, port: port),
              !hasProxy(state) || isLocalProxy(state, port: port),
              let bypass = settings["ExceptionsList"] as? [String],
              exceptions.allSatisfy(bypass.contains) else { return nil }
        // The original values are unavailable without the journal. Disable only SplitLane's endpoints.
        var baseline = settings
        for scheme in schemes { baseline[scheme + "Enable"] = 0 }
        return baseline
    }

    static func installing(on baseline: [String: Any], port: UInt16) -> [String: Any] {
        var settings = baseline
        for scheme in schemes {
            settings[scheme + "Enable"] = 1
            settings[scheme + "Proxy"] = "127.0.0.1"
            settings[scheme + "Port"] = Int(port)
        }
        var bypass = settings["ExceptionsList"] as? [String] ?? []
        for entry in exceptions where !bypass.contains(entry) { bypass.append(entry) }
        settings["ExceptionsList"] = bypass
        return settings
    }

    static func restoring(_ current: [String: Any], original: [String: Any],
                          installed: [String: Any]) -> [String: Any] {
        var settings = current
        func matches(_ key: String) -> Bool {
            guard let value = installed[key] else { return current[key] == nil }
            return (value as AnyObject).isEqual(current[key])
        }
        var ownsProxy = false
        for scheme in schemes {
            let keys = ["Enable", "Proxy", "Port"].map { scheme + $0 }
            guard keys.allSatisfy(matches) else { continue }
            ownsProxy = true
            for key in keys { settings[key] = original[key] }
        }
        if ownsProxy, matches("ExceptionsList") { settings["ExceptionsList"] = original["ExceptionsList"] }
        return settings
    }
}
