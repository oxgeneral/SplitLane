import Foundation
import SystemConfiguration

@main
struct ProxyOverlay {
    private static let flags = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]
    private static let journal = URL(fileURLWithPath: "/var/db/local.splitwebonmac.proxy-restore.plist")

    static func main() {
        do { try run() }
        catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    private static func run() throws {
        var args = Array(CommandLine.arguments.dropFirst())
        let authorized = args.first == "--authorized"
        var owner: uid_t?
        var lock: Int32 = -1
        defer { if lock >= 0 { close(lock) } }
        if authorized {
            args.removeFirst()
            guard geteuid() == 0,
                  let uid = ProcessInfo.processInfo.environment["SUDO_UID"].flatMap(uid_t.init), uid > 0 else {
                throw failure("Нет разрешения на управление системным прокси.")
            }
            owner = uid
            lock = open("/var/run/local.splitwebonmac.lock", O_RDONLY | O_CREAT | O_NOFOLLOW, 0o600)
            guard lock >= 0, flock(lock, LOCK_EX | LOCK_NB) == 0 else {
                throw failure("Другая копия SplitWebOnMac уже управляет маршрутами.")
            }
        }
        guard args.count == 4, let token = UUID(uuidString: args[0]),
              let port = UInt16(args[2]), port > 0, let pid = Int32(args[3]), pid > 1 else {
            throw failure("Неверные параметры запуска системного прокси.")
        }
        let lease = URL(fileURLWithPath: args[1])
        let sessionName = "splitwebonmac-\(token.uuidString)"
        if authorized {
            guard lease.lastPathComponent == "lease", lease.deletingLastPathComponent().lastPathComponent == sessionName,
                  lease.path.hasPrefix("/var/folders/") || lease.path.hasPrefix("/private/var/folders/") else {
                throw failure("Неверный путь к активной сессии SplitWebOnMac.")
            }
        }
        let state = URL(fileURLWithPath: "/private/tmp/\(sessionName)")
        let ready = state.appendingPathComponent("ready")
        guard let store = SCDynamicStoreCreate(nil, "SplitWebOnMac" as CFString, nil, nil) else {
            throw failure("Не удалось открыть сетевые настройки macOS.")
        }
        try restore()
        guard !primaryServices(store).isEmpty else { throw failure("Нет активного сетевого подключения.") }

        func active() -> Bool {
            guard kill(pid, 0) == 0 else { return false }
            if let owner {
                var status = stat()
                guard lstat(lease.path, &status) == 0, status.st_uid == owner,
                      status.st_mode & S_IFMT == S_IFREG else { return false }
                let modified = Date(timeIntervalSince1970: TimeInterval(status.st_mtimespec.tv_sec))
                return abs(Date().timeIntervalSince(modified)) < 5
            }
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: lease.path),
                  let last = attributes[.modificationDate] as? Date else { return false }
            return Date().timeIntervalSince(last) < 5
        }

        for _ in 0..<30 {
            guard active() else { return }
            if listenerReady(port) { break }
            Thread.sleep(forTimeInterval: 0.1)
        }
        guard listenerReady(port) else { throw failure("Локальный прокси не открыл порт.") }
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o755])
        defer {
            try? restore()
            try? FileManager.default.removeItem(at: ready)
            try? FileManager.default.removeItem(at: state)
        }

        var activeServices: [String] = []
        while active() {
            let next = primaryServices(store)
            if next != activeServices {
                try restore()
                try? FileManager.default.removeItem(at: ready)
                activeServices = next
                if !next.isEmpty {
                    try apply(to: next, port: port, store: store)
                    for _ in 0..<25 {
                        guard active() else { return }
                        if effective(port) { break }
                        Thread.sleep(forTimeInterval: 0.1)
                    }
                    guard effective(port) else { throw failure("macOS не применила прокси для текущего подключения.") }
                    try Data().write(to: ready)
                }
            } else if !activeServices.isEmpty, !effective(port) {
                // Give configd time to publish a new primary service before checking again.
                Thread.sleep(forTimeInterval: 0.5)
                if !effective(port), activeServices == primaryServices(store) {
                    throw failure("Системный прокси был изменён извне. Правила выключены.")
                }
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        try restore()
    }

    private static func primaryServices(_ store: SCDynamicStore) -> [String] {
        Set(["IPv4", "IPv6"].compactMap { family in
            let key = "State:/Network/Global/\(family)" as CFString
            return (SCDynamicStoreCopyValue(store, key) as? [String: Any])?["PrimaryService"] as? String
        }).sorted()
    }

    private static func effective(_ port: UInt16) -> Bool {
        guard let value = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return false }
        return ["HTTP", "HTTPS"].allSatisfy {
            value[$0 + "Enable"] as? Int == 1 && value[$0 + "Proxy"] as? String == "127.0.0.1" &&
                value[$0 + "Port"] as? Int == Int(port)
        }
    }

    private static func apply(to services: [String], port: UInt16, store: SCDynamicStore) throws {
        try updatePreferences { preferences in
            var backup: [String: [String: [String: Any]]] = [:]
            for id in services {
                let proto = try proxyProtocol(preferences, id)
                let original = SCNetworkProtocolGetConfiguration(proto) as? [String: Any] ?? [:]
                let stateKey = "State:/Network/Service/\(id)/Proxies" as CFString
                let state = SCDynamicStoreCopyValue(store, stateKey) as? [String: Any] ?? [:]
                guard !hasProxy(original), !hasProxy(state) else {
                    throw failure("В активном подключении уже настроен прокси. Его настройки сохранены.")
                }
                let changed = withLocalProxy(original, port: port)
                backup[id] = ["original": original, "installed": changed]
                guard SCNetworkProtocolSetConfiguration(proto, changed as CFDictionary) else {
                    throw failure("Не удалось задать локальный прокси.")
                }
            }
            let data = try PropertyListSerialization.data(fromPropertyList: backup, format: .binary, options: 0)
            try data.write(to: journal, options: .atomic)
        }
    }

    private static func restore() throws {
        guard FileManager.default.fileExists(atPath: journal.path) else { return }
        let data = try Data(contentsOf: journal)
        guard let backup = try PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: [String: [String: Any]]] else {
            throw failure("Не удалось прочитать резервную копию настроек прокси.")
        }
        try updatePreferences { preferences in
            for (id, settings) in backup {
                guard let proto = try? proxyProtocol(preferences, id),
                      let original = settings["original"], let installed = settings["installed"],
                      var current = SCNetworkProtocolGetConfiguration(proto) as? [String: Any] else { continue }
                for (key, value) in installed {
                    if let currentValue = current[key], (value as AnyObject).isEqual(currentValue) {
                        current[key] = original[key]
                    }
                }
                guard SCNetworkProtocolSetConfiguration(proto, current as CFDictionary) else {
                    throw failure("Не удалось восстановить настройки прокси.")
                }
            }
        }
        try FileManager.default.removeItem(at: journal)
    }

    private static func proxyProtocol(_ preferences: SCPreferences, _ id: String) throws -> SCNetworkProtocol {
        guard let service = SCNetworkServiceCopy(preferences, id as CFString),
              let proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else {
            throw failure("В активном сетевом сервисе нет настроек прокси.")
        }
        return proto
    }

    private static func updatePreferences(_ update: (SCPreferences) throws -> Void) throws {
        guard let preferences = SCPreferencesCreate(nil, "SplitWebOnMac" as CFString, nil),
              SCPreferencesLock(preferences, true) else {
            throw failure("Не удалось открыть настройки сети для изменения.")
        }
        defer { SCPreferencesUnlock(preferences) }
        try update(preferences)
        guard SCPreferencesCommitChanges(preferences), SCPreferencesApplyChanges(preferences) else {
            throw failure("macOS не сохранила настройки прокси.")
        }
    }

    private static func hasProxy(_ value: [String: Any]) -> Bool {
        flags.contains { (value[$0] as? Int ?? 0) != 0 }
    }

    private static func withLocalProxy(_ baseline: [String: Any], port: UInt16) -> [String: Any] {
        var value = baseline
        for scheme in ["HTTP", "HTTPS"] {
            value[scheme + "Enable"] = 1
            value[scheme + "Proxy"] = "127.0.0.1"
            value[scheme + "Port"] = Int(port)
        }
        var exceptions = value["ExceptionsList"] as? [String] ?? []
        for local in ["localhost", "127.0.0.1", "::1", "*.local"] where !exceptions.contains(local) {
            exceptions.append(local)
        }
        value["ExceptionsList"] = exceptions
        return value
    }

    private static func listenerReady(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        return withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
    }

    private static func failure(_ text: String) -> NSError {
        NSError(domain: "SplitWebOnMac.Proxy", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
