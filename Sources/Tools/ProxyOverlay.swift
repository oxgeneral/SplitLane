import Foundation
import OSLog
import SystemConfiguration

@main
struct ProxyOverlay {
    private static let journal = URL(fileURLWithPath: "/var/db/local.splitlane.proxy-restore.plist")
    private static let log = Logger(subsystem: "local.splitlane", category: "proxy")

    static func main() {
        do { try run() }
        catch {
            log.error("Proxy session failed: \(error.localizedDescription, privacy: .private)")
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    private static func run() throws {
        let request = try ProxyOverlayRequest(arguments: Array(CommandLine.arguments.dropFirst()))
        var owner: uid_t?
        var lock: Int32 = -1
        defer { if lock >= 0 { close(lock) } }
        if request.authorized {
            guard geteuid() == 0,
                  let uid = ProcessInfo.processInfo.environment["SUDO_UID"].flatMap(uid_t.init), uid > 0 else {
                throw failure("Нет разрешения на управление системным прокси.")
            }
            owner = uid
            lock = open("/var/run/local.splitlane.lock", O_RDONLY | O_CREAT | O_NOFOLLOW, 0o600)
            guard lock >= 0, flock(lock, LOCK_EX | LOCK_NB) == 0 else {
                throw failure("Другая копия SplitLane уже управляет маршрутами.")
            }
        }
        if let uid = request.packetCaptureOwner {
            guard geteuid() == 0, !request.authorized || uid == owner else {
                throw failure("Нет разрешения на управление сетевым фильтром SplitLane.")
            }
            owner = uid
        }
        let lease = request.lease
        let port = request.port
        let state = URL(fileURLWithPath: "/private/tmp/\(request.sessionName)")
        let ready = state.appendingPathComponent("ready")
        guard let store = SCDynamicStoreCreate(nil, "SplitLane" as CFString, nil, nil) else {
            throw failure("Не удалось открыть сетевые настройки macOS.")
        }
        func restoreTimeZone() throws {
            if FileManager.default.fileExists(atPath: SystemTimeZoneCommand.journal) {
                try SystemTimeZoneCommand.run(["restore"])
            }
        }
        try restoreTimeZone()
        try restore()
        try cleanLegacyVPNProxies()
        try PacketCapture.recover()
        guard !primaryServices(store).isEmpty else {
            throw failure("Подключись к Wi‑Fi или Ethernet и снова нажми «Включить правила».")
        }

        func active() throws -> Bool {
            var status = stat()
            guard kill(request.appPID, 0) == 0 else {
                log.notice("Restoring network settings because the application exited.")
                return false
            }
            guard lstat(lease.path, &status) == 0, status.st_mode & S_IFMT == S_IFREG,
                  owner == nil || status.st_uid == owner else { return false }
            guard kill(request.proxyPID, 0) == 0 else {
                log.error("The local proxy exited while routing was active.")
                throw failure("Локальный прокси остановился.")
            }
            return true
        }

        for _ in 0..<30 {
            guard try active() else { return }
            if listenerReady(port) { break }
            Thread.sleep(forTimeInterval: 0.1)
        }
        guard listenerReady(port) else { throw failure("Локальный прокси не открыл порт.") }
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o755])
        var vpnOverlay = VPNProxyOverlay()
        var protection: PacketCapture?
        var timeZoneStarted = false
        defer {
            try? FileManager.default.removeItem(at: ready)
            do { try vpnOverlay.stop() }
            catch { log.error("Could not restore the temporary VPN settings.") }
            do { try restore() }
            catch { log.error("Could not restore the system proxy. The recovery journal was retained.") }
            protection?.stop()
            try? FileManager.default.removeItem(at: state)
            if timeZoneStarted {
                do { try restoreTimeZone() }
                catch { log.error("Could not restore the system time zone. The recovery journal was retained.") }
            }
        }
        if let owner = request.packetCaptureOwner {
            protection = try PacketCapture(lease: lease, state: state, owner: owner,
                                           executable: URL(fileURLWithPath: CommandLine.arguments[0] + ".engine"))
        }

        var activeServices: [String] = []
        while try active() {
            try protection?.check()
            let next = primaryServices(store)
            if next != activeServices {
                try vpnOverlay.stop()
                try restore()
                try? FileManager.default.removeItem(at: ready)
                activeServices = next
                if !next.isEmpty {
                    var regularServices: [String] = []
                    var vpnServices: [String] = []
                    for id in next {
                        guard let isVPN = isVPNService(id, store: store) else {
                            throw failure("Не удалось определить тип активного подключения.")
                        }
                        if isVPN {
                            vpnServices.append(id)
                        } else {
                            regularServices.append(id)
                        }
                    }
                    if !regularServices.isEmpty { try apply(to: regularServices, port: port, store: store) }
                    for id in vpnServices { try vpnOverlay.install(service: id, port: port) }
                    for _ in 0..<25 {
                        guard try active() else { return }
                        if effective(port) { break }
                        Thread.sleep(forTimeInterval: 0.1)
                    }
                    guard effective(port) else { throw failure("macOS не применила прокси для текущего подключения.") }
                    if let timeZone = request.timeZone, !timeZoneStarted {
                        timeZoneStarted = true
                        try SystemTimeZoneCommand.run(["begin", timeZone])
                    }
                    try Data().write(to: ready)
                }
            } else if !activeServices.isEmpty, !effective(port) {
                // Give configd time to publish a new primary service before checking again.
                Thread.sleep(forTimeInterval: 0.5)
                if !effective(port), activeServices == primaryServices(store) {
                    let current = SCDynamicStoreCopyProxies(nil) as? [String: Any] ?? [:]
                    if ProxyOverlaySettings.hasProxy(current) {
                        log.error("The active system proxy no longer points to SplitLane.")
                        throw failure("Системный прокси был изменён извне. Правила выключены.")
                    }
                    log.notice("Re-applying SplitLane proxy after network service reset.")
                    activeServices = []
                }
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        try vpnOverlay.stop()
        try restore()
    }

    private static func isVPNService(_ id: String, store: SCDynamicStore) -> Bool? {
        let vpnTypes = ["VPN", "IPSec", "PPP"]
        let setupKey = "Setup:/Network/Service/\(id)/Interface" as CFString
        if let interface = SCDynamicStoreCopyValue(store, setupKey) as? [String: Any],
           let type = interface["Type"] as? String {
            return vpnTypes.contains(type)
        }
        for suffix in vpnTypes {
            if SCDynamicStoreCopyValue(store, "State:/Network/Service/\(id)/\(suffix)" as CFString) != nil {
                return true
            }
        }
        if let preferences = SCPreferencesCreate(nil, "SplitLane" as CFString, nil),
           let service = SCNetworkServiceCopy(preferences, id as CFString),
           let interface = SCNetworkServiceGetInterface(service),
           let type = SCNetworkInterfaceGetInterfaceType(interface) as String? {
            return vpnTypes.contains(type)
        }
        for family in ["IPv4", "IPv6"] {
            let stateKey = "State:/Network/Service/\(id)/\(family)" as CFString
            if let state = SCDynamicStoreCopyValue(store, stateKey) as? [String: Any],
               let name = state["InterfaceName"] as? String, !name.isEmpty {
                return ["utun", "ppp", "ipsec", "tun"].contains { name.hasPrefix($0) }
            }
        }
        return nil
    }

    private static func primaryServices(_ store: SCDynamicStore) -> [String] {
        Set(["IPv4", "IPv6"].compactMap { family in
            let key = "State:/Network/Global/\(family)" as CFString
            return (SCDynamicStoreCopyValue(store, key) as? [String: Any])?["PrimaryService"] as? String
        }).sorted()
    }

    private static func effective(_ port: UInt16) -> Bool {
        guard let value = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return false }
        return ProxyOverlaySettings.isLocalProxy(value, port: port)
    }

    private static func apply(to services: [String], port: UInt16, store: SCDynamicStore) throws {
        try updatePreferences { preferences in
            var backup: [String: [String: [String: Any]]] = [:]
            for id in services {
                let proto = try proxyProtocol(preferences, id)
                let current = SCNetworkProtocolGetConfiguration(proto) as? [String: Any] ?? [:]
                let stateKey = "State:/Network/Service/\(id)/Proxies" as CFString
                let state = SCDynamicStoreCopyValue(store, stateKey) as? [String: Any] ?? [:]
                guard let original = ProxyOverlaySettings.baseline(current, state: state, port: port) else {
                    throw failure("В активном подключении уже настроен другой прокси или PAC. Отключи его в системных настройках сети и повтори запуск.")
                }
                let changed = ProxyOverlaySettings.installing(on: original, port: port)
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
                guard let original = settings["original"], let installed = settings["installed"] else {
                    throw failure("Не удалось прочитать резервную копию настроек прокси.")
                }
                guard SCNetworkServiceCopy(preferences, id as CFString) != nil else { continue }
                let proto = try proxyProtocol(preferences, id)
                let current = SCNetworkProtocolGetConfiguration(proto) as? [String: Any] ?? [:]
                let restored = ProxyOverlaySettings.restoring(current, original: original, installed: installed)
                guard SCNetworkProtocolSetConfiguration(proto, restored as CFDictionary) else {
                    throw failure("Не удалось восстановить настройки прокси.")
                }
            }
        }
        try FileManager.default.removeItem(at: journal)
    }

    private static func cleanLegacyVPNProxies() throws {
        // An older helper may have lost its journal while NetworkExtension
        // retained a second copy of the loopback proxy in a disconnected VPN.
        try updatePreferencesIfChanged { preferences in
            var changed = false
            guard let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] else { return false }
            for service in services {
                guard let id = SCNetworkServiceGetServiceID(service) as String?,
                      let interface = SCNetworkServiceGetInterface(service),
                      let type = SCNetworkInterfaceGetInterfaceType(interface) as String?,
                      ["VPN", "PPP", "IPSec"].contains(type) else { continue }
                for suffix in ["Proxies", "VPN/Proxies"] {
                    let path = "/NetworkServices/\(id)/\(suffix)" as CFString
                    guard let values = SCPreferencesPathGetValue(preferences, path) as? [String: Any],
                          ProxyOverlaySettings.isLocalProxy(values, port: ProxyOverlaySettings.port),
                          let cleaned = ProxyOverlaySettings.baseline(values, state: [:], port: ProxyOverlaySettings.port)
                    else { continue }
                    guard SCPreferencesPathSetValue(preferences, path, cleaned as CFDictionary) else {
                        throw failure("Не удалось убрать прежний прокси SplitLane из VPN-профиля.")
                    }
                    changed = true
                }
            }
            return changed
        }
    }

    private static func proxyProtocol(_ preferences: SCPreferences, _ id: String) throws -> SCNetworkProtocol {
        guard let service = SCNetworkServiceCopy(preferences, id as CFString),
              let proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else {
            throw failure("В активном сетевом сервисе нет настроек прокси.")
        }
        return proto
    }

    private static func updatePreferences(_ update: (SCPreferences) throws -> Void) throws {
        try updatePreferencesIfChanged { preferences in
            try update(preferences)
            return true
        }
    }

    private static func updatePreferencesIfChanged(_ update: (SCPreferences) throws -> Bool) throws {
        guard let preferences = SCPreferencesCreate(nil, "SplitLane" as CFString, nil),
              SCPreferencesLock(preferences, true) else {
            throw failure("Не удалось открыть настройки сети для изменения.")
        }
        defer { SCPreferencesUnlock(preferences) }
        guard try update(preferences) else { return }
        guard SCPreferencesCommitChanges(preferences), SCPreferencesApplyChanges(preferences) else {
            throw failure("macOS не сохранила настройки прокси.")
        }
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
        NSError(domain: "SplitLane.Proxy", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
