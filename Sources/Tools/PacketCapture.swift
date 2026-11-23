import Foundation

final class PacketCapture {
    private static let anchor = "com.apple/local.splitwebonmac.webrtc"
    private static let journal = URL(fileURLWithPath: "/var/db/local.splitwebonmac.pf-token")

    private let engine = Process()
    private let directory: URL
    private let owner: uid_t
    private var token: String?
    private var nextCheck = ContinuousClock.now
    private let capturesTCP: Bool
    private var tunnel = ""
    private var installedRules = ""
    private var installedAddresses: [String] = []

    init(lease: URL, state: URL, owner: uid_t, executable: URL) throws {
        directory = state.appendingPathComponent("protection")
        self.owner = owner
        let apps = try Self.readRules(beside: lease, owner: owner)
        capturesTCP = apps.contains { $0.relayID != nil }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            let interfaces = try Self.command("/sbin/ifconfig", [])
            guard !interfaces.contains(PacketRoutingConfiguration.ipv4),
                  !interfaces.contains(PacketRoutingConfiguration.ipv6) else {
                throw Self.failure("Адрес интерфейса перехвата уже используется.")
            }
            let mainRules = try Self.command("/sbin/pfctl", ["-sr"])
            guard mainRules.split(separator: "\n").contains("anchor \"com.apple/*\" all") else {
                throw Self.failure("macOS не предоставила точку подключения сетевого фильтра SplitWeb.")
            }
            let config = directory.appendingPathComponent("tun.json")
            try PacketRoutingConfiguration.make(apps: apps).write(to: config)
            engine.executableURL = executable
            engine.arguments = ["run", "-c", config.path]
            engine.standardOutput = FileHandle.nullDevice
            engine.standardError = FileHandle.nullDevice
            try engine.run()

            var tunnel: String?
            for _ in 0..<20 {
                guard engine.isRunning else { break }
                if let name = Self.interface(in: try Self.command("/sbin/ifconfig", []), address: PacketRoutingConfiguration.ipv4) {
                    tunnel = name
                    break
                }
                Thread.sleep(forTimeInterval: 0.15)
            }
            guard let tunnel, tunnel.range(of: #"^utun[0-9]+$"#, options: .regularExpression) != nil else {
                throw Self.failure("Не удалось открыть виртуальный сетевой интерфейс SplitWeb.")
            }
            self.tunnel = tunnel
            let enabled = try Self.command("/sbin/pfctl", ["-E"])
            guard let value = enabled.split(separator: "\n").first(where: { $0.hasPrefix("Token") })?
                .split(whereSeparator: \.isWhitespace).last, UInt64(value) != nil else {
                throw Self.failure("Не удалось получить разрешение на временное правило фильтра.")
            }
            token = String(value)
            try Data(value.utf8).write(to: Self.journal, options: .atomic)
            try check()
        } catch {
            stop()
            throw error
        }
    }

    static func recover() throws {
        guard FileManager.default.fileExists(atPath: journal.path) else { return }
        let token = try String(contentsOf: journal, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard UInt64(token) != nil else { throw failure("Не удалось восстановить состояние сетевого фильтра SplitWeb.") }
        _ = try command("/sbin/pfctl", ["-a", anchor, "-F", "rules"])
        _ = try? command("/sbin/pfctl", ["-X", token])
        try FileManager.default.removeItem(at: journal)
    }

    func check() throws {
        guard engine.isRunning else { throw Self.failure("Сетевой фильтр SplitWeb остановился. Правила выключены.") }
        try updateFilter()
        guard ContinuousClock.now >= nextCheck else { return }
        let rules = try Self.command("/sbin/pfctl", ["-a", Self.anchor, "-sr"])
        let status = try Self.command("/sbin/pfctl", ["-si"])
        let expectedCount = installedRules.split(separator: "\n").filter { $0.contains("route-to") }.count
        guard rules.split(separator: "\n").filter({ $0.contains("route-to") }).count == expectedCount,
              status.split(separator: "\n").contains(where: { $0.hasPrefix("Status: Enabled") }) else {
            throw Self.failure("Системные правила перехвата трафика исчезли. Правила выключены.")
        }
        nextCheck = .now + .seconds(2)
    }

    private func updateFilter() throws {
        let addresses = PacketRoutingConfiguration.liveAddressSnapshot()
        let rules = PacketRoutingConfiguration.filter(owner: owner, interface: tunnel, capturesTCP: capturesTCP)
        // The const self table must be reloaded when DHCP or a VPN changes local addresses.
        guard rules != installedRules || addresses != installedAddresses else { return }
        let filter = directory.appendingPathComponent("filter.conf")
        try Data(rules.utf8).write(to: filter)
        _ = try Self.command("/sbin/pfctl", ["-n", "-a", Self.anchor, "-f", filter.path])
        _ = try Self.command("/sbin/pfctl", ["-a", Self.anchor, "-f", filter.path])
        installedRules = rules
        installedAddresses = addresses
    }

    func stop() {
        if let token {
            if (try? Self.command("/sbin/pfctl", ["-a", Self.anchor, "-F", "rules"])) != nil {
                _ = try? Self.command("/sbin/pfctl", ["-X", token])
                try? FileManager.default.removeItem(at: Self.journal)
            }
            self.token = nil
        }
        if engine.isRunning {
            engine.terminate()
            let deadline = ContinuousClock.now + .seconds(4)
            while engine.isRunning && ContinuousClock.now < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if engine.isRunning {
                kill(engine.processIdentifier, SIGKILL)
            }
            engine.waitUntilExit()
        }
        try? FileManager.default.removeItem(at: directory)
    }

    private static func readRules(beside lease: URL, owner: uid_t) throws -> [PacketRoutingRule] {
        let manifest = lease.deletingLastPathComponent().appendingPathComponent(PacketRoutingConfiguration.manifest)
        let fd = open(manifest.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw failure("Список приложений для перехвата трафика недоступен.") }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == owner, info.st_mode & S_IFMT == S_IFREG,
              (1...65_536).contains(info.st_size), let data = try file.read(upToCount: 65_537),
              data.count <= 65_536 else { throw failure("Неверный файл правил перехвата трафика.") }
        let apps = try JSONDecoder().decode([PacketRoutingRule].self, from: data)
        let ids = apps.compactMap(\.relayID)
        guard !apps.isEmpty, Set(ids).count == ids.count,
              apps.allSatisfy({ $0.path.hasPrefix("/") && $0.path.hasSuffix(".app") && !$0.path.contains("\0") &&
                  ($0.blockUDP || $0.relayID != nil) }) else {
            throw failure("Неверный список приложений для перехвата трафика.")
        }
        return apps
    }

    private static func interface(in output: String, address: String) -> String? {
        var current: String?
        for line in output.split(separator: "\n") {
            let parts = line.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 2 else { continue }
            if line.first?.isWhitespace == false { current = String(parts[0].dropLast()) }
            else if parts[0] == "inet" && parts[1] == address { return current }
        }
        return nil
    }

    private static func command(_ path: String, _ arguments: [String]) throws -> String {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw failure("Сетевой фильтр SplitWeb вернул ошибку. \(output)") }
        return output
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "SplitWebOnMac.PacketCapture", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
