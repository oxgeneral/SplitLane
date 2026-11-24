import CryptoKit
import Foundation

enum LocalRoutingConfiguration: Sendable {
    case tun(TunConfiguration)
    case proxy(ProxyRoutingConfiguration)

    var data: Data {
        switch self {
        case .tun(let configuration): configuration.data
        case .proxy(let configuration): configuration.data
        }
    }
}

@MainActor
final class TunSession {
    private let process = Process()
    private let output = Pipe()
    private let directory: URL
    private let lease: URL
    private let ready: URL
    private let managesTimeZone: Bool
    private var wantsStop = false
    private var proxy: Process?

    var isRunning: Bool { process.isRunning }
    var isReady: Bool { FileManager.default.fileExists(atPath: ready.path) }
    var stopping: Bool { wantsStop }

    init(configuration: LocalRoutingConfiguration, timeZone: String?) throws {
        if let timeZone, !TimeZone.knownTimeZoneIdentifiers.contains(timeZone) {
            throw TunConfiguration.failure("Выбери доступный часовой пояс Mac.")
        }
        managesTimeZone = timeZone != nil || FileManager.default.fileExists(atPath: SystemTimeZoneCommand.journal)
        let bundle = Bundle.main
        guard let engine = bundle.url(forAuxiliaryExecutable: "sing-box"),
              let engineSHA = bundle.object(forInfoDictionaryKey: "SplitLaneEngineSHA") as? String else {
            throw TunConfiguration.failure("В сборке отсутствует сетевой движок.")
        }

        let token = UUID().uuidString
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("splitlane-\(token)")
        lease = directory.appendingPathComponent("lease")
        ready = URL(fileURLWithPath: "/private/tmp/splitlane-\(token)/ready")
        let configURL = directory.appendingPathComponent("config.json")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        do {
            guard FileManager.default.createFile(atPath: configURL.path, contents: configuration.data,
                                                 attributes: [.posixPermissions: 0o600]) else {
                throw TunConfiguration.failure("Не удалось записать конфигурацию сетевого движка.")
            }
            try renewLease()
            let configSHA = SHA256.hash(data: configuration.data).map { String(format: "%02x", $0) }.joined()
            var args = AdministratorCommand.lock
            var launch = AdministratorCommand.prepare
            switch configuration {
            case .tun(let tun):
                args += ["/bin/bash", "-c", try Self.worker("run-tun"), "splitlane",
                         engine.path, engineSHA, configURL.path, configSHA, lease.path, token,
                         TunConfiguration.ipv4Address, tun.systemIPv4, tun.systemIPv6 ?? "",
                         SystemTimeZoneCommand.script, timeZone ?? ""] + tun.interfaces
            case .proxy(let configuration):
                guard let helper = bundle.url(forAuxiliaryExecutable: "proxy-overlay"),
                      let helperSHA = bundle.object(forInfoDictionaryKey: "SplitLaneProxyOverlaySHA") as? String else {
                    throw TunConfiguration.failure("В сборке отсутствует настройка системного прокси.")
                }
                let protected = !configuration.packetRules.isEmpty
                if protected {
                    let paths = try JSONEncoder().encode(configuration.packetRules)
                    guard FileManager.default.createFile(atPath: directory.appendingPathComponent(PacketRoutingConfiguration.manifest).path,
                                                         contents: paths, attributes: [.posixPermissions: 0o600]) else {
                        throw TunConfiguration.failure("Не удалось сохранить правила перехвата трафика.")
                    }
                }
                let child = Process()
                child.executableURL = URL(fileURLWithPath: "/bin/bash")
                child.arguments = ["-c", try Self.worker("run-engine"), "splitlane",
                                   engine.path, configURL.path, lease.path, String(getpid())]
                child.standardOutput = FileHandle.nullDevice
                child.standardError = FileHandle.nullDevice
                try child.run()
                proxy = child
                var overlayArgs = [token, lease.path, String(ProxyRoutingConfiguration.port),
                                   String(child.processIdentifier), String(getpid())]
                if protected { overlayArgs += ["protect", String(getuid())] }
                if let timeZone { overlayArgs += ["zone", timeZone] }
                if ProxyPermission.matchesCurrentBuild {
                    args = ["-n", "--", ProxyPermission.helper, "--authorized"] + overlayArgs
                    launch = { process, args in
                        process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
                        process.arguments = args
                    }
                } else {
                    args += ["/bin/bash", "-c", try Self.worker("run-proxy"), "splitlane", helper.path, helperSHA]
                    if protected { args += [engine.path, engineSHA] }
                    args += overlayArgs
                }
            }
            launch(process, args)
            process.standardOutput = FileHandle.nullDevice
            process.standardError = output
            try process.run()
        } catch {
            if let proxy, proxy.isRunning {
                proxy.terminate()
                proxy.waitUntilExit()
            }
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    func renewLease() throws {
        // The privileged overlay distinguishes a proxy crash from explicit lease removal.
        guard !wantsStop, proxy == nil else { return }
        try Data().write(to: lease, options: .atomic)
    }

    func stop() {
        wantsStop = true
        try? FileManager.default.removeItem(at: lease)
    }

    func finish() -> String? {
        let error = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let proxy, proxy.isRunning {
            proxy.terminate()
            proxy.waitUntilExit()
        }
        try? FileManager.default.removeItem(at: directory)
        let cancelled = AdministratorCommand.wasCancelled(error)
        let anotherSessionOwnsLock = error.contains("lockf:")
        let rootCause = (!cancelled && !anotherSessionOwnsLock && !error.isEmpty) ? error : nil
        if managesTimeZone, FileManager.default.fileExists(atPath: SystemTimeZoneCommand.journal),
           !cancelled, !anotherSessionOwnsLock {
            if let rootCause, rootCause.contains("Восстановить сеть") { return rootCause }
            let recovery = proxy != nil
                ? "Нажми «Восстановить сеть»."
                : "SplitLane повторит восстановление при следующем включении правил."
            let note = "macOS пока не восстановила часовой пояс. \(recovery)"
            return rootCause.map { "\($0) \(note)" } ?? note
        }
        if proxy != nil, FileManager.default.fileExists(atPath: ProxyOverlaySettings.proxyJournal.path),
           !cancelled, !anotherSessionOwnsLock {
            if let rootCause, rootCause.contains("Восстановить сеть") { return rootCause }
            let note = "macOS пока не восстановила прежние настройки прокси. Нажми «Восстановить сеть»."
            return rootCause.map { "\($0) \(note)" } ?? note
        }
        guard !wantsStop, process.terminationStatus != 0 else { return nil }
        if cancelled { return "Запуск отменён. Нажми «Включить правила», чтобы попробовать снова." }
        if anotherSessionOwnsLock { return "Другая копия SplitLane уже управляет маршрутами. Выключи правила в ней и попробуй снова." }
        if let explanation = AdministratorCommand.denialExplanation(error) { return explanation }
        return error.isEmpty ? "Не удалось включить сетевой движок." : error
    }

    nonisolated static func recoverNetwork() throws {
        let bundle = Bundle.main
        guard let helper = bundle.url(forAuxiliaryExecutable: "proxy-overlay"),
              let digest = bundle.object(forInfoDictionaryKey: "SplitLaneProxyOverlaySHA") as? String else {
            throw TunConfiguration.failure("В сборке отсутствует помощник для восстановления сети.")
        }
        try AdministratorCommand.run(["/bin/bash", "-c", worker("run-proxy"), "splitlane",
                                      helper.path, digest, "--recover"],
                                     cancelled: "Восстановление сети отменено.")
    }

    fileprivate nonisolated static func worker(_ name: String) throws -> String {
        guard let path = Bundle.main.url(forResource: name, withExtension: "sh") else {
            throw TunConfiguration.failure("В сборке отсутствует сценарий запуска.")
        }
        return try String(contentsOf: path, encoding: .utf8)
    }

}

enum AdministratorCommand {
    static let lock = ["/usr/bin/lockf", "-k", "-t", "0", ProxyOverlaySettings.lock]

    static func wasCancelled(_ message: String) -> Bool {
        message.contains("(-128)") || message.contains("(-60006)")
    }

    static func denialExplanation(_ message: String) -> String? {
        if message.contains("(-60005)") {
            return "macOS не разрешила изменить настройки сети. Попробуй снова и введи имя и пароль администратора этого Mac."
        }
        if message.contains("(-60007)") {
            return "macOS не смогла показать запрос разрешения. Открой панель SplitLane и попробуй снова."
        }
        return nil
    }

    static func prepare(_ process: Process, _ args: [String]) {
        let command = args.map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }.joined(separator: " ")
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = [
            "-e", "on run argv",
            "-e", "do shell script (item 1 of argv) with administrator privileges",
            "-e", "end run",
            "umask 077; exec " + command
        ]
    }

    static func run(_ args: [String], cancelled: String) throws {
        let process = Process()
        let output = Pipe()
        prepare(process, args)
        process.standardOutput = FileHandle.nullDevice
        process.standardError = output
        try process.run()
        let message = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            if wasCancelled(message) { throw TunConfiguration.failure(cancelled) }
            throw TunConfiguration.failure(denialExplanation(message) ?? message)
        }
    }
}

enum ProxyPermission {
    static var helper: String { "/Library/PrivilegedHelperTools/local.splitlane.proxy-overlay.\(getuid())" }

    static var isInstalled: Bool {
        FileManager.default.isExecutableFile(atPath: helper) &&
            FileManager.default.fileExists(atPath: "/private/etc/sudoers.d/local-splitlane-\(getuid())")
    }

    static var matchesCurrentBuild: Bool {
        guard isInstalled, FileManager.default.isExecutableFile(atPath: helper + ".engine"),
              let digest = Bundle.main.object(forInfoDictionaryKey: "SplitLaneProxyOverlaySHA") as? String,
              let engineDigest = Bundle.main.object(forInfoDictionaryKey: "SplitLaneEngineSHA") as? String else { return false }
        return [(helper, digest), (helper + ".engine", engineDigest)].allSatisfy { path, expected in
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else { return false }
            return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == expected
        }
    }

    static func setInstalled(_ installed: Bool) throws {
        let worker = try TunSession.worker("proxy-permission")
        var args = AdministratorCommand.lock + ["/bin/bash", "-c", worker, "splitlane",
                                                installed ? "install" : "remove", String(getuid())]
        if installed {
            guard let source = Bundle.main.url(forAuxiliaryExecutable: "proxy-overlay"),
                  let digest = Bundle.main.object(forInfoDictionaryKey: "SplitLaneProxyOverlaySHA") as? String,
                  let engine = Bundle.main.url(forAuxiliaryExecutable: "sing-box"),
                  let engineDigest = Bundle.main.object(forInfoDictionaryKey: "SplitLaneEngineSHA") as? String else {
                throw TunConfiguration.failure("В сборке отсутствует настройка системного прокси.")
            }
            args += [source.path, digest, String(ProxyRoutingConfiguration.port), engine.path, engineDigest]
        }
        try AdministratorCommand.run(args, cancelled: "Настройка разрешения отменена.")
    }
}
