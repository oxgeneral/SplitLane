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
    private var wantsStop = false
    private var proxy: Process?

    var isRunning: Bool { process.isRunning }
    var isReady: Bool { FileManager.default.fileExists(atPath: ready.path) }
    var stopping: Bool { wantsStop }

    init(configuration: LocalRoutingConfiguration) throws {
        let bundle = Bundle.main
        guard let engine = bundle.url(forResource: "sing-box", withExtension: nil),
              let engineSHA = bundle.object(forInfoDictionaryKey: "SplitWebEngineSHA") as? String else {
            throw TunConfiguration.failure("В сборке отсутствует сетевой движок.")
        }

        let token = UUID().uuidString
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("splitwebonmac-\(token)")
        lease = directory.appendingPathComponent("lease")
        ready = URL(fileURLWithPath: "/private/tmp/splitwebonmac-\(token)/ready")
        let configURL = directory.appendingPathComponent("config.json")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        do {
            try configuration.data.write(to: configURL)
            try renewLease()
            let configSHA = SHA256.hash(data: configuration.data).map { String(format: "%02x", $0) }.joined()
            var args = AdministratorCommand.lock
            var launch = AdministratorCommand.prepare
            switch configuration {
            case .tun(let tun):
                args += ["/bin/bash", "-c", try Self.worker("run-tun"), "splitwebonmac",
                         engine.path, engineSHA, configURL.path, configSHA, lease.path, token,
                         TunConfiguration.ipv4Address, tun.systemIPv4, tun.systemIPv6 ?? ""] + tun.interfaces
            case .proxy:
                guard let helper = bundle.url(forResource: "proxy-overlay", withExtension: nil),
                      let helperSHA = bundle.object(forInfoDictionaryKey: "SplitWebProxyOverlaySHA") as? String else {
                    throw TunConfiguration.failure("В сборке отсутствует настройка системного прокси.")
                }
                let child = Process()
                child.executableURL = URL(fileURLWithPath: "/bin/bash")
                child.arguments = ["-c", try Self.worker("run-engine"), "splitwebonmac", engine.path, configURL.path, lease.path]
                child.standardOutput = FileHandle.nullDevice
                child.standardError = FileHandle.nullDevice
                try child.run()
                proxy = child
                let overlayArgs = [token, lease.path, String(ProxyRoutingConfiguration.port), String(child.processIdentifier)]
                if ProxyPermission.isInstalled {
                    args = ["-n", "--", ProxyPermission.helper, "--authorized"] + overlayArgs
                    launch = { process, args in
                        process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
                        process.arguments = args
                    }
                } else {
                    args += ["/bin/bash", "-c", try Self.worker("run-proxy"), "splitwebonmac",
                             helper.path, helperSHA] + overlayArgs
                }
            }
            launch(process, args)
            process.standardOutput = FileHandle.nullDevice
            process.standardError = output
            try process.run()
        } catch {
            if proxy?.isRunning == true { proxy?.terminate() }
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    func renewLease() throws {
        if !wantsStop {
            if proxy?.isRunning == false { throw TunConfiguration.failure("Локальный прокси остановился.") }
            try Data().write(to: lease, options: .atomic)
        }
    }

    func stop() {
        wantsStop = true
        try? FileManager.default.removeItem(at: lease)
    }

    func finish() -> String? {
        let error = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if proxy?.isRunning == true { proxy?.terminate() }
        try? FileManager.default.removeItem(at: directory)
        if proxy != nil, FileManager.default.fileExists(atPath: "/var/db/local.splitwebonmac.proxy-restore.plist"),
           !error.contains("lockf:") {
            return "macOS пока не восстановила прежние настройки прокси. Резервная копия сохранена."
        }
        guard !wantsStop, process.terminationStatus != 0 else { return nil }
        if error.contains("(-128)") { return "Запуск отменён." }
        if error.contains("lock") { return "Другая копия SplitWebOnMac уже управляет маршрутами." }
        return error.isEmpty ? "Не удалось включить сетевой движок." : error
    }

    fileprivate nonisolated static func worker(_ name: String) throws -> String {
        guard let path = Bundle.main.url(forResource: name, withExtension: "sh") else {
            throw TunConfiguration.failure("В сборке отсутствует сценарий запуска.")
        }
        return try String(contentsOf: path, encoding: .utf8)
    }

}

private enum AdministratorCommand {
    static let lock = ["/usr/bin/lockf", "-k", "-t", "0", "/var/run/local.splitwebonmac.lock"]

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
}

enum ProxyPermission {
    static var helper: String { "/Library/PrivilegedHelperTools/local.splitwebonmac.proxy-overlay.\(getuid())" }

    static var isInstalled: Bool {
        FileManager.default.isExecutableFile(atPath: helper) &&
            FileManager.default.fileExists(atPath: "/private/etc/sudoers.d/local-splitwebonmac-\(getuid())")
    }

    static func setInstalled(_ installed: Bool) throws {
        let process = Process()
        let output = Pipe()
        let worker = try TunSession.worker("proxy-permission")
        var args = AdministratorCommand.lock + ["/bin/bash", "-c", worker, "splitwebonmac",
                                                installed ? "install" : "remove", String(getuid())]
        if installed {
            guard let source = Bundle.main.url(forResource: "proxy-overlay", withExtension: nil),
                  let digest = Bundle.main.object(forInfoDictionaryKey: "SplitWebProxyOverlaySHA") as? String else {
                throw TunConfiguration.failure("В сборке отсутствует настройка системного прокси.")
            }
            args += [source.path, digest, String(ProxyRoutingConfiguration.port)]
        }
        AdministratorCommand.prepare(process, args)
        process.standardOutput = FileHandle.nullDevice
        process.standardError = output
        try process.run()
        let message = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw TunConfiguration.failure(message.contains("(-128)") ? "Настройка разрешения отменена." : message)
        }
    }
}
