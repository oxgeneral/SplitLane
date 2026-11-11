import Foundation
import NetworkExtension
import SwiftUI
import SystemExtensions

@MainActor
final class Router: ObservableObject {
    @Published private(set) var routeGroups = RouteGroups()
    @Published private(set) var busy = false
    @Published private(set) var enabled = false
    @Published private(set) var connection: NEVPNStatus = .invalid
    @Published private(set) var error: String?
    @Published private(set) var proxyPermission = ProxyPermission.isInstalled
    @Published private var awaitingApproval = false

    private var manager: NETransparentProxyManager?
    private let activation = ExtensionActivation()
    private var tun: TunSession?
    private var extensionID: String { (Bundle.main.bundleIdentifier ?? "") + ".proxy" }
    var isInstallable: Bool {
        Bundle.main.object(forInfoDictionaryKey: "SplitWebRoutingBuild") as? Bool == true
    }
    private var isLocal: Bool {
        Bundle.main.object(forInfoDictionaryKey: "SplitWebEngineSHA") != nil
    }
    var isProxyMode: Bool { Bundle.main.object(forInfoDictionaryKey: "SplitWebProxyOverlaySHA") != nil }
    var canRoute: Bool { isInstallable || isLocal }
    var wantsRouting: Bool { isLocal ? tun != nil : enabled }
    var rulesLocked: Bool { busy || (isLocal && wantsRouting) }
    var isRouting: Bool { (isLocal ? enabled : connection == .connected) && !busy }
    var hasAssignedApps: Bool { routeGroups.groups.contains { !$0.apps.isEmpty } }
    var status: String {
        if isLocal {
            if busy {
                if tun?.stopping == true { return "Восстанавливаем системные маршруты…" }
                return isProxyMode && proxyPermission ? "Применяем сетевые настройки…" : "Может потребоваться пароль Mac"
            }
            if enabled { return isProxyMode ? "Правила включены · HTTP и HTTPS" : "Правила включены для новых соединений" }
            if wantsRouting { return "Ожидаем активное подключение…" }
            return "Правила выключены · системные настройки macOS"
        }
        if !isInstallable { return "Предпросмотр · правила сохранены на этом Mac" }
        if awaitingApproval { return "Ожидает разрешения в Системных настройках" }
        if busy { return "Применяем правила…" }
        if isRouting { return "Правила включены для новых соединений" }
        if enabled { return "Расширение сети пока не подключено" }
        return "Все приложения используют настройки macOS"
    }

    init() {
        do { routeGroups = try RouteGroups.load(from: .standard) }
        catch { self.error = "Не удалось открыть сохранённые сетевые группы." }
    }

    func refresh() async {
        guard isInstallable else { return }
        do {
            manager = try await loadManager()
            enabled = manager?.isEnabled == true
            updateConnectionStatus()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func updateConnectionStatus() {
        connection = manager?.connection.status ?? .invalid
    }

    func save(_ group: RouteGroup) {
        updateGroups { $0.save(group) }
    }

    func assign(_ apps: [GroupApp], to groupID: UUID) {
        guard !apps.isEmpty else { return }
        updateGroups { groups in
            for app in apps { groups.assign(app, to: groupID) }
        }
    }

    func removeApp(_ appID: String, from groupID: UUID) {
        updateGroups { $0.removeApp(appID, from: groupID) }
    }

    func removeGroup(_ groupID: UUID) {
        updateGroups { $0.removeGroup(groupID) }
    }

    func toggle() {
        if isLocal {
            guard !busy else { return }
            if let tun {
                busy = true
                tun.stop()
            } else {
                startLocal()
            }
        } else {
            apply(routeGroups, enable: !enabled)
        }
    }

    func stopLocal() {
        tun?.stop()
    }

    func setProxyPermission(_ allowed: Bool) {
        guard isProxyMode, !rulesLocked else { return }
        busy = true
        error = nil
        Task {
            defer {
                proxyPermission = ProxyPermission.isInstalled
                busy = false
            }
            do {
                try await Task.detached(priority: .userInitiated) { try ProxyPermission.setInstalled(allowed) }.value
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    private func startLocal() {
        busy = true
        error = nil
        let savedRules = routeGroups.rules
        let useProxy = isProxyMode
        Task {
            defer {
                tun = nil
                enabled = false
                busy = false
            }
            do {
                let configuration = try await Task.detached(priority: .userInitiated) { () -> LocalRoutingConfiguration in
                    if useProxy { return .proxy(try ProxyRoutingConfiguration.make(rules: savedRules)) }
                    return .tun(try TunConfiguration.make(rules: savedRules))
                }.value
                let session = try TunSession(configuration: configuration)
                tun = session
                while session.isRunning {
                    do {
                        try session.renewLease()
                    } catch {
                        busy = true
                        self.error = error.localizedDescription
                        session.stop()
                    }
                    if !session.stopping {
                        let ready = session.isReady
                        if enabled != ready { enabled = ready }
                        if ready && busy { busy = false }
                    }
                    try? await Task.sleep(for: .seconds(1))
                }
                if let failure = session.finish() { error = failure }
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    private func updateGroups(_ update: (inout RouteGroups) -> Void) {
        guard !rulesLocked else { return }
        var updated = routeGroups
        update(&updated)
        if isInstallable {
            apply(updated, enable: !updated.rules.isEmpty)
        } else {
            do { try store(updated) }
            catch { self.error = error.localizedDescription }
        }
    }

    private func loadManager() async throws -> NETransparentProxyManager? {
        try await NETransparentProxyManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == extensionID
        }
    }

    private func store(_ updated: RouteGroups) throws {
        let data = try updated.encoded()
        UserDefaults.standard.set(data, forKey: RouteGroups.defaultsKey)
        routeGroups = updated
        error = nil
    }

    private func apply(_ updated: RouteGroups, enable: Bool) {
        guard isInstallable, !busy else { return }
        busy = true
        error = nil
        Task {
            defer {
                busy = false
                awaitingApproval = false
                updateConnectionStatus()
            }
            do {
                let data = try RuleConfiguration.encode(updated.rules)
                if enable {
                    try await activation.activate(identifier: extensionID) { self.awaitingApproval = true }
                    awaitingApproval = false
                }

                let proxy = try await loadManager() ?? NETransparentProxyManager()
                let config = NETunnelProviderProtocol()
                config.providerBundleIdentifier = extensionID
                config.serverAddress = "SplitWebOnMac"
                config.providerConfiguration = [RuleConfiguration.key: data]
                proxy.protocolConfiguration = config
                proxy.localizedDescription = "SplitWebOnMac"
                proxy.isEnabled = enable
                try await proxy.saveToPreferences()
                manager = proxy
                enabled = enable
                try store(updated)
                try await proxy.loadFromPreferences()
                if enable && [.invalid, .disconnected].contains(proxy.connection.status) {
                    try proxy.connection.startVPNTunnel()
                }
            } catch {
                self.error = error.localizedDescription
                await refresh()
            }
        }
    }
}

@MainActor
private final class ExtensionActivation: NSObject, @preconcurrency OSSystemExtensionRequestDelegate {
    private var pending: CheckedContinuation<Void, Error>?
    private var approval: (() -> Void)?

    func activate(identifier: String, needsApproval: @escaping () -> Void) async throws {
        try await withCheckedThrowingContinuation { continuation in
            pending = continuation
            approval = needsApproval
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        approval?()
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed {
            pending?.resume()
            clear()
        } else {
            self.request(request, didFailWithError: NSError(domain: "SplitWebOnMac", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Для подключения расширения перезагрузи Mac."
            ]))
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        pending?.resume(throwing: error)
        clear()
    }

    private func clear() {
        pending = nil
        approval = nil
    }
}
