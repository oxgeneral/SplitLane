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
    @Published private var preparingPermission = false

    private var manager: NETransparentProxyManager?
    private let activation = ExtensionActivation()
    private var tun: TunSession?
    private var terminating = false
    private var extensionID: String { (Bundle.main.bundleIdentifier ?? "") + ".proxy" }
    var isInstallable: Bool {
        Bundle.main.object(forInfoDictionaryKey: "SplitWebRoutingBuild") as? Bool == true
    }
    private var isLocal: Bool {
        Bundle.main.object(forInfoDictionaryKey: "SplitWebEngineSHA") != nil
    }
    var isProxyMode: Bool { Bundle.main.object(forInfoDictionaryKey: "SplitWebProxyOverlaySHA") != nil }
    var canRoute: Bool { isInstallable || isLocal }
    var canConfigureSystemTimeZone: Bool { isLocal }
    private var systemTimeZone: String? { UserDefaults.standard.string(forKey: SystemTimeZoneCommand.preference) }
    private var asksForPassword: Bool { UserDefaults.standard.object(forKey: "askPasswordForRules") as? Bool ?? true }
    var startTitle: String {
        isProxyMode && !proxyPermission && !asksForPassword ? "Разрешить и включить" : "Включить правила"
    }
    var wantsRouting: Bool { isLocal ? tun != nil : enabled }
    var rulesLocked: Bool {
        busy || wantsRouting || (isInstallable && ![.invalid, .disconnected].contains(connection))
    }
    var isRouting: Bool { (isLocal ? enabled : connection == .connected) && !busy }
    var hasAssignedApps: Bool { routeGroups.groups.contains { !$0.apps.isEmpty } }
    var status: String {
        if isLocal {
            if busy {
                if tun?.stopping == true { return "Восстанавливаем системные маршруты…" }
                if preparingPermission { return "Подтверди настройку SplitWeb в окне macOS" }
                return isProxyMode && proxyPermission
                    ? "Применяем сетевые настройки…" : "Может потребоваться пароль Mac"
            }
            if enabled {
                if isProxyMode {
                    return routeGroups.rules.contains(where: \.usesTUNInProxyMode)
                        ? "Правила включены · полная изоляция (TUN)" : "Правила включены · HTTP и HTTPS"
                }
                return "Правила включены для новых соединений"
            }
            if wantsRouting { return "Ожидаем активное подключение…" }
            return "Правила выключены"
        }
        if !isInstallable { return "Предпросмотр · правила сохранены на этом Mac" }
        if awaitingApproval { return "Ожидает разрешения в Системных настройках" }
        if busy { return "Применяем правила…" }
        if isRouting { return "Правила включены для новых соединений" }
        if enabled { return "Расширение сети пока не подключено" }
        return "Правила выключены"
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

    func save(_ group: RouteGroup, credentials: ProxyCredentials?, apps: [GroupApp]) async throws {
        guard !rulesLocked else { throw TunConfiguration.failure("Сначала выключи сетевые правила.") }
        if let identifier = group.timeZoneIdentifier, TimeZone(identifier: identifier) == nil {
            throw TunConfiguration.failure("Выбери доступный часовой пояс.")
        }
        guard credentials == nil || (!isInstallable && credentials?.isValid(for: group.route.kind) == true) else {
            throw TunConfiguration.failure("Проверь логин и пароль прокси.")
        }
        var group = group
        let groupID = group.id
        let previousID = routeGroups.groups.first { $0.id == groupID }?.route.proxyCredentialID
        group.route.proxyCredentialID = credentials == nil ? nil : groupID
        var updated = routeGroups
        updated.save(group, assigning: apps)
        guard credentials != nil || previousID != nil else {
            try store(updated)
            return
        }
        try await storeAfterKeychainChange(updated) {
            if let credentials { try credentials.save(groupID) }
            else if let previousID { try ProxyCredentials.remove(previousID) }
        }
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
        guard let id = routeGroups.groups.first(where: { $0.id == groupID })?.route.proxyCredentialID else {
            updateGroups { $0.removeGroup(groupID) }
            return
        }
        Task {
            guard !rulesLocked else { return }
            var updated = routeGroups
            updated.removeGroup(groupID)
            do { try await storeAfterKeychainChange(updated) { try ProxyCredentials.remove(id) } }
            catch { self.error = error.localizedDescription }
        }
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
            guard enabled || !rulesLocked else { return }
            apply(routeGroups, enable: !enabled)
        }
    }

    @discardableResult
    func beginTermination() -> Bool {
        terminating = true
        return stopLocal()
    }

    @discardableResult
    func stopLocal() -> Bool {
        guard let tun else { return false }
        busy = true
        tun.stop()
        return true
    }

    func setProxyPermission(_ allowed: Bool) {
        guard isProxyMode, !rulesLocked else { return }
        busy = true
        error = nil
        preparingPermission = true
        Task {
            defer {
                proxyPermission = ProxyPermission.isInstalled
                preparingPermission = false
                busy = false
            }
            do {
                try await Task.detached(priority: .userInitiated) { try ProxyPermission.setInstalled(allowed) }.value
                UserDefaults.standard.set(!allowed, forKey: "askPasswordForRules")
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
        let systemTimeZone = self.systemTimeZone
        let asksForPassword = self.asksForPassword
        Task {
            let process = ProcessInfo.processInfo
            // Keep status updates timely while the menu bar panel is closed.
            let activity = process.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
                                                 reason: "SplitWebOnMac routing")
            defer {
                process.endActivity(activity)
                tun = nil
                enabled = false
                preparingPermission = false
                proxyPermission = ProxyPermission.isInstalled
                busy = false
            }
            do {
                let configuration = try await Task.detached(priority: .userInitiated) { () -> LocalRoutingConfiguration in
                    if useProxy { return .proxy(try ProxyRoutingConfiguration.make(rules: savedRules)) }
                    return .tun(try TunConfiguration.make(rules: savedRules))
                }.value
                if case .proxy = configuration,
                   ProxyPermission.isInstalled || !asksForPassword, !ProxyPermission.matchesCurrentBuild {
                    preparingPermission = true
                    try await Task.detached(priority: .userInitiated) { try ProxyPermission.setInstalled(true) }.value
                    proxyPermission = ProxyPermission.isInstalled
                    preparingPermission = false
                }
                guard !terminating else { return }
                let session = try TunSession(configuration: configuration, timeZone: systemTimeZone)
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
        do { try store(updated) }
        catch { self.error = error.localizedDescription }
    }

    private func loadManager() async throws -> NETransparentProxyManager? {
        try await NETransparentProxyManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == extensionID
        }
    }

    private func store(_ updated: RouteGroups) throws {
        store(updated, data: try updated.encoded())
    }

    private func storeAfterKeychainChange(_ updated: RouteGroups,
                                          change: @escaping @Sendable () throws -> Void) async throws {
        let data = try updated.encoded()
        busy = true
        defer { busy = false }
        try await Task.detached(priority: .userInitiated, operation: change).value
        store(updated, data: data)
    }

    private func store(_ updated: RouteGroups, data: Data) {
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
                try await proxy.loadFromPreferences()
                if enable && [.invalid, .disconnected].contains(proxy.connection.status) {
                    try proxy.connection.startVPNTunnel()
                }
                if !enable { proxy.connection.stopVPNTunnel() }
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
