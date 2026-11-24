import AppKit
import NetworkExtension
import SwiftUI
import UniformTypeIdentifiers

@main
struct SplitLaneApp {
    @MainActor
    static func main() {
        let app = NSApplication.shared
        let delegate = SplitLaneDelegate()
        app.delegate = delegate

        let menu = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "SplitLane")
        appMenu.addItem(withTitle: "Выйти из SplitLane", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        menu.addItem(appItem)

        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Правка")
        edit.addItem(withTitle: "Вырезать", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Копировать", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Вставить", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Выделить всё", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        menu.addItem(editItem)
        app.mainMenu = menu

        withExtendedLifetime(delegate) { app.run() }
    }
}

@MainActor
private final class SplitLaneDelegate: NSObject, NSApplicationDelegate {
    private let router = Router()
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let panel = NSPopover()
    private var mainWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem.button?.image = NSImage(systemSymbolName: "arrow.triangle.branch", accessibilityDescription: "SplitLane")
        statusItem.button?.toolTip = "SplitLane"
        statusItem.button?.target = self
        statusItem.button?.action = #selector(togglePanel)

        panel.behavior = .semitransient
        Task {
            for _ in 0..<20 {
                if showPanel() { return }
                try? await Task.sleep(for: .milliseconds(50))
            }
            showMainWindow()
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !showPanel() { showMainWindow() }
        return false
    }

    func applicationWillTerminate(_ notification: Notification) {
        router.stopLocal()
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard router.beginTermination() else { return .terminateNow }
        Task {
            let deadline = ContinuousClock.now + .seconds(15)
            while router.wantsRouting && ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(100))
            }
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    @objc private func togglePanel() {
        if panel.isShown {
            panel.performClose(nil)
        } else {
            showPanel()
        }
    }

    @discardableResult
    private func showPanel() -> Bool {
        if let mainWindow, mainWindow.isVisible {
            mainWindow.makeKeyAndOrderFront(nil)
            NSApp.activate()
            return true
        }
        if panel.isShown { return true }
        guard let button = statusItem.button, let window = button.window, let screen = window.screen else { return false }
        let anchor = window.convertToScreen(button.convert(button.bounds, to: nil))
        let center = NSPoint(x: anchor.midX, y: anchor.midY)
        // The status item starts with a provisional frame until macOS places it in the menu bar.
        guard screen.frame.contains(center), center.y >= screen.frame.maxY - anchor.height else { return false }
        let top = min(anchor.minY, screen.visibleFrame.maxY)
        let maxHeight = top - screen.visibleFrame.minY - 16
        let routes = RoutesView(router: router, maxHeight: maxHeight)
        if let host = panel.contentViewController as? NSHostingController<RoutesView> {
            host.rootView = routes
        } else {
            panel.contentViewController = NSHostingController(rootView: routes)
        }
        panel.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        NSApp.activate()
        if let panelWindow = panel.contentViewController?.view.window {
            panelWindow.setFrameTopLeftPoint(NSPoint(x: panelWindow.frame.minX, y: top))
            panelWindow.makeKey()
        }
        return panel.isShown
    }

    private func showMainWindow() {
        if mainWindow == nil {
            let screen = NSScreen.main?.visibleFrame.height ?? 600
            let host = NSHostingController(rootView: RoutesView(router: router, maxHeight: screen - 48))
            let window = NSWindow(contentViewController: host)
            window.title = "SplitLane"
            window.styleMask = [.titled, .closable]
            window.isReleasedWhenClosed = false
            window.center()
            mainWindow = window
        }
        mainWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate()
    }
}

struct AppIcon: View {
    let path: String

    var body: some View {
        Image(nsImage: NSWorkspace.shared.icon(forFile: path))
            .resizable()
            .frame(width: 24, height: 24)
            .accessibilityHidden(true)
    }
}

private struct GroupAppLabel: View {
    let app: GroupApp
    let locked: Bool
    @State private var hovered = false

    var body: some View {
        if locked {
            label
        } else {
            label
                .onHover { hovered = $0 }
                .overlay {
                    if hovered {
                        RoundedRectangle(cornerRadius: 5)
                            .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
                            .allowsHitTesting(false)
                    }
                }
                .onDrag {
                    let provider = NSItemProvider()
                    provider.registerObject(URL(fileURLWithPath: app.path) as NSURL, visibility: .ownProcess)
                    return provider
                } preview: {
                    Label(app.name, systemImage: "app")
                        .padding(8)
                }
                .help("Перетащи в другую группу")
        }
    }

    private var label: some View {
        HStack(spacing: 8) {
            AppIcon(path: app.path)
            Text(app.name).lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
    }
}

struct RoutesView: View {
    @ObservedObject var router: Router
    let maxHeight: CGFloat
    @AppStorage("hasEnabledRouting") private var hasEnabledRouting = false
    @State private var selection: RouteGroup?
    @State private var choosingApp = false
    @State private var dropTarget: UUID?
    @State private var invalidAppMessage: String?
    @State private var networks = NetworkChoices()
    @State private var appLaunchError: String?
    @State private var appRestart: (app: GroupApp, identifier: String, running: NSRunningApplication)?
    @State private var launchingApps: Set<String> = []
    @State private var editingSystemTimeZone = false

    var body: some View {
        ViewThatFits(in: .vertical) {
            panelContents { groupList }
            panelContents {
                ScrollView { groupList }
                    .scrollIndicators(.never)
            }
            .frame(height: maxHeight)
        }
        .frame(maxHeight: maxHeight, alignment: .top)
        .fixedSize(horizontal: false, vertical: true)
        .frame(width: 550)
        .background(Color(nsColor: .windowBackgroundColor))
        .alert("Не удалось добавить приложения", isPresented: Binding(
            get: { invalidAppMessage != nil },
            set: { if !$0 { invalidAppMessage = nil } }
        ), presenting: invalidAppMessage) { _ in
            Button("OK", role: .cancel) {}
        } message: { message in
            Text(message)
        }
        .alert("Не удалось открыть приложение", isPresented: Binding(
            get: { appLaunchError != nil },
            set: { if !$0 { appLaunchError = nil } }
        ), presenting: appLaunchError) { _ in
            Button("OK", role: .cancel) {}
        } message: { error in
            Text(error)
        }
        .alert("Перезапустить приложение?", isPresented: Binding(
            get: { appRestart != nil },
            set: { if !$0 { appRestart = nil } }
        ), presenting: appRestart) { request in
            Button("Перезапустить") {
                launch(request.app, timeZoneIdentifier: request.identifier, restarting: request.running)
            }
            Button("Отмена", role: .cancel) {}
        } message: { request in
            Text("«\(request.app.name)» уже открыто. Сохрани работу перед перезапуском с часовым поясом \(request.identifier).")
        }
        .sheet(item: $selection) { group in
            GroupEditor(group: group, editing: router.routeGroups.groups.contains { $0.id == group.id }, save: router.save,
                        networksLoaded: networks.loaded,
                        interfaces: networks.interfaces, vpns: networks.vpns, vpnApps: networks.vpnApps,
                        connectedVPNApps: networks.connectedVPNApps, connectedVPNProfiles: networks.connectedProfiles,
                        supportsWireGuard: router.isProxyMode,
                        supportsAmnezia: !router.canRoute || (router.isProxyMode &&
                            (bundledAmnezia != nil || networks.amneziaReady || group.route.kind == .amnezia)),
                        supportsProxyCredentials: !router.isInstallable,
                        supportsUDPBlocking: router.isInstallable || router.isProxyMode,
                        usesSystemUDPFilter: router.isProxyMode, supportsGroupTUN: router.isProxyMode)
        }
        .sheet(isPresented: $editingSystemTimeZone) { SystemTimeZoneEditor() }
        .task { await router.refresh() }
        .task {
            while !Task.isCancelled {
                // SystemConfiguration can wait on network services, including during sheet layout.
                let updated = await Task.detached(priority: .utility) { NetworkChoices.load() }.value
                guard !Task.isCancelled else { return }
                if networks != updated { networks = updated }
                try? await Task.sleep(for: .seconds(3))
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in
            router.updateConnectionStatus()
        }
        .onChange(of: router.isRouting, initial: true) { _, isRouting in
            if isRouting { hasEnabledRouting = true }
        }
    }

    private func panelContents<Content: View>(@ViewBuilder list: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            list()
            Divider()
            defaultRoute
            Divider()
            footer
        }
        .padding(16)
    }

    @ViewBuilder
    private var groupList: some View {
        if router.routeGroups.groups.isEmpty {
            ContentUnavailableView {
                Label("Настрой первую сетевую группу", systemImage: "arrow.triangle.branch")
            } description: {
                Text("Выбери Wi‑Fi, Ethernet, VPN или прокси и добавь приложения, которые будут использовать этот выход.")
            } actions: {
                Button("Создать группу") { selection = RouteGroup() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut("n", modifiers: .command)
                    .disabled(router.rulesLocked)
            }
            .frame(maxWidth: .infinity, minHeight: 180)
        } else {
            VStack(spacing: 0) {
                ForEach(router.routeGroups.groups) { group in
                    Divider()
                    groupSection(group)
                }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Text("Сетевые группы")
                .font(.title2.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            Spacer(minLength: 0)
            if choosingApp {
                ProgressView().controlSize(.small).accessibilityLabel("Выбор приложения")
            }
            if !router.routeGroups.groups.isEmpty {
                Button {
                    selection = RouteGroup()
                } label: {
                    Label("Новая группа", systemImage: "plus")
                }
                .buttonStyle(.bordered)
                .keyboardShortcut("n", modifiers: .command)
                .disabled(choosingApp || router.rulesLocked)
                .help(router.rulesLocked ? "Выключи правила, чтобы изменить список" : "Создать сетевую группу")
            }
        }
    }

    private func groupSection(_ group: RouteGroup) -> some View {
        let destination = describe(group.route)
        let title = group.name.isEmpty ? destination.name : group.name
        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: routeSymbol(group.route.kind))
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(.secondary)
                    .frame(width: 24)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.headline).lineLimit(1).accessibilityAddTraits(.isHeader)
                    let details = group.name.isEmpty ? destination.hint : [destination.name, destination.hint]
                        .compactMap { $0 }.joined(separator: " · ")
                    if let details {
                        HStack(spacing: 4) {
                            if destination.unavailable {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                                    .accessibilityHidden(true)
                            }
                            Text(details).foregroundStyle(.secondary).lineLimit(2)
                        }
                        .font(.caption)
                    }
                    if router.isProxyMode {
                        if group.usesTUNInProxyMode && group.blocksUDPInProxyMode {
                            Label("TUN · защита WebRTC", systemImage: "arrow.triangle.branch")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else if group.usesTUNInProxyMode {
                            Label("TUN · UDP открыт", systemImage: "arrow.triangle.branch")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else if group.blocksUDPInProxyMode {
                            Label("HTTP/HTTPS · защита WebRTC", systemImage: "shield")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            Label("Только HTTP и HTTPS", systemImage: "exclamationmark.triangle")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let identifier = group.timeZoneIdentifier {
                        Label(identifier, systemImage: "clock")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .accessibilityLabel("Часовой пояс \(identifier)")
                    }
                }
                Spacer(minLength: 0)
                if group.route.kind == .amnezia, let amnezia = bundledAmnezia {
                    Button("Открыть") {
                        Task {
                            do { _ = try await NSWorkspace.shared.openApplication(at: amnezia, configuration: .init()) }
                            catch { appLaunchError = "AmneziaVPN. \(error.localizedDescription)" }
                        }
                    }
                    .fixedSize()
                    .accessibilityLabel("Открыть AmneziaVPN")
                    .help("Открыть AmneziaVPN")
                }
                Button {
                    choosingApp = true
                    Task {
                        defer { choosingApp = false }
                        guard let apps = await pickGroupApps() else { return }
                        if apps.isEmpty {
                            invalidAppMessage = "Выбери приложение .app. Сам SplitLane в группу добавить нельзя."
                        } else {
                            router.assign(apps, to: group.id)
                        }
                    }
                } label: {
                    Label("Добавить приложения", systemImage: "plus")
                }
                .controlSize(.small)
                .disabled(choosingApp || router.rulesLocked)
                .help("Выбранное приложение будет перемещено в эту группу, если уже состоит в другой")
                Menu {
                    Button("Изменить группу") { selection = group }
                    Button("Удалить группу", role: .destructive) { router.removeGroup(group.id) }
                } label: {
                    Image(systemName: "ellipsis.circle").font(.system(size: 15))
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel("Настройки группы \(title)")
                .disabled(router.rulesLocked)
            }
            if group.apps.isEmpty {
                Text(router.rulesLocked ? "Нет приложений" : "Перетащи сюда приложения")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.leading, 32)
            } else {
                ForEach(group.apps) { app in
                    HStack(spacing: 8) {
                        GroupAppLabel(app: app, locked: router.rulesLocked)
                        if let identifier = group.timeZoneIdentifier {
                            Button("Открыть с поясом") {
                                launch(app, timeZoneIdentifier: identifier)
                            }
                            .buttonStyle(.borderless)
                            .disabled(launchingApps.contains(app.id))
                            .accessibilityLabel("Открыть \(app.name) с часовым поясом")
                            .help("Запустить с часовым поясом \(identifier)")
                        }
                        Button {
                            router.removeApp(app.id, from: group.id)
                        } label: {
                            Image(systemName: "minus.circle")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Убрать \(app.name) из группы")
                        .help("Приложение вернётся к текущей сети macOS")
                        .disabled(router.rulesLocked)
                    }
                    .padding(.leading, 16)
                }
            }
        }
        .padding(.vertical, 8)
        .background(dropTarget == group.id ? Color.accentColor.opacity(0.15) : .clear,
                    in: RoundedRectangle(cornerRadius: 8))
        .contentShape(Rectangle())
        .onDrop(of: router.rulesLocked || choosingApp ? [] : [.fileURL], isTargeted: Binding(
            get: { dropTarget == group.id },
            set: { targeted in
                if targeted { dropTarget = group.id }
                else if dropTarget == group.id { dropTarget = nil }
            }
        )) { providers in
            dropApps(providers, into: group.id)
        }
    }

    private func dropApps(_ providers: [NSItemProvider], into groupID: UUID) -> Bool {
        guard !router.rulesLocked, !choosingApp, !providers.isEmpty else { return false }
        choosingApp = true
        dropTarget = nil
        let transfers = providers.map { provider in
            AsyncStream<URL> { stream in
                _ = provider.loadObject(ofClass: NSURL.self) { item, _ in
                    if let url = item as? URL { stream.yield(url) }
                    stream.finish()
                }
            }
        }
        Task {
            defer { choosingApp = false }
            var urls: [URL] = []
            for transfer in transfers {
                for await url in transfer { urls.append(url) }
            }
            let apps = await groupApps(from: urls, knownApps: router.routeGroups.groups.flatMap(\.apps))
            if apps.isEmpty {
                invalidAppMessage = "Перетащи файлы .app из Finder. Сам SplitLane в группу добавить нельзя."
            } else {
                router.assign(apps, to: groupID)
            }
        }
        return true
    }

    private func launch(_ app: GroupApp, timeZoneIdentifier: String, restarting: NSRunningApplication? = nil) {
        launchingApps.insert(app.id)
        Task {
            defer { launchingApps.remove(app.id) }
            do {
                try await app.open(timeZoneIdentifier: timeZoneIdentifier, restarting: restarting)
            } catch GroupAppLaunchError.alreadyRunning(let running) {
                appRestart = (app, timeZoneIdentifier, running)
            } catch {
                appLaunchError = error.localizedDescription
            }
        }
    }

    private var bundledAmnezia: URL? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/AmneziaVPN for SplitLane.app")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    private func routeSymbol(_ kind: RouteKind) -> String {
        switch kind {
        case .direct: "network"
        case .vpn, .vpnApp, .wireguard, .amnezia: "lock.shield"
        case .http, .https, .socks5: "arrow.left.arrow.right"
        }
    }

    private var defaultRoute: some View {
        HStack(spacing: 8) {
            Image(systemName: "network")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
                .frame(width: 24)
                .accessibilityHidden(true)
            Text("Всё остальное").font(.headline)
            Spacer(minLength: 0)
            Text(networks.systemNetwork ?? "Текущая сеть macOS")
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .accessibilityElement(children: .combine)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error = router.error {
                Label {
                    Text(error)
                } icon: {
                    Image(systemName: "exclamationmark.circle").foregroundStyle(.orange)
                }
                .font(.callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 12) {
                Label {
                    Text(router.status).foregroundStyle(.secondary)
                } icon: {
                    Image(systemName: router.isRouting ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(router.isRouting ? Color.green : .secondary)
                }
                .font(.callout)
                Spacer(minLength: 0)
                Menu {
                    if router.canConfigureSystemTimeZone {
                        Button("Часовой пояс Mac…") { editingSystemTimeZone = true }
                            .disabled(router.rulesLocked)
                        Divider()
                    }
                    if router.isProxyMode {
                        Button(router.proxyPermission ? "Отозвать разрешение на запуск без пароля…" :
                                   "Разрешить включение правил без пароля…") {
                            router.setProxyPermission(!router.proxyPermission)
                        }
                        .disabled(router.rulesLocked)
                        Divider()
                    }
                    Button("Выйти из SplitLane") { NSApp.terminate(nil) }
                } label: {
                    Image(systemName: "gearshape")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel("Настройки SplitLane")
                .help("Настройки SplitLane")
                if router.recoveryPending {
                    Button("Восстановить сеть") { router.recoverLocalNetwork() }
                        .buttonStyle(.borderedProminent)
                        .disabled(router.busy)
                } else if router.canRoute && (router.wantsRouting || router.hasAssignedApps) {
                    Button(router.wantsRouting ? "Выключить правила" : router.startTitle) {
                        router.toggle()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(router.busy || (!router.wantsRouting && router.rulesLocked))
                }
            }
            if router.recoveryPending && !router.busy {
                Text("Остались настройки предыдущего сеанса. Восстановление снимет аварийную блокировку и вернёт системные настройки.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if router.isRouting {
                Text("Правила действуют для новых соединений. Если приложение уже было открыто, перезапусти его.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if router.isProxyMode && !hasEnabledRouting && router.hasAssignedApps &&
                        !router.busy && !router.wantsRouting && router.error == nil {
                Text("При включении правил macOS может запросить пароль администратора для временной настройки сети.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func describe(_ route: Route) -> (name: String, hint: String?, unavailable: Bool) {
        switch route.kind {
        case .direct:
            let network = networks.interfaces.first { $0.id == route.target }
            return (network?.name ?? route.target,
                    networks.loaded && network == nil ? "Сеть недоступна" : "Напрямую",
                    networks.loaded && network == nil)
        case .vpnApp, .vpn:
            let application = route.kind == .vpnApp
            let choices = application ? networks.vpnApps : networks.vpns
            let connected = application ? networks.connectedVPNApps : networks.connectedProfiles
            let choice = choices.first { $0.id == route.target }
            let missing = networks.loaded && choice == nil
            let disconnected = networks.loaded && !missing && !connected.contains(route.target)
            return (choice?.name ?? "VPN",
                    missing ? "Недоступен" : disconnected ? "VPN отключён" : "VPN",
                    missing || disconnected)
        case .wireguard:
            return (URL(fileURLWithPath: route.target).lastPathComponent, "Отдельный WireGuard", false)
        case .amnezia:
            return ("AmneziaVPN", networks.amneziaReady ? "Локальный выход открыт" : "Ожидает отдельное подключение",
                    networks.loaded && !networks.amneziaReady)
        case .http, .https, .socks5:
            let host = route.target.contains(":") && !route.target.hasPrefix("[") ? "[\(route.target)]" : route.target
            return ("\(host):\(route.port)", "Прокси · \(route.kind.title)", false)
        }
    }
}

private struct NetworkChoices: Equatable, Sendable {
    var loaded = false
    var interfaces: [NetworkChoice] = []
    var vpns: [NetworkChoice] = []
    var vpnApps: [NetworkChoice] = []
    var connectedProfiles: Set<String> = []
    var connectedVPNApps: Set<String> = []
    var systemNetwork: String?
    var amneziaReady = false

    static func load() -> NetworkChoices {
        let interfaces = physicalInterfaces()
        let vpns = vpnProfiles()
        let vpnApps = vpnApplications()
        let profileInterfaces = Dictionary(uniqueKeysWithValues: vpns.compactMap { choice in
            vpnInterface(profileID: choice.id).map { (choice.id, $0) }
        })
        let appInterfaces = Dictionary(uniqueKeysWithValues: vpnApps.compactMap { choice -> (String, Set<String>)? in
            let active = vpnApplicationInterfaces(bundleID: choice.id)
            return active.isEmpty ? nil : (choice.id, active)
        })
        let systemNetwork = DefaultNetwork.describeCurrent(interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
                                                           profileInterfaces: profileInterfaces,
                                                           appInterfaces: appInterfaces)
        return NetworkChoices(loaded: true, interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
                              connectedProfiles: Set(profileInterfaces.keys), connectedVPNApps: Set(appInterfaces.keys),
                              systemNetwork: systemNetwork, amneziaReady: amneziaRelayReady())
    }

    private static func amneziaRelayReady() -> Bool {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/SplitLane/amnezia.sock")
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let count = withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            let path = Array(url.path.utf8CString)
            guard path.count <= buffer.count else { return 0 }
            buffer.copyBytes(from: path.map { UInt8(bitPattern: $0) })
            return path.count
        }
        guard count > 0 else { return false }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { return false }
        let length = socklen_t(MemoryLayout<sockaddr_un>.offset(of: \.sun_path)! + count)
        address.sun_len = UInt8(length)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, length) }
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        return result == 0 && getpeereid(fd, &uid, &gid) == 0 && uid == geteuid()
    }
}
