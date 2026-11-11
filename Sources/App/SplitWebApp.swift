import AppKit
import NetworkExtension
import SwiftUI

@main
struct SplitWebApp: App {
    @StateObject private var router = Router()

    var body: some Scene {
        Window("SplitWebOnMac", id: "routes") {
            RoutesView(router: router)
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 620, height: 460)
    }
}

struct AppIcon: View {
    let path: String

    var body: some View {
        Image(nsImage: NSWorkspace.shared.icon(forFile: path))
            .resizable()
            .frame(width: 36, height: 36)
            .accessibilityHidden(true)
    }
}

struct RoutesView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var router: Router
    @State private var selection: RouteGroup?
    @State private var choosingApp = false
    @State private var networks = NetworkChoices()
    @State private var amneziaLaunchFailed = false

    private var palette: RoutePalette { RoutePalette(dark: scheme == .dark) }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header

            ScrollView {
                if router.routeGroups.groups.isEmpty {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Все приложения используют текущую сеть").font(.headline)
                        Text("Создай группу для приложений, которым нужен свой выход в интернет.")
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, minHeight: 104, alignment: .leading)
                    .padding(.horizontal, 16)
                    .background(palette.surface, in: RoundedRectangle(cornerRadius: 10))
                } else {
                    LazyVStack(spacing: 10) {
                        ForEach(router.routeGroups.groups, content: groupCard)
                    }
                }
            }
            .frame(minHeight: 110)

            defaultRoute
            footer
        }
        .padding(22)
        .frame(minWidth: 560, minHeight: 360)
        .background(palette.canvas)
        .alert("Не удалось открыть AmneziaVPN", isPresented: $amneziaLaunchFailed) {
            Button("OK", role: .cancel) {}
        }
        .sheet(item: $selection) { group in
            GroupEditor(group: group, editing: router.routeGroups.groups.contains { $0.id == group.id }, save: router.save,
                        interfaces: networks.interfaces, vpns: networks.vpns, vpnApps: networks.vpnApps,
                        connectedVPNApps: networks.connectedVPNApps, supportsWireGuard: router.isProxyMode,
                        supportsAmnezia: router.isProxyMode || !router.canRoute)
        }
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
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
            router.stopLocal()
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Сетевые группы").font(.system(size: 30, weight: .semibold, design: .rounded))
                    .accessibilityAddTraits(.isHeader)
                Text("Один выход в интернет для приложений в каждой группе.")
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if choosingApp {
                ProgressView().controlSize(.small).accessibilityLabel("Выбор приложения")
            }
            Button {
                selection = RouteGroup()
            } label: {
                Label("Новая группа", systemImage: "plus")
            }
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
            .tint(palette.signal)
            .keyboardShortcut("n", modifiers: .command)
            .disabled(choosingApp || router.rulesLocked)
            .help(router.rulesLocked ? "Выключи правила, чтобы изменить список" : "Создать сетевую группу")
        }
    }

    private func groupCard(_ group: RouteGroup) -> some View {
        let destination = describe(group.route)
        let title = group.name.isEmpty ? destination.name : group.name
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .font(.system(size: 19, weight: .medium))
                    .foregroundStyle(palette.signal)
                    .frame(width: 30)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.headline).lineLimit(1)
                    let details = group.name.isEmpty ? destination.hint : [destination.name, destination.hint]
                        .compactMap { $0 }.joined(separator: " · ")
                    if let details {
                        Text(details)
                            .font(.caption)
                            .foregroundStyle(destination.unavailable ? palette.attention : .secondary)
                            .lineLimit(2)
                    }
                }
                Spacer(minLength: 0)
                if group.route.kind == .amnezia, let amnezia = bundledAmnezia {
                    Button("Открыть") {
                        Task {
                            do { _ = try await NSWorkspace.shared.openApplication(at: amnezia, configuration: .init()) }
                            catch { amneziaLaunchFailed = true }
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
                        router.assign(await pickGroupApps(), to: group.id)
                    }
                } label: {
                    Label("Добавить приложения", systemImage: "plus")
                }
                .disabled(choosingApp || router.rulesLocked)
                .help("Выбранное приложение будет перемещено в эту группу, если уже состоит в другой")
                Menu {
                    Button("Изменить группу") { selection = group }
                    Button("Удалить группу", role: .destructive) { router.removeGroup(group.id) }
                } label: {
                    Image(systemName: "ellipsis.circle").font(.title3)
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel("Настройки группы \(title)")
                .disabled(router.rulesLocked)
            }
            if group.apps.isEmpty {
                Text("В группе пока нет приложений.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                Divider()
                ForEach(group.apps) { app in
                    HStack(spacing: 10) {
                        AppIcon(path: app.path)
                        Text(app.name).lineLimit(1)
                        Spacer()
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
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(palette.surface, in: RoundedRectangle(cornerRadius: 10))
    }

    private var bundledAmnezia: URL? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/AmneziaVPN for SplitWeb.app")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    private var connector: some View {
        Image(systemName: "arrow.right")
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(palette.signal)
            .frame(width: 30)
            .accessibilityHidden(true)
    }

    private var defaultRoute: some View {
        HStack(spacing: 10) {
            Image(systemName: "network")
                .font(.system(size: 18, weight: .medium))
                .foregroundStyle(palette.signal)
                .frame(width: 36, height: 36)
                .background(palette.signal.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                .accessibilityHidden(true)

            Text("Всё остальное")
                .font(.headline)
                .frame(minWidth: 90, maxWidth: .infinity, alignment: .leading)

            connector

            VStack(alignment: .leading, spacing: 3) {
                Text(networks.systemNetwork ?? "Текущая сеть macOS")
                    .font(.headline)
                    .lineLimit(1)
                Text("Маршрут по умолчанию")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(minWidth: 145, maxWidth: .infinity, alignment: .leading)
            Color.clear.frame(width: 25, height: 1).accessibilityHidden(true)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(palette.channel, in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error = router.error {
                Label(error, systemImage: "exclamationmark.circle")
                    .font(.callout)
                    .foregroundStyle(palette.attention)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 12) {
                Label(router.status, systemImage: router.isRouting ? "checkmark.circle.fill" : "circle")
                    .font(.callout)
                    .foregroundStyle(router.isRouting ? palette.active : .secondary)
                Spacer(minLength: 0)
                if router.isProxyMode {
                    Menu {
                        Button(router.proxyPermission ? "Отозвать разрешение на запуск без пароля…" :
                                   "Разрешить включение правил без пароля…") {
                            router.setProxyPermission(!router.proxyPermission)
                        }
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .accessibilityLabel("Настройки запуска")
                    .help("Настройки запуска")
                    .disabled(router.rulesLocked)
                }
                if router.canRoute && (router.wantsRouting || router.hasAssignedApps) {
                    Button(router.wantsRouting ? "Выключить правила" : "Включить правила") {
                        router.toggle()
                    }
                    .disabled(router.busy)
                }
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
                    missing ? "VPN недоступен" : disconnected ? "VPN отключён" : "VPN",
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

private struct RoutePalette {
    let dark: Bool

    var canvas: Color { color(0xEDF2F5, 0x181F28) }
    var surface: Color { color(0xFCFDFF, 0x202C39) }
    var channel: Color { color(0xDDEAF2, 0x26384A) }
    var signal: Color { color(0x15548A, 0x91BEED) }
    var active: Color { color(0x126652, 0x79CBAE) }
    var attention: Color { color(0x93491E, 0xF6B382) }

    private func color(_ light: UInt32, _ darkValue: UInt32) -> Color {
        let rgb = dark ? darkValue : light
        return Color(red: Double((rgb >> 16) & 255) / 255,
                     green: Double((rgb >> 8) & 255) / 255, blue: Double(rgb & 255) / 255)
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
        let appInterfaces = Dictionary(uniqueKeysWithValues: vpnApps.compactMap { choice in
            vpnApplicationInterface(bundleID: choice.id).map { (choice.id, $0) }
        })
        // A VPN can redirect traffic with two half-routes while leaving the default entry intact.
        let routeInterfaces = ["1.0.0.1", "208.67.222.222"].compactMap { address -> String? in
            let route = try? runCommand("/sbin/route", ["-n", "get", "-inet", address])
            return route?.split(whereSeparator: \.isNewline).lazy.compactMap { row -> String? in
                let parts = row.split(whereSeparator: \.isWhitespace)
                guard parts.count == 2, parts[0] == "interface:" else { return nil }
                return String(parts[1])
            }.first
        }
        let systemInterface = routeInterfaces.count == 2 && routeInterfaces.first == routeInterfaces.last
            ? routeInterfaces.first : nil
        let systemVPN = vpnApps.first { appInterfaces[$0.id] == systemInterface && systemInterface != nil }
            ?? vpns.first { profileInterfaces[$0.id] == systemInterface && systemInterface != nil }
        let systemNetwork = systemVPN.map { "VPN \($0.name)" }
            ?? interfaces.first { $0.id == systemInterface }?.name
        return NetworkChoices(loaded: true, interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
                              connectedProfiles: Set(profileInterfaces.keys), connectedVPNApps: Set(appInterfaces.keys),
                              systemNetwork: systemNetwork, amneziaReady: amneziaRelayReady())
    }

    private static func amneziaRelayReady() -> Bool {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/SplitWebOnMac/amnezia.sock")
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
