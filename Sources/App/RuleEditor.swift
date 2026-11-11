import AppKit
import Security
import SwiftUI
import UniformTypeIdentifiers

@MainActor
func pickGroupApps() async -> [GroupApp] {
    let panel = NSOpenPanel()
    panel.directoryURL = URL(fileURLWithPath: "/Applications")
    panel.allowedContentTypes = [.applicationBundle]
    panel.allowsMultipleSelection = true
    panel.message = "Выбери приложения для этой сетевой группы."
    panel.prompt = "Выбрать"

    let response: NSApplication.ModalResponse = await withCheckedContinuation { continuation in
        let completed: (NSApplication.ModalResponse) -> Void = { continuation.resume(returning: $0) }
        if let window = NSApp.keyWindow {
            panel.beginSheetModal(for: window, completionHandler: completed)
        } else {
            panel.begin(completionHandler: completed)
        }
    }
    guard response == .OK else { return [] }
    let urls = panel.urls
    let ownID = Bundle.main.bundleIdentifier
    return await Task.detached(priority: .userInitiated) { () -> [GroupApp] in
        urls.compactMap { url in
            let resolved = url.resolvingSymlinksInPath()
            guard let bundle = Bundle(url: resolved), let identifier = bundle.bundleIdentifier,
                  identifier != ownID else { return nil }

            var code: SecStaticCode?
            var signingInfo: CFDictionary?
            if SecStaticCodeCreateWithPath(resolved as CFURL, [], &code) == errSecSuccess, let code {
                SecCodeCopySigningInformation(code, [], &signingInfo)
            }
            let signingID = (signingInfo as? [String: Any])?[kSecCodeInfoIdentifier as String] as? String ?? identifier
            let name = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ??
                FileManager.default.displayName(atPath: resolved.path).replacingOccurrences(of: ".app", with: "")
            return GroupApp(name: name, path: resolved.path, signingID: signingID)
        }
    }.value
}

struct GroupEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var group: RouteGroup
    @State private var selectingProfile = false
    @State private var didChooseCategory = false
    let editing: Bool
    let save: (RouteGroup) -> Void

    let interfaces: [NetworkChoice]
    let vpns: [NetworkChoice]
    let vpnApps: [NetworkChoice]
    let connectedVPNApps: Set<String>
    let supportsWireGuard: Bool
    let supportsAmnezia: Bool

    private enum Category: String, CaseIterable {
        case vpn = "VPN"
        case proxy = "Прокси"
        case direct = "Напрямую"
    }

    private enum VPNChoice: Hashable {
        case none
        case app(String)
        case amnezia
        case profile(String)
        case wireguard
    }

    private var category: Category {
        switch group.route.kind {
        case .direct: .direct
        case .vpnApp, .vpn, .wireguard, .amnezia: .vpn
        case .http, .https, .socks5: .proxy
        }
    }

    private var categorySelection: Binding<Category?> {
        Binding(
            get: { editing || didChooseCategory ? category : nil },
            set: { selection in
                guard let selection else { return }
                didChooseCategory = true
                if selection != category {
                    switch selection {
                    case .direct: group.route = Route(kind: .direct)
                    case .vpn: group.route = Route(kind: .vpnApp)
                    case .proxy: group.route = Route(kind: .socks5)
                    }
                }
                if selection == .direct, group.route.target.isEmpty {
                    group.route.target = interfaces.first?.id ?? ""
                }
            }
        )
    }

    private var vpnSelection: Binding<VPNChoice> {
        Binding(
            get: {
                switch group.route.kind {
                case .vpnApp where !group.route.target.isEmpty: .app(group.route.target)
                case .vpn where !group.route.target.isEmpty: .profile(group.route.target)
                case .amnezia: .amnezia
                case .wireguard: .wireguard
                default: .none
                }
            },
            set: { choice in
                switch choice {
                case .none: group.route = Route(kind: .vpnApp)
                case .app(let id): group.route = Route(kind: .vpnApp, target: id)
                case .profile(let id): group.route = Route(kind: .vpn, target: id)
                case .amnezia: group.route = Route(kind: .amnezia)
                case .wireguard:
                    group.route = Route(kind: .wireguard, interface: interfaces.first(where: {
                        $0.name.hasPrefix("Wi-Fi")
                    })?.id ?? interfaces.first?.id)
                }
            }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 5) {
                Text(editing ? "Настройки группы" : "Новая сетевая группа")
                    .font(.title2.weight(.semibold))
                Text("У всех приложений в группе будет один сетевой выход.")
                    .foregroundStyle(.secondary)
            }

            TextField("Название группы", text: $group.name, prompt: Text("По названию выхода"))
                .textFieldStyle(.roundedBorder)

            Picker("Способ подключения", selection: categorySelection) {
                ForEach(Category.allCases, id: \.self) { category in
                    Text(category.rawValue).tag(Optional(category))
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            if let selection = categorySelection.wrappedValue {
                switch selection {
                case .vpn: vpnFields
                case .proxy: proxyFields
                case .direct: directFields
                }
            } else {
                Text("Выбери выход для группы, затем добавь приложения.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Divider()

            HStack(spacing: 10) {
                Spacer()
                Button("Отмена") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(editing ? "Сохранить" : "Создать группу") {
                    group.name = group.name.trimmingCharacters(in: .whitespacesAndNewlines)
                    save(group)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
            }
        }
        .padding(24)
        .frame(width: 440)
        .fileImporter(isPresented: $selectingProfile, allowedContentTypes: [UTType(filenameExtension: "conf") ?? .data]) {
            if case .success(let url) = $0 { group.route.target = url.path }
        }
    }

    private var vpnFields: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("Через", selection: vpnSelection) {
                Text("Выбери VPN").tag(VPNChoice.none)
                if case .app(let id) = vpnSelection.wrappedValue, !vpnApps.contains(where: { $0.id == id }) {
                    Text("Прежнее приложение недоступно").tag(VPNChoice.app(id))
                }
                if case .profile(let id) = vpnSelection.wrappedValue, !vpns.contains(where: { $0.id == id }) {
                    Text("Прежний профиль недоступен").tag(VPNChoice.profile(id))
                }
                ForEach(vpnApps) { choice in
                    Text(choice.name).tag(VPNChoice.app(choice.id))
                }
                if supportsAmnezia || group.route.kind == .amnezia {
                    Text("AmneziaVPN · отдельный выход").tag(VPNChoice.amnezia)
                }
                if !vpns.isEmpty {
                    Section("Профили macOS") {
                        ForEach(vpns) { choice in
                            Text("\(choice.name) · профиль").tag(VPNChoice.profile(choice.id))
                        }
                    }
                }
                if supportsWireGuard || group.route.kind == .wireguard {
                    Text("Отдельный WireGuard").tag(VPNChoice.wireguard)
                }
            }
            if group.route.kind == .wireguard {
                Button(group.route.target.isEmpty ? "Выбрать файл WireGuard" :
                        URL(fileURLWithPath: group.route.target).lastPathComponent) { selectingProfile = true }
                Picker("Сеть для подключения", selection: Binding(
                    get: { group.route.interface ?? "" },
                    set: { group.route.interface = $0 }
                )) {
                    Text("Выбери сеть").tag("")
                    ForEach(interfaces) { choice in Text(choice.name).tag(choice.id) }
                }
            } else if group.route.kind == .amnezia {
                Text("Нужна сборка AmneziaVPN с режимом для SplitWeb. Пока её выход закрыт, запросы группы будут блокироваться.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if vpnApps.isEmpty && vpns.isEmpty && !supportsAmnezia {
                Text("Подключи VPN в его приложении, чтобы добавить доступный маршрут.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if group.route.kind == .vpn ||
                        (!group.route.target.isEmpty && !connectedVPNApps.contains(group.route.target)) {
                Text("Если VPN выключен, подключи его в VPN-приложении.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var proxyFields: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("Тип", selection: $group.route.kind) {
                ForEach([RouteKind.socks5, .http, .https]) { kind in
                    Text(kind.title).tag(kind)
                }
            }
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Адрес").font(.caption).foregroundStyle(.secondary).accessibilityHidden(true)
                    TextField("Адрес", text: $group.route.target, prompt: Text("proxy.example.com"))
                        .labelsHidden()
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Порт").font(.caption).foregroundStyle(.secondary).accessibilityHidden(true)
                    TextField("Порт", text: $group.route.port, prompt: Text("1080"))
                        .labelsHidden()
                        .monospacedDigit()
                }
                .frame(width: 72)
            }
            .textFieldStyle(.roundedBorder)
        }
    }

    private var directFields: some View {
        Picker("Сеть", selection: $group.route.target) {
            Text("Выбери сеть").tag("")
            if !group.route.target.isEmpty, !interfaces.contains(where: { $0.id == group.route.target }) {
                Text("Прежняя сеть недоступна").tag(group.route.target)
            }
            ForEach(interfaces) { choice in Text(choice.name).tag(choice.id) }
        }
    }

    private var canSave: Bool {
        switch group.route.kind {
        case .direct: interfaces.contains { $0.id == group.route.target }
        case .vpnApp: vpnApps.contains { $0.id == group.route.target }
        case .amnezia: supportsAmnezia
        case .vpn: vpns.contains { $0.id == group.route.target }
        case .wireguard: supportsWireGuard && group.route.isValid && interfaces.contains { $0.id == group.route.interface }
        case .socks5, .http, .https: group.route.isValid
        }
    }
}
