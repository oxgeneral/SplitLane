import AppKit
import Security
import SwiftUI
import UniformTypeIdentifiers

@MainActor
func pickGroupApps() async -> [GroupApp]? {
    let panel = NSOpenPanel()
    panel.directoryURL = URL(fileURLWithPath: "/Applications")
    panel.allowedContentTypes = [.applicationBundle]
    panel.allowsMultipleSelection = true
    panel.message = "Выбери приложения для этой сетевой группы."
    panel.prompt = "Выбрать"

    let response: NSApplication.ModalResponse = await withCheckedContinuation { continuation in
        let completed: (NSApplication.ModalResponse) -> Void = { continuation.resume(returning: $0) }
        if let window = NSApp.keyWindow, !window.isSheet {
            panel.beginSheetModal(for: window, completionHandler: completed)
        } else {
            panel.begin(completionHandler: completed)
        }
    }
    return response == .OK ? await groupApps(from: panel.urls) : nil
}

func groupApps(from urls: [URL], knownApps: [GroupApp] = []) async -> [GroupApp] {
    let ownID = Bundle.main.bundleIdentifier
    return await Task.detached(priority: .userInitiated) { () -> [GroupApp] in
        let knownByPath = Dictionary(uniqueKeysWithValues: knownApps.map { ($0.path, $0) })
        return urls.compactMap { url in
            guard url.isFileURL else { return nil }
            if let known = knownByPath[url.path] { return known }
            let resolved = url.resolvingSymlinksInPath()
            if let known = knownByPath[resolved.path] { return known }
            guard resolved.pathExtension == "app", let bundle = Bundle(url: resolved),
                  let identifier = bundle.bundleIdentifier,
                  identifier != ownID, identifier != "local.splitwebonmac.amnezia" else { return nil }

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
    @State private var selectingTimeZone = false
    @State private var didChooseCategory = false
    @State private var credentials = ProxyCredentials()
    @State private var credentialsLoaded = false
    @State private var saving = false
    @State private var errorMessage: String?
    @State private var selectedApps: [GroupApp] = []
    @State private var choosingApps = false
    @State private var invalidSelection = false
    let editing: Bool
    let save: (RouteGroup, ProxyCredentials?, [GroupApp]) async throws -> Void

    let networksLoaded: Bool
    let interfaces: [NetworkChoice]
    let vpns: [NetworkChoice]
    let vpnApps: [NetworkChoice]
    let connectedVPNApps: Set<String>
    let connectedVPNProfiles: Set<String>
    let supportsWireGuard: Bool
    let supportsAmnezia: Bool
    let supportsProxyCredentials: Bool
    let supportsUDPBlocking: Bool
    let usesSystemUDPFilter: Bool
    let supportsGroupTUN: Bool

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
                case .wireguard: group.route = Route(kind: .wireguard)
                }
            }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(editing ? "Настройки группы" : "Новая сетевая группа")
                .font(.title2.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
                .padding(16)

            Divider()

            Form {
                Section("Подключение") {
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
                        Text("Выбери выход в интернет для приложений этой группы.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                if !editing { applicationSection }
                Section {
                    if editing {
                        advancedFields
                    } else {
                        DisclosureGroup("Дополнительные настройки") { advancedFields }
                    }
                }
            }
            .formStyle(.grouped)

            if let errorMessage {
                Text(errorMessage)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
            }

            Divider()

            HStack(spacing: 10) {
                Spacer()
                Button("Отмена") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(editing ? "Сохранить" : "Создать группу") {
                    saving = true
                    errorMessage = nil
                    let auth = group.route.kind.isProxy && !credentials.isEmpty ? credentials : nil
                    var updated = group
                    updated.name = group.name.trimmingCharacters(in: .whitespacesAndNewlines)
                    let apps = selectedApps
                    Task {
                        defer { saving = false }
                        do {
                            if updated.route.kind == .wireguard {
                                let route = updated.route
                                try await Task.detached(priority: .userInitiated) {
                                    _ = try WireGuardProfile.read(URL(fileURLWithPath: route.target),
                                                                  tag: "wireguard", interface: route.interface ?? "")
                                }.value
                            }
                            try await save(updated, auth, apps)
                            dismiss()
                        } catch {
                            errorMessage = error.localizedDescription
                        }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!canSave || choosingApps)
            }
            .padding(16)
        }
        .frame(width: 470, height: 480)
        .disabled(saving)
        .task {
            guard supportsProxyCredentials, let id = group.route.proxyCredentialID else { return }
            do {
                let stored = try await Task.detached(priority: .userInitiated) { try ProxyCredentials.load(id) }.value
                guard !Task.isCancelled, group.route.proxyCredentialID == id else { return }
                if credentials.isEmpty { credentials = stored }
                credentialsLoaded = true
            } catch {
                guard !Task.isCancelled, group.route.proxyCredentialID == id else { return }
                errorMessage = error.localizedDescription
            }
        }
        .fileImporter(isPresented: $selectingProfile, allowedContentTypes: [UTType(filenameExtension: "conf") ?? .data]) {
            if case .success(let url) = $0 { group.route.target = url.path }
        }
    }

    private var applicationSection: some View {
        Section("Приложения") {
            ForEach(selectedApps) { app in
                HStack {
                    AppIcon(path: app.path)
                    Text(app.name)
                    Spacer()
                    Button {
                        selectedApps.removeAll { $0.id == app.id }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Убрать \(app.name)")
                }
            }
            Button {
                choosingApps = true
                Task {
                    defer { choosingApps = false }
                    guard let apps = await pickGroupApps() else { return }
                    invalidSelection = apps.isEmpty
                    for app in apps where !selectedApps.contains(where: { $0.id == app.id }) {
                        selectedApps.append(app)
                    }
                }
            } label: {
                Label("Выбрать приложения…", systemImage: "plus")
            }
            .disabled(choosingApps)
            if invalidSelection {
                Text("Выбери приложение .app. Сам SplitWebOnMac в группу добавить нельзя.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if selectedApps.isEmpty {
                Text("Добавь хотя бы одно приложение, чтобы сразу включить правила.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var advancedFields: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField("Название группы", text: $group.name, prompt: Text("По названию выхода"))
            if supportsGroupTUN {
                Toggle("Перехватывать трафик через TUN", isOn: Binding(
                    get: { group.usesTUNInProxyMode },
                    set: { group.useTUN = $0 }
                ))
                Text("Применяет маршрут группы к приложениям, которые подключаются в обход системного прокси. Для новых соединений.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            udpProtection
            timeZoneField
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
                physicalNetworkHint
            } else if group.route.kind == .amnezia {
                Text("Нужна сборка AmneziaVPN с режимом для SplitWeb. Пока её выход закрыт, запросы группы будут блокироваться.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if !networksLoaded {
                ProgressView("Ищем VPN…").controlSize(.small)
            } else if vpnApps.isEmpty && vpns.isEmpty && !supportsAmnezia {
                Text(supportsWireGuard
                     ? "Добавь профиль в VPN-приложении и подключись. Если у тебя есть файл .conf, выбери «Отдельный WireGuard»."
                     : "Добавь профиль в VPN-приложении и подключись.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if !group.route.target.isEmpty, !(group.route.kind == .vpn
                        ? connectedVPNProfiles : connectedVPNApps).contains(group.route.target) {
                Text("Этот VPN сейчас отключён. Подключи его в VPN-приложении перед проверкой маршрута.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var proxyFields: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("Протокол", selection: $group.route.kind) {
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
            if group.route.proxyEndpoint == nil && (!group.route.target.isEmpty || !group.route.port.isEmpty) {
                Text("Укажи имя сервера или IP-адрес и порт от 1 до 65535.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if supportsProxyCredentials {
                HStack(alignment: .top, spacing: 10) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Логин").font(.caption).foregroundStyle(.secondary).accessibilityHidden(true)
                        TextField("Логин", text: $credentials.username)
                            .labelsHidden()
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Пароль").font(.caption).foregroundStyle(.secondary).accessibilityHidden(true)
                        SecureField("Пароль", text: $credentials.password)
                            .labelsHidden()
                    }
                }
                .textFieldStyle(.roundedBorder)
                Text("Оставь оба поля пустыми, если прокси без авторизации.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var directFields: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Сеть", selection: $group.route.target) {
                Text("Выбери сеть").tag("")
                if !group.route.target.isEmpty, !interfaces.contains(where: { $0.id == group.route.target }) {
                    Text("Прежняя сеть недоступна").tag(group.route.target)
                }
                ForEach(interfaces) { choice in Text(choice.name).tag(choice.id) }
            }
            physicalNetworkHint
        }
    }

    @ViewBuilder
    private var physicalNetworkHint: some View {
        if !networksLoaded {
            ProgressView("Ищем сетевые интерфейсы…").controlSize(.small)
        } else if interfaces.isEmpty {
            Text("Подключись к Wi‑Fi или Ethernet и выбери сеть.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var udpProtection: some View {
        let udpRoute = group.usesTUNInProxyMode
            ? "При выключении UDP идёт через TUN. Выход группы должен поддерживать UDP."
            : "При выключении UDP использует сеть macOS."
        return VStack(alignment: .leading, spacing: 5) {
            Toggle("Защита от утечек WebRTC", isOn: Binding(
                get: { group.blockUDP ?? supportsUDPBlocking },
                set: { group.blockUDP = $0 }
            ))
            .toggleStyle(.switch)
            .disabled(!supportsUDPBlocking && group.blockUDP != true)

            Text(usesSystemUDPFilter
                 ? "Блокирует исходящий UDP группы, включая WebRTC и HTTP/3. \(udpRoute)"
                 : supportsUDPBlocking
                    ? "Блокирует UDP приложений группы. При выключении UDP использует сеть macOS."
                    : "В этой сборке WebRTC может обходить маршрут группы.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var timeZoneField: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text("Часовой пояс")
                Spacer()
                Button {
                    selectingTimeZone.toggle()
                } label: {
                    Label(group.timeZoneIdentifier ?? "Системный", systemImage: "chevron.up.chevron.down")
                }
                .accessibilityLabel("Часовой пояс, \(group.timeZoneIdentifier ?? "системный")")
                .popover(isPresented: $selectingTimeZone, arrowEdge: .bottom) {
                    TimeZonePicker(selection: $group.timeZoneIdentifier) { selectingTimeZone = false }
                }
            }
            if group.timeZoneIdentifier != nil {
                Text("Нажми «Открыть с поясом» рядом с приложением в SplitWeb. Настройка передаётся при новом запуске.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var canSave: Bool {
        switch group.route.kind {
        case .direct: interfaces.contains { $0.id == group.route.target }
        case .vpnApp: vpnApps.contains { $0.id == group.route.target }
        case .amnezia: supportsAmnezia
        case .vpn: vpns.contains { $0.id == group.route.target }
        case .wireguard: supportsWireGuard && group.route.isValid && interfaces.contains { $0.id == group.route.interface }
        case .socks5, .http, .https:
            group.route.isValid && (credentials.isEmpty
                ? group.route.proxyCredentialID == nil || credentialsLoaded
                : supportsProxyCredentials && credentials.isValid(for: group.route.kind))
        }
    }
}

struct TimeZonePicker: View {
    @Binding var selection: String?
    var defaultTitle = "Системный"
    var includesUTC = true
    let dismiss: () -> Void
    @State private var search = ""
    @FocusState private var searchFocused: Bool

    private static let knownIdentifiers = TimeZone.knownTimeZoneIdentifiers.sorted()
    private static let identifiersWithUTC = Set(knownIdentifiers).union(["UTC"]).sorted()

    var body: some View {
        let identifiers = includesUTC ? Self.identifiersWithUTC : Self.knownIdentifiers
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let matches = query.isEmpty ? identifiers : identifiers.filter { identifier in
            identifier.localizedStandardContains(query) ||
                identifier.replacingOccurrences(of: "_", with: " ").localizedStandardContains(query)
        }

        VStack(alignment: .leading, spacing: 8) {
            TextField("Поиск по городу, например New York", text: $search)
                .textFieldStyle(.roundedBorder)
                .focused($searchFocused)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    if query.isEmpty { option(defaultTitle, identifier: nil) }
                    ForEach(matches, id: \.self) { option($0, identifier: $0) }
                    if matches.isEmpty {
                        Text("Часовой пояс не найден")
                            .foregroundStyle(.secondary)
                            .padding(6)
                    }
                }
            }
            .frame(height: 224)
        }
        .padding(12)
        .frame(width: 300)
        .onAppear { searchFocused = true }
    }

    private func option(_ title: String, identifier: String?) -> some View {
        Button {
            selection = identifier
            dismiss()
        } label: {
            HStack {
                Text(title)
                Spacer()
                if selection == identifier { Image(systemName: "checkmark") }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selection == identifier ? .isSelected : [])
    }
}
