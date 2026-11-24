import Foundation

struct GroupApp: Identifiable, Codable, Equatable, Sendable {
    var id: String { path }
    let name: String
    let path: String
    let signingID: String
}

struct RouteGroup: Identifiable, Codable, Equatable, Sendable {
    var id = UUID()
    var name = ""
    var route = Route()
    var apps: [GroupApp] = []
    var blockUDP: Bool?
    var useTUN: Bool?
    var timeZoneIdentifier: String?

    var blocksUDPInProxyMode: Bool { blockUDP != false }
    var usesTUNInProxyMode: Bool { useTUN != false }
}

struct RouteGroups: Codable, Equatable, Sendable {
    private(set) var groups: [RouteGroup] = []
    static let defaultsKey = "networkGroups"

    var rules: [AppRule] {
        groups.flatMap { group in
            group.apps.map {
                AppRule(name: $0.name, path: $0.path, signingID: $0.signingID,
                        route: group.route, blockUDP: group.blockUDP, useTUN: group.useTUN)
            }
        }
    }

    init() {}

    init(legacyRules: [AppRule]) {
        for rule in legacyRules {
            let app = GroupApp(name: rule.name, path: rule.path, signingID: rule.signingID)
            if let index = groups.firstIndex(where: {
                $0.route == rule.route && $0.blockUDP == rule.blockUDP && $0.useTUN == rule.useTUN
            }) {
                groups[index].apps.append(app)
            } else {
                groups.append(RouteGroup(route: rule.route, apps: [app], blockUDP: rule.blockUDP, useTUN: rule.useTUN))
            }
        }
    }

    mutating func save(_ group: RouteGroup, assigning apps: [GroupApp] = []) {
        if let index = groups.firstIndex(where: { $0.id == group.id }) {
            groups[index] = group
        } else {
            groups.append(group)
        }
        for app in apps { assign(app, to: group.id) }
    }

    mutating func assign(_ app: GroupApp, to groupID: UUID) {
        guard let target = groups.firstIndex(where: { $0.id == groupID }),
              !groups[target].apps.contains(where: { $0.id == app.id }) else { return }
        for index in groups.indices where index != target {
            groups[index].apps.removeAll { $0.id == app.id }
        }
        groups[target].apps.append(app)
    }

    mutating func removeApp(_ appID: String, from groupID: UUID) {
        guard let index = groups.firstIndex(where: { $0.id == groupID }) else { return }
        groups[index].apps.removeAll { $0.id == appID }
    }

    mutating func removeGroup(_ groupID: UUID) {
        groups.removeAll { $0.id == groupID }
    }

    static func load(from defaults: UserDefaults) throws -> RouteGroups {
        if let data = defaults.data(forKey: defaultsKey) {
            let value = try JSONDecoder().decode(Self.self, from: data)
            try value.validate()
            return value
        }
        let legacy = try defaults.data(forKey: RuleConfiguration.defaultsKey).map(RuleConfiguration.decode) ?? []
        return RouteGroups(legacyRules: legacy)
    }

    func encoded() throws -> Data {
        try validate()
        return try JSONEncoder().encode(self)
    }

    private func validate() throws {
        guard Set(groups.map(\.id)).count == groups.count,
              groups.allSatisfy({ $0.route.isValid &&
                  ($0.route.proxyCredentialID == nil || $0.route.proxyCredentialID == $0.id) }) else {
            throw TunConfiguration.failure("Проверь выходы сетевых групп.")
        }
        try RuleConfiguration.validate(rules)
    }
}
