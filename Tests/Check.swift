import Foundation
import Network

@main
struct Check {
    static func main() throws {
        let route = Route(kind: .socks5, target: "127.0.0.1", port: "1080")
        precondition(route.proxyEndpoint == .hostPort(host: "127.0.0.1", port: 1080))
        precondition(Route(kind: .https, target: "[::1]", port: "65535").isValid)
        precondition(!Route(kind: .socks5, target: "user:secret@example.com", port: "1080").isValid)
        precondition(!Route(kind: .http, target: "example.com", port: "0").isValid)
        precondition(!Route(kind: .http, target: "example.com", port: "65536").isValid)
        precondition(tcpParameters(for: Route(kind: .vpn, target: "missing"), interfaces: []) == nil)
        precondition(tcpParameters(for: Route(kind: .vpnApp, target: "com.test.missing-vpn"), interfaces: []) == nil)
        precondition(tcpParameters(for: Route(kind: .direct, target: "en0"), interfaces: []) == nil)
        let app = AppRule(name: "Browser", path: "/Applications/Browser.app", signingID: "com.test.browser")
        precondition(AppRule.match(signingID: "helper", executablePath: app.path + "/Contents/helper", rules: [app]) == app)
        precondition(AppRule.match(signingID: "helper", executablePath: app.path + "-other/Contents/helper", rules: [app]) == nil)
        precondition(AppRule.match(signingID: app.signingID, executablePath: "/tmp/fake", rules: [app]) == nil)
        precondition(AppRule.match(signingID: app.signingID, executablePath: nil, rules: [app]) == app)
        var configured = app
        configured.route = route
        let encoded = try RuleConfiguration.encode([configured])
        let restored = try RuleConfiguration.decode(encoded)
        precondition(restored == [configured])
        configured.route = Route(kind: .vpnApp, target: "com.test.vpn")
        let savedVPN = try RuleConfiguration.decode(RuleConfiguration.encode([configured]))
        precondition(savedVPN == [configured])
        precondition((try? RuleConfiguration.encode([configured, configured])) == nil)
        precondition((try? RuleConfiguration.encode([app])) == nil)

        let secondApp = AppRule(name: "Editor", path: "/Applications/Editor.app", signingID: "com.test.editor",
                                route: configured.route)
        var groups = RouteGroups(legacyRules: [configured, secondApp])
        precondition(groups.groups.count == 1 && groups.rules == [configured, secondApp])
        let oldGroup = groups.groups[0]
        let newGroup = RouteGroup(name: "Прокси", route: route)
        groups.save(newGroup)
        groups.assign(oldGroup.apps[1], to: newGroup.id)
        groups.assign(oldGroup.apps[1], to: newGroup.id)
        precondition(groups.groups.map(\.apps.count) == [1, 1])
        precondition(groups.rules[1].route == route)
        let restoredGroups = try JSONDecoder().decode(RouteGroups.self, from: groups.encoded())
        precondition(restoredGroups == groups)
        groups.removeApp(secondApp.path, from: oldGroup.id)
        precondition(groups == restoredGroups)
        groups.removeGroup(newGroup.id)
        precondition(groups.rules == [configured])
        var duplicateGroup = RouteGroup(route: route)
        duplicateGroup.apps = oldGroup.apps
        groups.save(duplicateGroup)
        precondition((try? groups.encoded()) == nil)
        precondition(VPNTransport.socketAddress("192.0.2.5:443") == "192.0.2.5")
        precondition(VPNTransport.socketAddress("[2001:db8::1]:443") == "2001:db8::1")
        precondition(VPNTransport.socketAddress("example.com:443") == nil)
        precondition(VPNTransport.subnetPrefix("255.255.252.0") == 22)
        precondition(VPNTransport.subnetPrefix("255.0.255.0") == nil)
        precondition((try? TunConfiguration.make(rules: [])) == nil)
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        let profile = """
            [Interface]
            PrivateKey = \(key)
            Address = 10.76.3.1/30
            DNS = 10.76.3.2
            [Peer]
            PublicKey = \(key)
            Endpoint = [::1]:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            PersistentKeepalive = 25
            """
        let wireGuard = try WireGuardProfile(contents: profile, tag: "second-vpn", interface: "en0")
        precondition(wireGuard.dns == "10.76.3.2")
        precondition(wireGuard.endpoint["system"] as? Bool == false)
        precondition(wireGuard.endpoint["bind_interface"] as? String == "en0")
        precondition((try? WireGuardProfile(contents: profile + "\nPostUp = unexpected", tag: "invalid", interface: "en0")) == nil)
        print("Route checks passed.")
    }
}
