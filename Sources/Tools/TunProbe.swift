import Foundation

@main
struct TunProbe {
    static func main() {
        do {
            try writeConfiguration()
        } catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    private static func writeConfiguration() throws {
        let config = try TunConfiguration.make(rules: appRules(), probe: true)
        FileHandle.standardOutput.write(config.data)
    }

    private static func appRules() throws -> [AppRule] {
        let args = Array(CommandLine.arguments.dropFirst())
        if args == ["--saved-rules"] {
            let defaults = UserDefaults(suiteName: "local.splitlane.preview")
            guard let defaults, let groups = try? RouteGroups.load(from: defaults),
                  !groups.rules.isEmpty else {
                throw TunConfiguration.failure("Сначала добавь правила в окне SplitLane.")
            }
            return groups.rules
        }
        guard args.isEmpty,
              let wifi = physicalInterfaces().first(where: { $0.name.hasPrefix("Wi-Fi") }),
              let happ = vpnProfiles().first(where: { $0.name == "Happ" }) else {
            throw TunConfiguration.failure("Для этой пробы нужны Wi-Fi и профиль Happ.")
        }
        return [
            AppRule(name: "Chrome", path: "/Applications/Google Chrome.app", signingID: "com.google.Chrome",
                    route: Route(kind: .direct, target: wifi.id)),
            AppRule(name: "Safari", path: "/Applications/Safari.app", signingID: "com.apple.Safari",
                    route: Route(kind: .vpn, target: happ.id)),
            AppRule(name: "Codex", path: "/Applications/Codex.app", signingID: "com.openai.codex",
                    route: Route(kind: .socks5, target: "127.0.0.1", port: "10808"))
        ]
    }

}
