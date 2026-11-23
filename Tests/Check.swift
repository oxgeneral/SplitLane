import Foundation
import Network

@main
struct Check {
    static func main() throws {
        checkProxyOverlayRecovery()
        try ProxyPermissionCheck.run()
        NetworkAdaptationCheck.run()
        let route = Route(kind: .socks5, target: "127.0.0.1", port: "1080")
        precondition(route.proxyEndpoint == .hostPort(host: "127.0.0.1", port: 1080))
        let credentials = ProxyCredentials(username: "proxy-user", password: "p:a@ss")
        precondition([RouteKind.socks5, .http, .https].allSatisfy { credentials.isValid(for: $0) })
        precondition(!ProxyCredentials(username: "proxy-user").isValid(for: .socks5))
        precondition(ProxyCredentials(username: "proxy-user").isValid(for: .http))
        precondition(!ProxyCredentials(username: "user:name", password: "pass").isValid(for: .http))
        precondition(!ProxyCredentials(username: "user", password: String(repeating: "я", count: 128)).isValid(for: .socks5))
        var authenticated = RouteGroup(route: route)
        authenticated.route.proxyCredentialID = authenticated.id
        var authenticatedGroups = RouteGroups()
        authenticatedGroups.save(authenticated)
        let savedGroups = try authenticatedGroups.encoded()
        let decodedGroups = try JSONDecoder().decode(RouteGroups.self, from: savedGroups)
        precondition(decodedGroups == authenticatedGroups)
        precondition(!String(decoding: savedGroups, as: UTF8.self).contains(credentials.password))
        precondition(tcpParameters(for: authenticated.route, interfaces: []) == nil)
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
        precondition(restored[0].blockUDP == nil && restored[0].blocksUDPInExtension)
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
        precondition(restoredGroups.groups.allSatisfy { $0.timeZoneIdentifier == nil })
        precondition(restoredGroups.groups.allSatisfy { $0.useTUN == nil })
        var zonedGroups = restoredGroups
        var zonedGroup = newGroup
        zonedGroup.apps = restoredGroups.groups[1].apps
        zonedGroup.timeZoneIdentifier = "America/New_York"
        zonedGroups.save(zonedGroup)
        let zonedReloaded = try JSONDecoder().decode(RouteGroups.self, from: zonedGroups.encoded())
        precondition(zonedReloaded == zonedGroups)
        precondition(zonedReloaded.rules == restoredGroups.rules)
        precondition(restoredGroups.groups.allSatisfy { $0.blockUDP == nil })
        var protectedGroups = restoredGroups
        var protectedGroup = protectedGroups.groups[1]
        protectedGroup.blockUDP = true
        protectedGroups.save(protectedGroup)
        let persisted = try JSONDecoder().decode(RouteGroups.self, from: protectedGroups.encoded())
        let protectedRules = try RuleConfiguration.decode(RuleConfiguration.encode(persisted.rules))
        precondition(persisted == protectedGroups && protectedRules.map(\.blockUDP) == [nil, true])
        precondition(protectedRules[1].blocksUDPInExtension)
        precondition((try? RuleConfiguration.validateLocalUDPPolicy(protectedRules)) == nil)
        precondition((try? TunConfiguration.make(rules: protectedRules, probe: true)) == nil)
        protectedGroup.blockUDP = false
        protectedGroups.save(protectedGroup)
        let unprotectedRules = try RuleConfiguration.decode(RuleConfiguration.encode(protectedGroups.rules))
        precondition(unprotectedRules[1].blockUDP == false && !unprotectedRules[1].blocksUDPInExtension)
        try RuleConfiguration.validateLocalUDPPolicy(unprotectedRules)
        let safariURL = URL(fileURLWithPath: "/Applications/Safari.app").resolvingSymlinksInPath()
        if Bundle(url: safariURL)?.executableURL != nil {
            let safariCanonical = try canonicalAppBundlePath(for: "/Applications/Safari.app", name: "Safari")
            precondition(safariCanonical == safariURL.path && safariCanonical.hasSuffix(".app"))

            // Default nil flags in proxy mode enable full isolation (TUN + WebRTC/UDP blocking).
            let defaultSafari = AppRule(name: "Safari", path: safariURL.path, signingID: "com.apple.Safari", route: route)
            precondition(defaultSafari.usesTUNInProxyMode && defaultSafari.blocksUDPInProxyMode)
            let defaultProxy = try ProxyRoutingConfiguration.make(rules: [defaultSafari])
            precondition(defaultProxy.packetRules.count == 1 &&
                         defaultProxy.packetRules[0].path == safariURL.path &&
                         defaultProxy.packetRules[0].blockUDP == true &&
                         defaultProxy.packetRules[0].relayID != nil)

            // Explicit opt-out of TUN keeps only UDP blocking when blockUDP is true.
            var safari = AppRule(name: "Safari", path: safariURL.path, signingID: "com.apple.Safari",
                                 route: route, blockUDP: true, useTUN: false)
            let protectedProxy = try ProxyRoutingConfiguration.make(rules: [safari])
            precondition(protectedProxy.packetRules == [PacketRoutingRule(path: safariURL.path, blockUDP: true, relayID: nil)])
            safari.blockUDP = false
            let unprotectedProxy = try ProxyRoutingConfiguration.make(rules: [safari])
            precondition(unprotectedProxy.packetRules.isEmpty && unprotectedProxy.data == protectedProxy.data)

            var tunGroup = RouteGroup(route: route, apps: [GroupApp(name: safari.name, path: safari.path, signingID: safari.signingID)],
                                      useTUN: true)
            var tunGroups = RouteGroups()
            for blockUDP in [nil, false, true] as [Bool?] {
                tunGroup.blockUDP = blockUDP
                tunGroups.save(tunGroup)
                let loaded = try JSONDecoder().decode(RouteGroups.self, from: tunGroups.encoded())
                precondition(loaded.rules[0].useTUN == true && loaded.rules[0].blockUDP == blockUDP)
                let expectsBlock = blockUDP != false
                let proxy = try ProxyRoutingConfiguration.make(rules: loaded.rules)
                precondition(proxy.packetRules[0].blockUDP == expectsBlock)
                let relayID = proxy.packetRules[0].relayID!.uuidString
                let proxyJSON = try JSONSerialization.jsonObject(with: proxy.data) as! [String: Any]
                let proxyRules = (proxyJSON["route"] as! [String: Any])["rules"] as! [[String: Any]]
                precondition(proxyRules.first?["inbound"] as? String == PacketRoutingConfiguration.relayTag &&
                             proxyRules.first?["auth_user"] as? String == relayID &&
                             proxyRules.first?["outbound"] as? String == "app-0")
                precondition(proxyRules.contains {
                    $0["mode"] as? String == "and" && $0["action"] as? String == "reject" &&
                    ($0["rules"] as? [[String: Any]])?.first?["inbound"] as? String == ProxyRoutingConfiguration.proxyTag
                })
                precondition(proxyRules.contains {
                    $0["inbound"] as? String == ProxyRoutingConfiguration.proxyTag &&
                    $0["action"] as? String == "reject" &&
                    ($0["process_path_regex"] as? String)?.contains("WebKit") == true
                })
                precondition(proxyRules.last?["inbound"] as? String == PacketRoutingConfiguration.relayTag &&
                             proxyRules.last?["action"] as? String == "reject")
                let outbounds = proxyJSON["outbounds"] as! [[String: Any]]
                precondition(outbounds.first { $0["tag"] as? String == "app-0" }?["type"] as? String == "socks")
                let tun = try PacketRoutingConfiguration.make(apps: proxy.packetRules)
                let tunJSON = try JSONSerialization.jsonObject(with: tun) as! [String: Any]
                let tunRoute = tunJSON["route"] as! [String: Any]
                let tunRules = tunRoute["rules"] as! [[String: Any]]
                let appRouteIndex = expectsBlock ? 1 : 0
                if expectsBlock {
                    precondition(tunRules[0]["network"] as? String == "udp" && tunRules[0]["action"] as? String == "reject" &&
                                 tunRules[0]["method"] as? String == "drop")
                }
                precondition(tunRules[appRouteIndex]["outbound"] as? String == relayID)
                let unknownUDP = tunRules[appRouteIndex + 1]
                let udpConditions = unknownUDP["rules"] as! [[String: Any]]
                precondition(unknownUDP["action"] as? String == "reject" && unknownUDP["mode"] as? String == "and" &&
                             udpConditions[0]["network"] as? String == "udp" &&
                             udpConditions[1]["process_path_regex"] as? String == ".+" && udpConditions[1]["invert"] as? Bool == true)
                let unknownTCP = tunRules[appRouteIndex + 2]
                let tcpConditions = unknownTCP["rules"] as! [[String: Any]]
                precondition(unknownTCP["action"] as? String == "reject" && unknownTCP["mode"] as? String == "and" &&
                             tcpConditions[0]["network"] as? String == "tcp" &&
                             tcpConditions[1]["process_path_regex"] as? String == ".+" && tcpConditions[1]["invert"] as? Bool == true)
                let unknownWebKitUDP = tunRules[appRouteIndex + 3]
                let webKitPattern = unknownWebKitUDP["process_path_regex"] as! String
                let webKitPath = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
                precondition(unknownWebKitUDP["network"] as? String == "udp" && unknownWebKitUDP["action"] as? String == "reject" &&
                             webKitPath.range(of: webKitPattern, options: .regularExpression) != nil &&
                             (safariURL.path + "/Contents/MacOS/Safari").range(of: webKitPattern, options: .regularExpression) == nil)
                let unknownWebKitTCP = tunRules[appRouteIndex + 4]
                precondition(unknownWebKitTCP["network"] as? String == "tcp" && unknownWebKitTCP["action"] as? String == "reject" &&
                             unknownWebKitTCP["process_path_regex"] as? String == webKitPattern)
                let passthrough = tunRules[appRouteIndex + 5]
                precondition(passthrough["outbound"] as? String == "original-scope")
                let packetOutbounds = tunJSON["outbounds"] as! [[String: Any]]
                precondition(packetOutbounds.first { $0["tag"] as? String == "original-scope" }?["bind_interface"] as? String == "splitweb-original-scope")
                precondition(!packetOutbounds.contains { $0["tag"] as? String == "system" })
                precondition(!tunRules.contains { $0["source_ip_cidr"] != nil })
                precondition(tunRules.count == appRouteIndex + 6 && tunRoute["final"] as? String == "original-scope")
                precondition((tunJSON["inbounds"] as? [[String: Any]])?.first?["auto_route"] as? Bool == false)
            }
            tunGroup.blockUDP = true
            tunGroup.useTUN = false
            tunGroups.save(tunGroup)
            let disabledTUN = try ProxyRoutingConfiguration.make(rules: tunGroups.rules)
            precondition(disabledTUN.packetRules.first?.relayID == nil)

            let finderURL = URL(fileURLWithPath: "/System/Library/CoreServices/Finder.app")
            let finder = AppRule(name: "Finder", path: finderURL.path, signingID: "com.apple.finder",
                                 route: Route(kind: .http, target: "127.0.0.1", port: "1081"), blockUDP: false, useTUN: true)
            safari.useTUN = true
            safari.blockUDP = true
            let combined = try ProxyRoutingConfiguration.make(rules: [safari, finder])
            let relayIDs = Set(combined.packetRules.compactMap(\.relayID))
            precondition(relayIDs.count == 2)
            let combinedJSON = try JSONSerialization.jsonObject(with: combined.data) as! [String: Any]
            let combinedOutbounds = combinedJSON["outbounds"] as! [[String: Any]]
            let combinedProxyRules = (combinedJSON["route"] as! [String: Any])["rules"] as! [[String: Any]]
            let combinedTun = try PacketRoutingConfiguration.make(apps: combined.packetRules.reversed())
            let combinedTunJSON = try JSONSerialization.jsonObject(with: combinedTun) as! [String: Any]
            let combinedTunRules = (combinedTunJSON["route"] as! [String: Any])["rules"] as! [[String: Any]]
            let orderedApps = combined.packetRules.sorted { $0.path.count > $1.path.count }
            precondition(combinedTunRules.compactMap { ($0["outbound"] as? String).flatMap(UUID.init(uuidString:)) } ==
                         orderedApps.compactMap(\.relayID))
            for appRule in orderedApps {
                let relayID = appRule.relayID!.uuidString
                let authRule = combinedProxyRules.first { $0["auth_user"] as? String == relayID }!
                let outbound = combinedOutbounds.first { $0["tag"] as? String == authRule["outbound"] as? String }!
                let isSafari = appRule.path == safariURL.path
                precondition(outbound["server_port"] as? Int == (isSafari ? 1080 : 1081))
                precondition(outbound["type"] as? String == (isSafari ? "socks" : "http"))
                let appRoute = combinedTunRules.first { $0["outbound"] as? String == relayID }!
                let pattern = "^" + NSRegularExpression.escapedPattern(for: appRule.path) + "/"
                precondition(appRoute["process_path_regex"] as? String == pattern && appRoute["outbound"] as? String == relayID)
            }
            let applicationDrops = combinedTunRules.filter {
                $0["action"] as? String == "reject" && ($0["process_path_regex"] as? String)?.hasPrefix("^") == true
            }
            precondition(applicationDrops.count == 1)

            // Verify per-group DNS isolation for both .vpn and .direct routes.
            let profileID = "00000000-0000-0000-0000-000000000000"
            safari.route = Route(kind: .vpn, target: profileID)
            let directIface = physicalInterfaces().first?.id ?? "en0"
            var directFinder = finder
            directFinder.route = Route(kind: .direct, target: directIface)
            let withIsolatedDNS = try ProxyRoutingConfiguration.make(rules: [safari, directFinder])
            let vpnJSON = try JSONSerialization.jsonObject(with: withIsolatedDNS.data) as! [String: Any]
            let vpnOutbounds = vpnJSON["outbounds"] as! [[String: Any]]
            let vpnOutbound = vpnOutbounds.first { $0["bind_interface"] as? String == "splitweb-vpn-service:" + profileID }
            let directOutbound = vpnOutbounds.first { $0["bind_interface"] as? String == directIface }
            precondition(vpnOutbound?["type"] as? String == "direct" && directOutbound?["type"] as? String == "direct")
            let vpnTag = vpnOutbound!["tag"] as! String
            let directTag = directOutbound!["tag"] as! String
            let dnsServers = (vpnJSON["dns"] as! [String: Any])["servers"] as! [[String: Any]]
            let vpnDNS = dnsServers.first { $0["tag"] as? String == "dns-\(vpnTag)" }
            let directDNS = dnsServers.first { $0["tag"] as? String == "dns-\(directTag)" }
            precondition(vpnDNS?["type"] as? String == "https" && vpnDNS?["detour"] as? String == vpnTag)
            precondition(directDNS?["type"] as? String == "local" && directDNS?["bind_interface"] as? String == directIface &&
                         directDNS?["udp_fragment"] as? Bool == true)
            let vpnRelayID = withIsolatedDNS.packetRules.first { $0.path == safariURL.path }?.relayID?.uuidString
            let vpnRules = (vpnJSON["route"] as! [String: Any])["rules"] as! [[String: Any]]
            precondition(vpnRelayID != nil && vpnRules.contains {
                $0["auth_user"] as? String == vpnRelayID && $0["outbound"] as? String == vpnTag
            })
            precondition(vpnRules.contains { $0["action"] as? String == "resolve" && $0["server"] as? String == "dns-\(vpnTag)" })
            precondition(vpnRules.contains { $0["action"] as? String == "resolve" && $0["server"] as? String == "dns-\(directTag)" })
            precondition((try? TunConfiguration.makeOutbound(for: safari)) == nil)
        }
        let blockFilter = PacketRoutingConfiguration.filter(owner: 501, interface: "utun9", capturesTCP: false)
        precondition(!blockFilter.contains("proto tcp"))
        let groupFilter = PacketRoutingConfiguration.filter(owner: 501, interface: "utun9", capturesTCP: true)
        precondition(groupFilter.contains("out quick on utun9 inet proto tcp no state"))
        precondition(groupFilter.contains("out quick on ! lo0 route-to (utun9 172.31.252.2) inet proto tcp"))
        precondition(groupFilter.contains("in quick on utun9 route-to (lo0 ::1) inet6 proto tcp from any to <splitweb_local_addresses> no state"))
        precondition(groupFilter.contains("keep state (if-bound)"))
        precondition(groupFilter.contains("on ! lo0 route-to (utun9 172.31.252.2) inet proto udp"))
        precondition(groupFilter.contains("on ! lo0 route-to (utun9 fd9e:7345:2b1c:252::2) inet6 proto udp"))
        precondition(groupFilter.split(separator: "\n").filter { $0.contains("proto udp") } ==
                     blockFilter.split(separator: "\n").filter { $0.contains("proto udp") })
        for filter in [blockFilter, groupFilter] {
            try checkPacketFilterExpansion(filter)
        }
        checkDefaultNetworkDetection()
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

    static func checkPacketFilterExpansion(_ filter: String) throws {
        let expectedRoutes = filter.split(separator: "\n").filter { $0.contains("route-to") }.count
        for optimizer in [[], ["-o", "none"]] {
            let input = Pipe()
            let output = Pipe()
            let compiler = Process()
            compiler.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
            compiler.arguments = ["-n", "-v", "-a", "com.apple/local.splitwebonmac.test"] + optimizer + ["-f", "-"]
            compiler.standardInput = input
            compiler.standardOutput = output
            compiler.standardError = output
            try compiler.run()
            try input.fileHandleForWriting.write(contentsOf: Data(filter.utf8))
            try input.fileHandleForWriting.close()
            let compiled = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            compiler.waitUntilExit()
            precondition(compiler.terminationStatus == 0, compiled)
            let loadedRoutes = compiled.split(separator: "\n").filter { $0.contains("route-to") }.count
            precondition(loadedRoutes == expectedRoutes, "pfctl expanded \(expectedRoutes) route-to rules to \(loadedRoutes)")
        }
        precondition(filter.contains("table <splitweb_local_addresses> const { self }"))
    }

    static func checkProxyOverlayRecovery() {
        let port = ProxyOverlaySettings.port
        let original: [String: Any] = ["HTTPEnable": 0, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080,
                                       "ExceptionsList": ["internal.example"], "FTPPassive": 1]
        let stale = ProxyOverlaySettings.installing(on: original, port: port)
        precondition(ProxyOverlaySettings.baseline(original, state: [:], port: port)?["HTTPPort"] as? Int == 8080)
        precondition(ProxyOverlaySettings.baseline(stale, state: stale, port: port)?["HTTPEnable"] as? Int == 0)
        precondition(ProxyOverlaySettings.baseline(stale, state: [:], port: port)?["HTTPSEnable"] as? Int == 0)
        let restored = ProxyOverlaySettings.restoring(stale, original: original, installed: stale)
        precondition(NSDictionary(dictionary: restored).isEqual(to: original))

        var foreign = stale
        foreign["HTTPProxy"] = "another.proxy.example"
        precondition(ProxyOverlaySettings.baseline(foreign, state: [:], port: port) == nil)
        precondition(ProxyOverlaySettings.baseline(stale, state: foreign, port: port) == nil)
        let partial = ProxyOverlaySettings.restoring(foreign, original: original, installed: stale)
        precondition(partial["HTTPProxy"] as? String == "another.proxy.example" &&
                     partial["HTTPEnable"] as? Int == 1 && partial["HTTPPort"] as? Int == Int(port))
        var automatic = stale
        automatic["ProxyAutoConfigEnable"] = 1
        precondition(ProxyOverlaySettings.baseline(automatic, state: [:], port: port) == nil)
        var noSignature = stale
        noSignature["ExceptionsList"] = ["internal.example"]
        precondition(ProxyOverlaySettings.baseline(noSignature, state: [:], port: port) == nil)
    }

    static func checkDefaultNetworkDetection() {
        // Majority probe wins even when one DNS IP like 1.0.0.1 is excluded to en0.
        precondition(DefaultNetwork.selectDominantInterface(
            from: ["en0", "utun13", "utun13", "utun13"], fallback: "en0"
        ) == "utun13")
        // SplitWeb's own capture interfaces and loopback are excluded.
        precondition(DefaultNetwork.selectDominantInterface(
            from: ["utun9", "utun9", "utun9", "utun9"], fallback: "en0", excluded: ["utun9"]
        ) == "en0")
        precondition(DefaultNetwork.selectDominantInterface(
            from: [nil, nil], fallback: "lo0"
        ) == nil)

        // Tunnel owner detection for non-SC VPN clients (AmneziaVPN, Tailscale, OpenVPN, WireGuard).
        let processes = [
            "/Applications/AmneziaVPN.app/Contents/MacOS/amneziawg-go utun13",
            "/usr/local/bin/tailscaled --tun=utun14",
            "/opt/homebrew/sbin/openvpn --dev utun15 --config client.ovpn"
        ]
        precondition(DefaultNetwork.detectTunnelOwner(interface: "utun13", processLines: processes) == "AmneziaVPN")
        precondition(DefaultNetwork.detectTunnelOwner(interface: "utun14", processLines: processes) == "Tailscale")
        precondition(DefaultNetwork.detectTunnelOwner(interface: "utun15", processLines: processes) == "OpenVPN")
        precondition(DefaultNetwork.detectTunnelOwner(interface: "utun1", processLines: processes) == nil)

        // Resolution across SC VPN app, SC profile, DynamicStore service, physical interface, non-SC tunnel, and foreign proxy.
        let interfaces = [NetworkChoice(id: "en0", name: "Wi-Fi (en0)")]
        let vpns = [NetworkChoice(id: "p1", name: "WorkVPN")]
        let vpnApps = [NetworkChoice(id: "su.ffg.happ", name: "Happ")]
        let dynamic = [
            DynamicStoreServiceInfo(id: "s1", name: "iPhone USB", interface: "en8", isVPN: false),
            DynamicStoreServiceInfo(id: "s2", name: "IKEv2 Office", interface: "ipsec0", isVPN: true)
        ]
        precondition(DefaultNetwork.resolveDescription(
            interface: "utun12", interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
            profileInterfaces: ["p1": "utun5"], appInterfaces: ["su.ffg.happ": ["utun12", "utun19"]],
            dynamicServices: dynamic, tunnelOwner: nil, foreignProxy: nil
        ) == "VPN Happ")
        precondition(DefaultNetwork.resolveDescription(
            interface: "utun5", interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
            profileInterfaces: ["p1": "utun5"], appInterfaces: [:],
            dynamicServices: dynamic, tunnelOwner: nil, foreignProxy: nil
        ) == "VPN WorkVPN")
        precondition(DefaultNetwork.resolveDescription(
            interface: "en8", interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
            profileInterfaces: [:], appInterfaces: [:],
            dynamicServices: dynamic, tunnelOwner: nil, foreignProxy: nil
        ) == "iPhone USB (en8)")
        precondition(DefaultNetwork.resolveDescription(
            interface: "ipsec0", interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
            profileInterfaces: [:], appInterfaces: [:],
            dynamicServices: dynamic, tunnelOwner: nil, foreignProxy: nil
        ) == "VPN IKEv2 Office")
        precondition(DefaultNetwork.resolveDescription(
            interface: "utun13", interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
            profileInterfaces: [:], appInterfaces: [:],
            dynamicServices: dynamic, tunnelOwner: "AmneziaVPN", foreignProxy: nil
        ) == "VPN AmneziaVPN (utun13)")
        precondition(DefaultNetwork.resolveDescription(
            interface: "utun16", interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
            profileInterfaces: [:], appInterfaces: [:],
            dynamicServices: dynamic, tunnelOwner: nil, foreignProxy: nil
        ) == "VPN (utun16)")
        precondition(DefaultNetwork.resolveDescription(
            interface: "en0", interfaces: interfaces, vpns: vpns, vpnApps: vpnApps,
            profileInterfaces: [:], appInterfaces: [:],
            dynamicServices: dynamic, tunnelOwner: nil, foreignProxy: "прокси SOCKS 127.0.0.1:10808"
        ) == "Wi-Fi (en0) · прокси SOCKS 127.0.0.1:10808")

        // Foreign proxy ignores SplitWeb's own loopback proxy, detects external SOCKS/HTTP/PAC.
        let own = ProxyOverlaySettings.installing(on: [:], port: ProxyOverlaySettings.port)
        precondition(DefaultNetwork.foreignProxyDescription(from: own) == nil)
        precondition(DefaultNetwork.foreignProxyDescription(from: [
            "SOCKSEnable": 1, "SOCKSProxy": "127.0.0.1", "SOCKSPort": 10808
        ]) == "прокси SOCKS 127.0.0.1:10808")
        precondition(DefaultNetwork.foreignProxyDescription(from: [
            "ProxyAutoConfigEnable": 1
        ]) == "прокси PAC")
    }
}
