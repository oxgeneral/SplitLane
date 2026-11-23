import Darwin
import Foundation
import Network
import NetworkExtension
import Security

final class Provider: NETransparentProxyProvider {
    private let queue = DispatchQueue(label: "SplitWebOnMac.flows")
    private var rules: [AppRule] = []
    private var pathMonitor: NWPathMonitor?
    private var relays: [ObjectIdentifier: TCPRelay] = [:]

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        guard let config = protocolConfiguration as? NETunnelProviderProtocol,
              let data = config.providerConfiguration?[RuleConfiguration.key] as? Data,
              let rules = try? RuleConfiguration.decode(data), !rules.isEmpty else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        queue.sync {
            self.rules = rules
            let monitor = NWPathMonitor()
            pathMonitor = monitor
            monitor.start(queue: queue)
        }

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [NENetworkRule(
            remoteNetworkEndpoint: nil, remotePrefix: 0, localNetworkEndpoint: nil,
            localPrefix: 0, protocol: .any, direction: .outbound
        )]
        // shortcut: system DNS can use the default route until a DNS provider is integrated and verified.
        setTunnelNetworkSettings(settings) { error in
            if error == nil {
                routingLog.notice("Routing enabled with \(rules.count, privacy: .public) app rules")
            }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            let closing = Array(self.relays.values)
            for relay in closing { relay.stop(with: self.refused) }
            self.pathMonitor?.cancel()
            self.pathMonitor = nil
            self.rules = []
            completionHandler()
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let metadata = flow.metaData
        let path = executablePath(for: metadata.sourceAppAuditToken)
        return queue.sync {
            let rule = AppRule.match(signingID: metadata.sourceAppSigningIdentifier, executablePath: path, rules: rules)
                ?? webKitOwnerPath(for: metadata.sourceAppAuditToken, executablePath: path).flatMap {
                    AppRule.match(signingID: metadata.sourceAppSigningIdentifier, executablePath: $0, rules: rules)
                }
            guard let rule else { return false }
            if flow is NEAppProxyUDPFlow && !rule.blocksUDPInExtension { return false }
            routingLog.debug("Matched \(rule.signingID, privacy: .private(mask: .hash)) to \(rule.route.kind.rawValue, privacy: .public)")
            guard let tcp = flow as? NEAppProxyTCPFlow,
                  let parameters = tcpParameters(for: rule.route,
                    interfaces: pathMonitor?.currentPath.availableInterfaces ?? []) else {
                flow.closeReadWithError(refused)
                flow.closeWriteWithError(refused)
                return true
            }

            let id = ObjectIdentifier(tcp)
            let relay = TCPRelay(flow: tcp, parameters: parameters, queue: queue) { [weak self] in
                self?.relays.removeValue(forKey: id)
            }
            relays[id] = relay
            relay.start()
            return true
        }
    }

    private var refused: Error {
        NSError(domain: NEAppProxyErrorDomain, code: NEAppProxyFlowError.refused.rawValue)
    }

    private func executablePath(for token: Data?) -> String? {
        guard let token else { return nil }
        var guest: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: token] as CFDictionary, [], &guest)
                == errSecSuccess, let guest else { return nil }
        var code: SecStaticCode?
        var url: CFURL?
        guard SecCodeCopyStaticCode(guest, [], &code) == errSecSuccess, let code,
              SecCodeCopyPath(code, [], &url) == errSecSuccess, let url else { return nil }
        return (url as URL).resolvingSymlinksInPath().path
    }

    // shortcut: use the same WebKit ownership lookup as the local engine until macOS exposes it publicly.
    private static let responsiblePID: (@convention(c) (pid_t) -> pid_t)? = {
        guard let symbol = dlsym(dlopen(nil, RTLD_LAZY), "responsibility_get_pid_responsible_for_pid") else {
            return nil
        }
        return unsafeBitCast(symbol, to: (@convention(c) (pid_t) -> pid_t).self)
    }()

    private func webKitOwnerPath(for token: Data?, executablePath: String?) -> String? {
        guard let executablePath, !executablePath.contains(".app/"),
              let token, token.count == MemoryLayout<audit_token_t>.size,
              let lookup = Self.responsiblePID else { return nil }
        let pid = audit_token_to_pid(token.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
        let owner = lookup(pid)
        guard owner > 1, owner != pid else { return nil }
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(owner, &path, UInt32(path.count)) > 0 else { return nil }
        let resolved = URL(fileURLWithPath: String(cString: path)).resolvingSymlinksInPath().path
        return resolved.contains(".app/") ? resolved : nil
    }
}
