import Foundation
import SystemConfiguration

// Publish the proxy only for this session. NetworkExtension can copy a saved
// service proxy into VPN/Proxies and reuse it after the local listener exits.
struct VPNProxyOverlay {
    private struct Entry {
        let key: CFString
        let previous: [String: Any]?
        let installed: [String: Any]
        let session: SCDynamicStore
    }
    private var entries: [Entry] = []

    mutating func install(service: String, port: UInt16) throws {
        guard let session = SCDynamicStoreCreate(nil, "SplitLane VPN" as CFString, nil, nil) else {
            throw Self.failure("Не удалось открыть временные настройки VPN.")
        }
        let key = "Setup:/Network/Service/\(service)/Proxies" as CFString
        let stateKey = "State:/Network/Service/\(service)/Proxies" as CFString
        let previous = SCDynamicStoreCopyValue(session, key) as? [String: Any]
        let state = SCDynamicStoreCopyValue(session, stateKey) as? [String: Any] ?? [:]
        guard !ProxyOverlaySettings.hasProxy(previous ?? [:]), !ProxyOverlaySettings.hasProxy(state) else {
            throw Self.failure("В VPN уже настроен другой системный прокси. Отключи его в настройках VPN-клиента и повтори запуск.")
        }
        let installed = ProxyOverlaySettings.installing(on: previous ?? [:], port: port)
        // The temporary key disappears even on SIGKILL. Existing inactive
        // settings stay on disk and are republished on a normal stop.
        if previous != nil, !SCDynamicStoreRemoveValue(session, key) {
            throw Self.failure("Настройки VPN изменились во время включения правил.")
        }
        guard SCDynamicStoreAddTemporaryValue(session, key, installed as CFDictionary) else {
            if let previous { _ = SCDynamicStoreAddValue(session, key, previous as CFDictionary) }
            throw Self.failure("Не удалось включить временный прокси VPN.")
        }
        SplitLaneLog.info("vpn", "Installed temporary proxy on VPN service=\(service) port=\(port)")
        entries.append(Entry(key: key, previous: previous, installed: installed, session: session))
    }

    mutating func stop() throws {
        while let entry = entries.last {
            // Another publisher can replace a temporary key when a VPN
            // reconnects. Only restore the value that this session installed.
            if let current = SCDynamicStoreCopyValue(entry.session, entry.key) as? [String: Any] {
                let unchanged = NSDictionary(dictionary: current).isEqual(to: entry.installed)
                if entry.previous != nil || !unchanged {
                    let restored = ProxyOverlaySettings.restoring(current, original: entry.previous ?? [:],
                                                                 installed: entry.installed)
                    if !NSDictionary(dictionary: current).isEqual(to: restored) {
                        guard let publisher = SCDynamicStoreCreate(nil, "SplitLane VPN restore" as CFString, nil, nil),
                              SCDynamicStoreSetValue(publisher, entry.key, restored as CFDictionary) else {
                            throw Self.failure("Не удалось восстановить временные настройки VPN.")
                        }
                        SplitLaneLog.info("vpn", "Restored VPN proxy key=\(entry.key)")
                    }
                }
            }
            entries.removeLast()
        }
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "SplitLane.VPNProxy", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
