import Foundation
import SystemConfiguration

// Integration check on a synthetic service ID, with no IP configuration or routes.
@main
struct VPNProxyOverlayCheck {
    static func main() throws {
        let port = ProxyOverlaySettings.port
        if CommandLine.arguments.count == 2 {
            var overlay = VPNProxyOverlay()
            try overlay.install(service: CommandLine.arguments[1], port: port)
            _ = withExtendedLifetime(overlay) { pause() }
            return
        }
        guard geteuid() == 0 else { throw NSError(domain: "Run the dynamic store checks as administrator", code: 1) }
        let service = "SplitLane-Test-" + UUID().uuidString
        let key = "Setup:/Network/Service/\(service)/Proxies" as CFString
        let store = SCDynamicStoreCreate(nil, "SplitLane test" as CFString, nil, nil)!
        func current() -> [String: Any]? { SCDynamicStoreCopyValue(store, key) as? [String: Any] }
        defer { _ = SCDynamicStoreRemoveValue(store, key) }
        var overlay = VPNProxyOverlay()
        try overlay.install(service: service, port: port)
        precondition(ProxyOverlaySettings.isLocalProxy(current() ?? [:], port: port))
        try overlay.stop()
        for _ in 0..<50 where current() != nil { Thread.sleep(forTimeInterval: 0.02) }
        precondition(current() == nil)

        let original: [String: Any] = ["HTTPEnable": 0, "HTTPPort": 8080, "ExceptionsList": ["example.org"]]
        precondition(SCDynamicStoreSetValue(store, key, original as CFDictionary))
        try overlay.install(service: service, port: port)
        try overlay.stop()
        precondition(NSDictionary(dictionary: current() ?? [:]).isEqual(to: original))

        try overlay.install(service: service, port: port)
        var external = current()!
        external["HTTPProxy"] = "other.example"
        precondition(SCDynamicStoreSetValue(store, key, external as CFDictionary))
        try overlay.stop()
        precondition(current()?["HTTPProxy"] as? String == "other.example" && current()?["HTTPSEnable"] == nil)
        do {
            try overlay.install(service: service, port: port)
            preconditionFailure("A foreign proxy was overwritten")
        } catch { }
        precondition(SCDynamicStoreRemoveValue(store, key))

        let child = Process()
        child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
        child.arguments = [service]
        try child.run()
        defer { if child.isRunning { child.terminate() } }
        for _ in 0..<100 where current() == nil { Thread.sleep(forTimeInterval: 0.02) }
        precondition(ProxyOverlaySettings.isLocalProxy(current() ?? [:], port: port))
        kill(child.processIdentifier, SIGKILL)
        child.waitUntilExit()
        for _ in 0..<100 where current() != nil { Thread.sleep(forTimeInterval: 0.02) }
        precondition(current() == nil)
        print("VPN proxy activation, restoration, external change and SIGKILL checks passed.")
    }
}
