import Darwin
import Foundation
import SystemConfiguration

final class PacketCapture {
    private static let anchor = "com.apple/local.splitlane.webrtc"
    private static let journal = ProxyOverlaySettings.packetJournal

    private let engine = Process()
    private let engineLifetime = Pipe()
    private let store = SCDynamicStoreCreate(nil, "SplitLane.capture" as CFString, nil, nil)
    private let directory: URL
    private let owner: uid_t
    private var token: String?
    private var nextCheck = ContinuousClock.now
    private var nextRouteRefresh = ContinuousClock.now
    private var nextBypassRefresh = ContinuousClock.now
    let capturesTCP: Bool
    private var tunnel = ""
    private var installedRules = ""
    private var installedAddresses: [String] = []
    private var cachedTCPV4: [String] = ["! lo0"]
    private var cachedTCPV6: [String] = ["! lo0"]
    private var cachedBypassEndpoints: [PacketBypassEndpoint] = []
    private var packetTunnelAppexCache: [String: Bool] = [:]
    private var fallbackRules: URL { directory.appendingPathComponent("blocked.conf") }
    private var armed: URL { directory.appendingPathComponent("armed") }
    private var enginePIDFile: URL { directory.appendingPathComponent("engine.pid") }

    var diagnosticSummary: String {
        "tunnel=\(tunnel) tcpV4=[\(cachedTCPV4.joined(separator: ","))] tcpV6=[\(cachedTCPV6.joined(separator: ","))] bypass=\(cachedBypassEndpoints.count)"
    }

    init(lease: URL, state: URL, owner: uid_t, executable: URL) throws {
        directory = state.appendingPathComponent("protection")
        self.owner = owner
        let apps = try Self.readRules(beside: lease, owner: owner)
        capturesTCP = apps.contains { $0.relayID != nil }
        SplitLaneLog.info("pf", "Starting packet capture owner=\(owner) apps=\(apps.count) capturesTCP=\(capturesTCP)")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            let interfaces = try Self.command("/sbin/ifconfig", [])
            guard !interfaces.contains(PacketRoutingConfiguration.ipv4),
                  !interfaces.contains(PacketRoutingConfiguration.ipv6) else {
                throw Self.failure("Адрес интерфейса перехвата уже используется.")
            }
            try Self.checkAnchor(allowRestoreDefault: true)
            let config = directory.appendingPathComponent("tun.json")
            try PacketRoutingConfiguration.make(apps: apps).write(to: config)
            let fallback = PacketRoutingConfiguration.filter(owner: owner, interface: nil, capturesTCP: capturesTCP)
            try fallback.write(to: fallbackRules, atomically: true, encoding: .utf8)
            _ = try Self.command("/sbin/pfctl", ["-n", "-a", Self.anchor, "-f", fallbackRules.path])
            engine.executableURL = URL(fileURLWithPath: "/bin/bash")
            engine.arguments = ["-c", Self.watchEngine, "splitlane-capture", executable.path, config.path,
                                armed.path, Self.journal.path, Self.anchor, fallbackRules.path,
                                ProxyOverlaySettings.lock, enginePIDFile.path]
            engine.standardInput = engineLifetime
            let captureLog = SplitLaneLog.openAppendHandle(for: .captureEngine)
            engine.standardOutput = captureLog ?? FileHandle.nullDevice
            engine.standardError = captureLog ?? FileHandle.nullDevice
            defer { try? captureLog?.close() }
            try engine.run()

            var tunnel: String?
            for _ in 0..<20 {
                guard engine.isRunning else { break }
                if let name = Self.interface(in: try Self.command("/sbin/ifconfig", []), address: PacketRoutingConfiguration.ipv4) {
                    tunnel = name
                    break
                }
                Thread.sleep(forTimeInterval: 0.15)
            }
            guard let tunnel, tunnel.range(of: #"^utun[0-9]+$"#, options: .regularExpression) != nil else {
                throw Self.failure("Не удалось открыть виртуальный сетевой интерфейс SplitLane.")
            }
            self.tunnel = tunnel
            let enabled = try Self.command("/sbin/pfctl", ["-E"])
            guard let value = enabled.split(separator: "\n").first(where: { $0.hasPrefix("Token") })?
                .split(whereSeparator: \.isWhitespace).last, UInt64(value) != nil else {
                throw Self.failure("Не удалось получить разрешение на временное правило фильтра.")
            }
            token = String(value)
            try Data(value.utf8).write(to: Self.journal, options: .atomic)
            SplitLaneLog.info("pf", "Capture tunnel ready tunnel=\(tunnel) enginePID=\(engine.processIdentifier)")
            try check()
        } catch {
            SplitLaneLog.error("pf", "Packet capture init failed: \(error.localizedDescription)")
            stop()
            throw error
        }
    }

    func armFallback() throws {
        if let token {
            try Data(token.utf8).write(to: armed, options: .atomic)
            SplitLaneLog.info("pf", "Armed emergency PF fallback guard")
        }
    }

    func hold() throws {
        SplitLaneLog.warning("pf", "Activating emergency PF blocking")
        try Self.checkAnchor()
        _ = try Self.command("/sbin/pfctl", ["-a", Self.anchor, "-f", fallbackRules.path])
        let status = try Self.command("/sbin/pfctl", ["-si"])
        guard status.split(separator: "\n").contains(where: { $0.hasPrefix("Status: Enabled") }) else {
            throw Self.failure("Сетевой фильтр macOS выключен. Аварийная блокировка недоступна.")
        }
        SplitLaneLog.notice("pf", "Emergency PF blocking active")
    }

    static func recover() throws {
        guard FileManager.default.fileExists(atPath: journal.path) else { return }
        SplitLaneLog.notice("recover", "Flushing PF anchor \(anchor) and releasing token")
        _ = try command("/sbin/pfctl", ["-a", anchor, "-F", "rules"])
        let token = (try? String(contentsOf: journal, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let token, UInt64(token) != nil {
            _ = try? command("/sbin/pfctl", ["-X", token])
        }
        try FileManager.default.removeItem(at: journal)
        guard let token, UInt64(token) != nil else {
            throw failure("Правила сетевого фильтра SplitLane очищены, но файл токена был повреждён.")
        }
        SplitLaneLog.info("recover", "PF anchor flushed and journal removed")
    }

    func check() throws {
        guard engine.isRunning else { throw Self.failure("Сетевой движок перехвата SplitLane остановился.") }
        try updateFilter()
        guard ContinuousClock.now >= nextCheck else { return }
        try Self.checkAnchor()
        let rules = try Self.command("/sbin/pfctl", ["-a", Self.anchor, "-sr"])
        let status = try Self.command("/sbin/pfctl", ["-si"])
        let expectedCount = installedRules.split(separator: "\n").filter { $0.contains("route-to") }.count
        guard rules.split(separator: "\n").filter({ $0.contains("route-to") }).count == expectedCount,
              status.split(separator: "\n").contains(where: { $0.hasPrefix("Status: Enabled") }) else {
            throw Self.failure("Системные правила перехвата трафика исчезли.")
        }
        nextCheck = .now + .seconds(2)
    }

    private func updateFilter() throws {
        let addresses = PacketRoutingConfiguration.liveAddressSnapshot()
        guard addresses.contains("\(tunnel) inet \(PacketRoutingConfiguration.ipv4)") else {
            throw Self.failure("Виртуальный сетевой интерфейс SplitLane исчез.")
        }
        let addressesChanged = addresses != installedAddresses
        let previousBypass = Set(cachedBypassEndpoints)
        let now = ContinuousClock.now
        if installedRules.isEmpty || addressesChanged || now >= nextRouteRefresh {
            let defaultV4 = Self.defaultRouteInterface(family: "-inet", excluding: tunnel)
            let defaultV6 = Self.defaultRouteInterface(family: "-inet6", excluding: tunnel)
            cachedTCPV4 = PacketRoutingConfiguration.tcpCaptureInterfaces(
                family: "inet", excluding: tunnel, liveAddresses: addresses, defaultRouteInterface: defaultV4
            )
            cachedTCPV6 = PacketRoutingConfiguration.tcpCaptureInterfaces(
                family: "inet6", excluding: tunnel, liveAddresses: addresses, defaultRouteInterface: defaultV6
            )
            nextRouteRefresh = now + .seconds(3)
        }
        if installedRules.isEmpty || addressesChanged || now >= nextBypassRefresh {
            cachedBypassEndpoints = discoverVPNBypassEndpoints()
            nextBypassRefresh = now + .seconds(1)
        }
        let rules = PacketRoutingConfiguration.filter(
            owner: owner,
            interface: tunnel,
            capturesTCP: capturesTCP,
            tcpCaptureInterfacesV4: cachedTCPV4,
            tcpCaptureInterfacesV6: cachedTCPV6,
            bypassEndpoints: cachedBypassEndpoints
        )
        // The const self table must be reloaded when DHCP or a VPN changes local addresses.
        guard rules != installedRules || addressesChanged else { return }
        let reason = installedRules.isEmpty ? "initial" : (addressesChanged ? "addressesChanged" : "rulesChanged")
        let filter = directory.appendingPathComponent("filter.conf")
        try Data(rules.utf8).write(to: filter)
        _ = try Self.command("/sbin/pfctl", ["-n", "-a", Self.anchor, "-f", filter.path])
        _ = try Self.command("/sbin/pfctl", ["-a", Self.anchor, "-f", filter.path])
        let addedEndpoints = Set(cachedBypassEndpoints).subtracting(previousBypass)
        let killedAddresses = Set(addedEndpoints.map(\.address))
        for address in killedAddresses {
            _ = try? Self.command("/sbin/pfctl", ["-k", address])
        }
        installedRules = rules
        installedAddresses = addresses
        SplitLaneLog.info("pf", "Reloaded PF anchor reason=\(reason) \(diagnosticSummary) killedStates=\(killedAddresses.count)")
    }

    private static func defaultRouteInterface(family: String, excluding captureTunnel: String) -> String? {
        let probes = family == "-inet6"
            ? ["2606:4700:4700::1111", "2620:fe::fe", "2001:4860:4860::8888"]
            : ["1.0.0.1", "198.41.0.4", "9.9.9.9"]
        var counts: [String: Int] = [:]
        var order: [String] = []
        for probe in probes {
            guard let iface = routeInterface(arguments: ["-n", "get", family, probe]),
                  iface != "lo0", iface != captureTunnel else { continue }
            if counts[iface] == nil { order.append(iface) }
            counts[iface, default: 0] += 1
        }
        if let best = order.max(by: { counts[$0, default: 0] < counts[$1, default: 0] }) {
            return best
        }
        if let fallback = routeInterface(arguments: ["-n", "get", family, "default"]),
           fallback != "lo0", fallback != captureTunnel {
            return fallback
        }
        return nil
    }

    private static func routeInterface(arguments: [String]) -> String? {
        guard let output = try? command("/sbin/route", arguments),
              let row = output.split(whereSeparator: \.isNewline).first(where: { $0.contains("interface:") }),
              let name = row.split(whereSeparator: \.isWhitespace).last else { return nil }
        let value = String(name)
        return if_nametoindex(value) != 0 ? value : nil
    }

    private func discoverVPNBypassEndpoints() -> [PacketBypassEndpoint] {
        var endpoints = Set<PacketBypassEndpoint>()
        // 1. Active SystemConfiguration VPN services (captures UDP WireGuard/IKEv2 ServerAddress).
        if let store,
           let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/(IPv4|IPv6|VPN|PPP|IPSec)" as CFString) as? [String] {
            var vpnServices = Set<String>()
            for key in keys where key.hasSuffix("/VPN") || key.hasSuffix("/PPP") || key.hasSuffix("/IPSec") {
                let parts = key.split(separator: "/")
                if parts.count == 5 { vpnServices.insert(String(parts[3])) }
            }
            for serviceID in vpnServices {
                for (suffix, field) in [("VPN", "RemoteAddress"), ("IPv4", "ServerAddress"), ("IPv6", "ServerAddress")] {
                    guard let dict = SCDynamicStoreCopyValue(store, "State:/Network/Service/\(serviceID)/\(suffix)" as CFString) as? [String: Any],
                          let raw = dict[field] as? String,
                          let family = Self.validExternalAddressFamily(raw) else { continue }
                    endpoints.insert(PacketBypassEndpoint(family: family, proto: "tcp", address: raw, port: nil))
                    endpoints.insert(PacketBypassEndpoint(family: family, proto: "udp", address: raw, port: nil))
                }
            }
        }
        // 2. Running NEPacketTunnelProvider extensions owned by the current user (e.g. Happ, V2Box, Outline).
        let byteEstimate = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        if byteEstimate > 0 {
            var pids = [pid_t](repeating: 0, count: Int(byteEstimate) / MemoryLayout<pid_t>.stride + 64)
            let actualBytes = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids, Int32(pids.count * MemoryLayout<pid_t>.stride))
            let count = max(0, Int(actualBytes) / MemoryLayout<pid_t>.stride)
            for i in 0..<count {
                let pid = pids[i]
                guard pid > 0 else { continue }
                var bsd = proc_bsdinfo()
                guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0,
                      bsd.pbi_uid == owner else { continue }
                guard let path = Self.pidPath(pid), isPacketTunnelExtension(path) else { continue }
                for ep in Self.socketEndpoints(for: pid) {
                    endpoints.insert(ep)
                }
            }
        }
        return endpoints.sorted()
    }

    private func isPacketTunnelExtension(_ path: String) -> Bool {
        if let cached = packetTunnelAppexCache[path] { return cached }
        let result: Bool
        if let range = path.range(of: ".appex/") {
            let plistURL = URL(fileURLWithPath: String(path[..<range.upperBound]) + "Contents/Info.plist")
            if let dict = NSDictionary(contentsOf: plistURL),
               let ext = dict["NSExtension"] as? [String: Any],
               let point = ext["NSExtensionPointIdentifier"] as? String {
                result = point == "com.apple.networkextension.packet-tunnel"
            } else {
                result = false
            }
        } else {
            result = false
        }
        packetTunnelAppexCache[path] = result
        return result
    }

    private static func pidPath(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }

    private static func socketEndpoints(for pid: pid_t) -> [PacketBypassEndpoint] {
        let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bytes > 0 else { return [] }
        let capacity = Int(bytes) / MemoryLayout<proc_fdinfo>.stride + 16
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: capacity)
        let actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * MemoryLayout<proc_fdinfo>.stride))
        guard actual > 0 else { return [] }
        let count = Int(actual) / MemoryLayout<proc_fdinfo>.stride
        var result: [PacketBypassEndpoint] = []
        for i in 0..<count {
            guard fds[i].proc_fdtype == PROX_FDTYPE_SOCKET else { continue }
            var info = socket_fdinfo()
            let got = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &info, Int32(MemoryLayout<socket_fdinfo>.size))
            guard got == Int32(MemoryLayout<socket_fdinfo>.size) else { continue }
            let psi = info.psi
            let proto: String
            let ini: in_sockinfo
            if psi.soi_kind == SOCKINFO_TCP {
                proto = "tcp"
                ini = psi.soi_proto.pri_tcp.tcpsi_ini
            } else if psi.soi_kind == SOCKINFO_IN && psi.soi_protocol == IPPROTO_UDP {
                proto = "udp"
                ini = psi.soi_proto.pri_in
            } else {
                continue
            }
            let port = UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_fport))
            guard port > 0, port != 53 else { continue }
            if ini.insi_vflag & UInt8(INI_IPV4) != 0 {
                var addr = ini.insi_faddr.ina_46.i46a_addr4
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                    let ip = String(cString: buf)
                    if validExternalAddressFamily(ip) == "inet" {
                        result.append(PacketBypassEndpoint(family: "inet", proto: proto, address: ip, port: port))
                    }
                }
            } else if ini.insi_vflag & UInt8(INI_IPV6) != 0 {
                var addr = ini.insi_faddr.ina_6
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    let ip = String(cString: buf)
                    if validExternalAddressFamily(ip) == "inet6" {
                        result.append(PacketBypassEndpoint(family: "inet6", proto: proto, address: ip, port: port))
                    }
                }
            }
        }
        return result
    }

    private static func validExternalAddressFamily(_ address: String) -> String? {
        guard !address.isEmpty, address != PacketRoutingConfiguration.ipv4, address != PacketRoutingConfiguration.ipv6 else {
            return nil
        }
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            let value = UInt32(bigEndian: v4.s_addr)
            let first = (value >> 24) & 0xff
            let second = (value >> 16) & 0xff
            // Reject unspecified, loopback, link-local, multicast, and reserved/experimental (e.g. 254.1.1.1).
            if first == 0 || first == 127 || (first == 169 && second == 254) || first >= 224 { return nil }
            return "inet"
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1 {
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            guard bytes.count == 16 else { return nil }
            let isZero = bytes.allSatisfy { $0 == 0 }
            let isLoopback = bytes.prefix(15).allSatisfy { $0 == 0 } && bytes[15] == 1
            let isLinkLocal = bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
            let isMulticast = bytes[0] == 0xff
            if isZero || isLoopback || isLinkLocal || isMulticast { return nil }
            return "inet6"
        }
        return nil
    }

    private static func checkAnchor(allowRestoreDefault: Bool = false) throws {
        var rules = try pfMainRules()
        if hasAppleAnchor(in: rules) { return }
        if allowRestoreDefault, rules.isEmpty, canLoadSystemPFConf() {
            SplitLaneLog.warning("pf", "Main PF ruleset empty at startup; loading /etc/pf.conf")
            _ = try command("/sbin/pfctl", ["-f", "/etc/pf.conf"])
            rules = try pfMainRules()
            if hasAppleAnchor(in: rules) {
                SplitLaneLog.notice("pf", "Restored default macOS PF anchor from /etc/pf.conf")
                return
            }
        }
        if !rules.isEmpty {
            SplitLaneLog.error("pf", "Main PF ruleset missing com.apple/* anchor (foreign rules count=\(rules.count))")
            throw failure("Другой сетевой фильтр или VPN (например, KillSwitch) заменил правила PF macOS. Отключи его и попробуй снова.")
        }
        SplitLaneLog.error("pf", "Main PF ruleset missing com.apple/* anchor (empty ruleset)")
        throw failure("macOS не предоставила точку подключения сетевого фильтра SplitLane.")
    }

    private static func pfMainRules() throws -> [String] {
        let output = try runCommand("/sbin/pfctl", ["-sr"])
        return output.stdout
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private static func hasAppleAnchor(in rules: [String]) -> Bool {
        rules.contains { $0 == "anchor \"com.apple/*\" all" || $0 == "anchor \"com.apple/*\"" }
    }

    private static func canLoadSystemPFConf() -> Bool {
        let path = "/etc/pf.conf"
        var info = stat()
        guard lstat(path, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFREG,
              let contents = try? String(contentsOfFile: path, encoding: .utf8) else { return false }
        return contents.contains("anchor \"com.apple/*\"")
    }

    func stop(keepingFilter: Bool = false) {
        SplitLaneLog.info("pf", "Stopping packet capture keepingFilter=\(keepingFilter) hasToken=\(token != nil) engineRunning=\(engine.isRunning)")
        if let token, !keepingFilter {
            if (try? Self.command("/sbin/pfctl", ["-a", Self.anchor, "-F", "rules"])) != nil {
                _ = try? Self.command("/sbin/pfctl", ["-X", token])
                try? FileManager.default.removeItem(at: Self.journal)
            }
            self.token = nil
        }
        if engine.isRunning {
            engine.terminate()
            let deadline = ContinuousClock.now + .seconds(4)
            while engine.isRunning && ContinuousClock.now < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if engine.isRunning {
                SplitLaneLog.warning("pf", "Capture engine did not exit on SIGTERM; sending SIGKILL")
                if let text = try? String(contentsOf: enginePIDFile, encoding: .utf8),
                   let childPID = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)), childPID > 1 {
                    kill(childPID, SIGKILL)
                }
                kill(engine.processIdentifier, SIGKILL)
            }
            engine.waitUntilExit()
        }
        try? engineLifetime.fileHandleForReading.close()
        try? engineLifetime.fileHandleForWriting.close()
        try? FileManager.default.removeItem(at: directory)
    }

    // When the helper is killed, arm PF before the child releases its tunnel.
    // The same lock and token prevent an old worker from overwriting a recovered session.
    private static let watchEngine = #"""
        "$1" run --disable-color -c "$2" </dev/null &
        child=$!
        printf '%s\n' "$child" > "$8"
        watcher=
        cleanup() {
            trap '' HUP INT TERM
            if [[ -n "$watcher" ]]; then
                kill -TERM "$watcher" 2>/dev/null || true
                wait "$watcher" 2>/dev/null || true
            fi
            if [[ -n "$child" ]]; then
                kill -TERM "$child" 2>/dev/null || true
                for attempt in 1 2 3 4 5 6 7 8 9 10; do
                    kill -0 "$child" 2>/dev/null || break
                    /bin/sleep 0.1
                done
                kill -KILL "$child" 2>/dev/null || true
                wait "$child" 2>/dev/null || true
            fi
        }
        trap cleanup EXIT
        trap 'exit 1' HUP INT TERM
        wrapper=$$
        (
            if ! IFS= read -r _ && [[ -f "$3" ]]; then
                /usr/bin/lockf -k -t 10 "$7" /bin/bash -c '
                    if /usr/bin/cmp -s "$1" "$2"; then
                        /sbin/pfctl -a "$3" -f "$4"
                    fi' splitlane-guard "$3" "$4" "$5" "$6"
            fi
            kill -TERM "$wrapper" 2>/dev/null || true
        ) <&0 &
        watcher=$!
        result=0
        wait "$child" || result=$?
        child=
        exit "$result"
        """#

    private static func readRules(beside lease: URL, owner: uid_t) throws -> [PacketRoutingRule] {
        let manifest = lease.deletingLastPathComponent().appendingPathComponent(PacketRoutingConfiguration.manifest)
        let fd = open(manifest.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw failure("Список приложений для перехвата трафика недоступен.") }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == owner, info.st_mode & S_IFMT == S_IFREG,
              (1...65_536).contains(info.st_size), let data = try file.read(upToCount: 65_537),
              data.count <= 65_536 else { throw failure("Неверный файл правил перехвата трафика.") }
        let apps = try JSONDecoder().decode([PacketRoutingRule].self, from: data)
        let ids = apps.compactMap(\.relayID)
        guard !apps.isEmpty, Set(ids).count == ids.count,
              apps.allSatisfy({ $0.path.hasPrefix("/") && $0.path.hasSuffix(".app") && !$0.path.contains("\0") &&
                  ($0.blockUDP || $0.relayID != nil) }) else {
            throw failure("Неверный список приложений для перехвата трафика.")
        }
        return apps
    }

    private static func interface(in output: String, address: String) -> String? {
        var current: String?
        for line in output.split(separator: "\n") {
            let parts = line.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 2 else { continue }
            if line.first?.isWhitespace == false { current = String(parts[0].dropLast()) }
            else if parts[0] == "inet" && parts[1] == address { return current }
        }
        return nil
    }

    private static func command(_ path: String, _ arguments: [String]) throws -> String {
        let result = try runCommand(path, arguments)
        return [result.stdout, result.stderr].filter { !$0.isEmpty }.joined(separator: "\n")
    }

    private static func runCommand(_ path: String, _ arguments: [String]) throws -> (stdout: String, stderr: String) {
        try autoreleasepool {
            var outFDs: [Int32] = [-1, -1]
            var errFDs: [Int32] = [-1, -1]
            guard pipe(&outFDs) == 0 else {
                throw failure("Не удалось открыть канал вывода сетевого фильтра (errno \(errno)).")
            }
            guard pipe(&errFDs) == 0 else {
                let code = errno
                close(outFDs[0])
                close(outFDs[1])
                throw failure("Не удалось открыть канал ошибок сетевого фильтра (errno \(code)).")
            }
            for fd in outFDs + errFDs {
                _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
            }
            let outRead = FileHandle(fileDescriptor: outFDs[0], closeOnDealloc: true)
            let outWrite = FileHandle(fileDescriptor: outFDs[1], closeOnDealloc: true)
            let errRead = FileHandle(fileDescriptor: errFDs[0], closeOnDealloc: true)
            let errWrite = FileHandle(fileDescriptor: errFDs[1], closeOnDealloc: true)
            defer {
                try? outRead.close()
                try? outWrite.close()
                try? errRead.close()
                try? errWrite.close()
            }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = arguments
            process.standardOutput = outWrite
            process.standardError = errWrite
            try process.run()
            // Close parent's write ends immediately so EOF is delivered as soon as the child exits.
            try? outWrite.close()
            try? errWrite.close()

            var errData = Data()
            let group = DispatchGroup()
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                autoreleasepool {
                    errData = errRead.readDataToEndOfFile()
                }
                group.leave()
            }
            let outData = outRead.readDataToEndOfFile()
            group.wait()
            process.waitUntilExit()

            let stdout = String(decoding: outData, as: UTF8.self)
            let stderr = String(decoding: errData, as: UTF8.self)
            guard process.terminationStatus == 0 else {
                let combined = [stderr, stdout].map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }.joined(separator: "\n")
                throw failure("Сетевой фильтр SplitLane вернул ошибку. \(combined)")
            }
            return (stdout, stderr)
        }
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "SplitLane.PacketCapture", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
