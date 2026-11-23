import Foundation

struct ProxyOverlayRequest {
    let authorized: Bool
    let timeZone: String?
    let packetCaptureOwner: uid_t?
    let sessionName: String
    let lease: URL
    let port: UInt16
    let proxyPID: Int32
    let appPID: Int32

    init(arguments: [String]) throws {
        var args = arguments
        authorized = args.first == "--authorized"
        if authorized { args.removeFirst() }
        if args.count >= 6 && args[args.count - 2] == "zone" {
            let value = args.removeLast()
            args.removeLast()
            guard TimeZone.knownTimeZoneIdentifiers.contains(value) else {
                throw Self.failure("Недоступный часовой пояс Mac.")
            }
            timeZone = value
        } else {
            timeZone = nil
        }

        let protected = args.count == 7 && args[5] == "protect"
        guard args.count == 5 || protected, let token = UUID(uuidString: args[0]),
              let port = UInt16(args[2]), port > 0, let proxyPID = Int32(args[3]), proxyPID > 1,
              let appPID = Int32(args[4]), appPID > 1 else {
            throw Self.failure("Неверные параметры запуска системного прокси.")
        }
        let lease = URL(fileURLWithPath: args[1])
        let sessionName = "splitwebonmac-\(token.uuidString)"
        if authorized || protected {
            guard lease.lastPathComponent == "lease", lease.deletingLastPathComponent().lastPathComponent == sessionName,
                  lease.path.hasPrefix("/var/folders/") || lease.path.hasPrefix("/private/var/folders/") else {
                throw Self.failure("Неверный путь к активной сессии SplitWebOnMac.")
            }
        }
        if protected {
            guard let owner = uid_t(args[6]), owner > 0 else {
                throw Self.failure("Нет разрешения на управление сетевым фильтром SplitWeb.")
            }
            packetCaptureOwner = owner
        } else {
            packetCaptureOwner = nil
        }
        self.sessionName = sessionName
        self.lease = lease
        self.port = port
        self.proxyPID = proxyPID
        self.appPID = appPID
    }

    private static func failure(_ message: String) -> NSError {
        NSError(domain: "SplitWebOnMac.ProxyOverlay", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
