import Foundation

enum ProxyPermissionCheck {
    static func run() throws {
        let token = "00000000-0000-0000-0000-000000000000"
        let port = String(ProxyRoutingConfiguration.port)
        let user = "501"
        let zone = "America/Argentina/Buenos_Aires"
        let base = [token, "/var/folders/test/splitlane-\(token)/lease", port, "2", "3"]
        let protection = ["protect", user]
        let timeZone = ["zone", zone]
        let timeZoneOptions = [[], timeZone]
        for authorization in [[], ["--authorized"]] {
            for capture in [[], protection] {
                for option in timeZoneOptions {
                    let request = try ProxyOverlayRequest(arguments: authorization + base + capture + option)
                    precondition(request.authorized == !authorization.isEmpty)
                    precondition(request.packetCaptureOwner == (capture.isEmpty ? nil : 501))
                    precondition(request.timeZone == (option.isEmpty ? nil : zone))
                }
            }
        }
        let authorized = ["--authorized"] + base
        let malformed = [
            authorized + ["zone"],
            authorized + timeZone + timeZone,
            authorized + timeZone + protection,
            authorized + timeZone + ["/bin/sh"],
            authorized + ["zone", "../America/New_York"],
            authorized + ["zone", "America/New_York; /bin/sh"],
            authorized + ["protect", "0"] + timeZone
        ]
        let invalidRequests = malformed + [
            authorized + ["zone", "America/Not_A_Time_Zone"],
            Array(authorized.prefix(2)) + ["/private/tmp/lease"] + Array(authorized.suffix(3)) + timeZone
        ]
        for arguments in invalidRequests {
            precondition((try? ProxyOverlayRequest(arguments: arguments)) == nil)
        }

        let script = URL(fileURLWithPath: "Sources/Engine/proxy-permission.sh")
        let digest = String(repeating: "a", count: 64)
        let policy = try command("/bin/bash", ["-c", #"source "$1"; permission_rule "$2" "$3" "$4""#,
                                               "splitlane-permission-test", script.path, user, digest, port])
        precondition(policy.status == 0, policy.output)
        precondition(policy.output.hasPrefix("#\(user) ALL=(root) NOPASSWD: sha256:\(digest) /Library/PrivilegedHelperTools/local.splitlane.proxy-overlay.\(user) ^"))
        let start = policy.output.firstIndex(of: "^")!
        let pattern = policy.output[start...].trimmingCharacters(in: .newlines)
        for arguments in [authorized, authorized + timeZone, authorized + protection, authorized + protection + timeZone,
                          authorized + ["zone", "Etc/GMT+7"]] {
            let input = arguments.joined(separator: " ")
            precondition(input.range(of: pattern, options: .regularExpression) == input.startIndex..<input.endIndex)
        }
        let forbiddenArguments = malformed + [
            ["--recover"], ["--authorized", "--recover"],
            authorized + ["protect", "502"] + timeZone,
            Array(authorized.prefix(3)) + ["80"] + Array(authorized.suffix(2)) + timeZone,
            base + timeZone,
            authorized + ["zone", "America//New_York"]
        ]
        for arguments in forbiddenArguments {
            precondition(arguments.joined(separator: " ").range(of: pattern, options: .regularExpression) == nil)
        }

        let file = FileManager.default.temporaryDirectory.appendingPathComponent("splitlane-permission-test-\(UUID())")
        defer { try? FileManager.default.removeItem(at: file) }
        try policy.output.write(to: file, atomically: true, encoding: .utf8)
        let parsed = try command("/usr/sbin/visudo", ["-cf", file.path])
        precondition(parsed.status == 0, parsed.output)

        let worker = try String(contentsOf: script, encoding: .utf8)
        for args in [[script.path], ["-c", worker, "splitlane"]] {
            let rejected = try command("/bin/bash", args + ["invalid-test-action", user])
            precondition(rejected.status == 1 && rejected.output.isEmpty, rejected.output)
        }
    }

    private static func command(_ executable: String, _ arguments: [String]) throws -> (status: Int32, output: String) {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        return (process.terminationStatus, output)
    }
}
