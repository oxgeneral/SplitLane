import AppKit

enum GroupAppLaunchError: Error {
    case alreadyRunning(NSRunningApplication)
}

extension GroupApp {
    @MainActor
    @discardableResult
    func open(timeZoneIdentifier: String, restarting: NSRunningApplication? = nil) async throws -> NSRunningApplication {
        guard TimeZone(identifier: timeZoneIdentifier) != nil else {
            throw TunConfiguration.failure("Этот часовой пояс недоступен. Выбери другой в настройках группы.")
        }

        let url = URL(fileURLWithPath: path, isDirectory: true).resolvingSymlinksInPath()
        guard let bundle = Bundle(url: url), let bundleID = bundle.bundleIdentifier,
              let executable = bundle.executableURL, FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw TunConfiguration.failure("Не удалось найти «\(name)». Добавь приложение в группу заново.")
        }

        let workspace = NSWorkspace.shared
        func runningApps() -> [NSRunningApplication] {
            workspace.runningApplications.filter { application in
                !application.isTerminated && (application.bundleIdentifier == bundleID ||
                    application.bundleURL?.resolvingSymlinksInPath() == url)
            }
        }

        let running = runningApps()
        if running.count == 1, let application = running.first {
            guard restarting == application else { throw GroupAppLaunchError.alreadyRunning(application) }
            if application.terminate() {
                for _ in 0..<100 {
                    if application.isTerminated { break }
                    try await Task.sleep(for: .milliseconds(100))
                }
            }
        }
        guard runningApps().isEmpty else {
            throw TunConfiguration.failure("Закрой «\(name)» через ⌘Q и снова открой его из SplitLane.")
        }

        let configuration = NSWorkspace.OpenConfiguration()
        // Each XPC launch strips one prefix. An XPC service can start another service.
        // shortcut: covers two XPC launches, extend when a deeper app chain is reproduced.
        configuration.environment = [
            "TZ": timeZoneIdentifier,
            "__XPC_TZ": timeZoneIdentifier,
            "__XPC___XPC_TZ": timeZoneIdentifier
        ]
        configuration.createsNewApplicationInstance = true
        return try await workspace.openApplication(at: url, configuration: configuration)
    }
}
