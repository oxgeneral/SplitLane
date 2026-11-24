import Darwin
import Foundation
import OSLog

enum SplitLaneLogStream: String, Sendable {
    case app = "app.log"
    case proxyEngine = "proxy-engine.log"
    case helper = "helper.log"
    case captureEngine = "capture-engine.log"

    var isPrivileged: Bool {
        switch self {
        case .helper, .captureEngine: true
        case .app, .proxyEngine: false
        }
    }
}

enum SplitLaneLogLevel: String, Sendable {
    case info = "INFO"
    case notice = "NOTICE"
    case warning = "WARN"
    case error = "ERROR"
}

enum SplitLaneLog {
    static let maxFileBytes: off_t = 2 * 1024 * 1024
    static let systemDirectory = URL(fileURLWithPath: "/Library/Logs/SplitLane", isDirectory: true)
    static var userDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/SplitLane", isDirectory: true)
    }

    private static let lock = NSLock()
    private static let osLog = Logger(subsystem: "local.splitlane", category: "diagnostic")
    private static var privilegedReaderUID: uid_t?

    static func setPrivilegedReaderUID(_ uid: uid_t) {
        guard uid > 0 else { return }
        lock.lock()
        privilegedReaderUID = uid
        lock.unlock()
    }

    static func fileURL(for stream: SplitLaneLogStream, baseDirectory: URL? = nil) -> URL {
        let dir = baseDirectory ?? (stream.isPrivileged ? systemDirectory : userDirectory)
        return dir.appendingPathComponent(stream.rawValue, isDirectory: false)
    }

    static func openFDCount() -> Int {
        (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? -1
    }

    static func info(_ component: String, _ message: String, stream: SplitLaneLogStream = defaultStream) {
        write(level: .info, component: component, message: message, stream: stream)
    }

    static func notice(_ component: String, _ message: String, stream: SplitLaneLogStream = defaultStream) {
        write(level: .notice, component: component, message: message, stream: stream)
    }

    static func warning(_ component: String, _ message: String, stream: SplitLaneLogStream = defaultStream) {
        write(level: .warning, component: component, message: message, stream: stream)
    }

    static func error(_ component: String, _ message: String, stream: SplitLaneLogStream = defaultStream) {
        write(level: .error, component: component, message: message, stream: stream)
    }

    static var defaultStream: SplitLaneLogStream {
        geteuid() == 0 ? .helper : .app
    }

    static func write(
        level: SplitLaneLogLevel,
        component: String,
        message: String,
        stream: SplitLaneLogStream = defaultStream,
        baseDirectory: URL? = nil,
        maxBytes: off_t = maxFileBytes
    ) {
        let sanitized = sanitize(message)
        let line = "\(timestamp()) [\(level.rawValue)] [\(component)] \(sanitized)\n"
        switch level {
        case .info:
            osLog.info("[\(component, privacy: .public)] \(sanitized, privacy: .private)")
        case .notice:
            osLog.notice("[\(component, privacy: .public)] \(sanitized, privacy: .private)")
        case .warning:
            osLog.warning("[\(component, privacy: .public)] \(sanitized, privacy: .private)")
        case .error:
            osLog.error("[\(component, privacy: .public)] \(sanitized, privacy: .private)")
        }

        lock.lock()
        defer { lock.unlock() }
        guard let fd = openValidatedAppendFD(stream: stream, baseDirectory: baseDirectory, maxBytes: maxBytes) else {
            return
        }
        defer { close(fd) }
        writeAll(fd: fd, data: Data(line.utf8))
    }

    /// Opens an append-only validated FileHandle suitable for redirecting child process output.
    /// Caller should close the returned handle after launching the child process.
    static func openAppendHandle(
        for stream: SplitLaneLogStream,
        baseDirectory: URL? = nil,
        maxBytes: off_t = maxFileBytes
    ) -> FileHandle? {
        lock.lock()
        defer { lock.unlock() }
        guard let fd = openValidatedAppendFD(stream: stream, baseDirectory: baseDirectory, maxBytes: maxBytes) else {
            return nil
        }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    /// Builds a single human-readable diagnostic report combining the tails of all log streams.
    static func diagnosticReport(maxLinesPerStream: Int = 250) -> String {
        let bundle = Bundle.main
        let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        let bundleID = bundle.bundleIdentifier ?? "?"
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        let header = """
            === SplitLane Diagnostic Log ===
            Generated: \(timestamp())
            App: \(bundleID) \(version) (\(build))
            macOS: \(osVersion)
            User logs: \(userDirectory.path)
            System logs: \(systemDirectory.path)
            Recovery pending: \(ProxyOverlaySettings.recoveryPending)

            """

        let sections: [(String, SplitLaneLogStream)] = [
            ("App Log (app.log)", .app),
            ("Helper Log (helper.log)", .helper),
            ("Proxy Engine Log (proxy-engine.log)", .proxyEngine),
            ("Capture Engine Log (capture-engine.log)", .captureEngine)
        ]

        var body = header
        for (title, stream) in sections {
            let url = fileURL(for: stream)
            body += "\n--- \(title) [\(url.path)] ---\n"
            if let tail = readTail(at: url, maxLines: maxLinesPerStream) {
                body += tail.isEmpty ? "(empty)\n" : tail + "\n"
            } else {
                body += "(not present or unreadable)\n"
            }
        }
        return body
    }

    @discardableResult
    static func exportDiagnosticReport(maxLinesPerStream: Int = 400) -> URL? {
        let report = diagnosticReport(maxLinesPerStream: maxLinesPerStream)
        lock.lock()
        defer { lock.unlock() }
        let dir = userDirectory
        guard ensureSecureDirectory(dir, privileged: false) else { return nil }
        let target = dir.appendingPathComponent("diagnostic.log", isDirectory: false)
        let fd = open(target.path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid() else {
            return nil
        }
        _ = fchmod(fd, 0o600)
        writeAll(fd: fd, data: Data(report.utf8))
        return target
    }

    /// Caps an actively-written log stream (such as a redirected child process's stdout/stderr)
    /// in place using ftruncate so O_APPEND writers seamlessly continue writing from offset 0.
    static func truncateIfOversized(
        for stream: SplitLaneLogStream,
        baseDirectory: URL? = nil,
        maxBytes: off_t = maxFileBytes
    ) {
        guard maxBytes > 0 else { return }
        lock.lock()
        defer { lock.unlock() }
        let privileged = baseDirectory == nil ? stream.isPrivileged : (geteuid() == 0)
        if privileged && geteuid() != 0 { return }
        let dir = baseDirectory ?? (privileged ? systemDirectory : userDirectory)
        guard ensureSecureDirectory(dir, privileged: privileged) else { return }
        let url = dir.appendingPathComponent(stream.rawValue, isDirectory: false)
        let fd = open(url.path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              isValidatedLogFile(info, privileged: privileged),
              info.st_size >= maxBytes else {
            return
        }
        if ftruncate(fd, 0) == 0 {
            let notice = "\(timestamp()) [INFO] [log] Truncated oversized \(stream.rawValue) (was \(info.st_size) bytes)\n"
            writeAll(fd: fd, data: Data(notice.utf8))
        }
    }

    static func clearUserLogs(baseDirectory: URL? = nil) {
        lock.lock()
        defer { lock.unlock() }
        let dir = baseDirectory ?? userDirectory
        let activeStreams = [
            SplitLaneLogStream.app.rawValue,
            SplitLaneLogStream.proxyEngine.rawValue
        ]
        for name in activeStreams {
            let url = dir.appendingPathComponent(name, isDirectory: false)
            let fd = open(url.path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { continue }
            defer { close(fd) }
            var info = stat()
            if fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid() {
                _ = ftruncate(fd, 0)
            }
        }
        let removable = [
            SplitLaneLogStream.app.rawValue + ".1",
            SplitLaneLogStream.proxyEngine.rawValue + ".1",
            "diagnostic.log"
        ]
        for name in removable {
            let url = dir.appendingPathComponent(name, isDirectory: false)
            _ = unlink(url.path)
        }
    }

    // MARK: - Internals

    private static func isValidatedLogFile(_ info: stat, privileged: Bool) -> Bool {
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1 else { return false }
        if privileged {
            if let reader = privilegedReaderUID {
                return info.st_uid == 0 || info.st_uid == reader
            }
            // In a root-only directory (0755 root:wheel), only root can create or replace entries.
            return true
        }
        return info.st_uid == geteuid()
    }

    private static func openValidatedAppendFD(
        stream: SplitLaneLogStream,
        baseDirectory: URL?,
        maxBytes: off_t
    ) -> Int32? {
        let privileged = baseDirectory == nil ? stream.isPrivileged : (geteuid() == 0)
        // Never allow an unprivileged process to write into the root log directory.
        if privileged && geteuid() != 0 { return nil }

        let dir = baseDirectory ?? (privileged ? systemDirectory : userDirectory)
        guard ensureSecureDirectory(dir, privileged: privileged) else { return nil }

        let url = dir.appendingPathComponent(stream.rawValue, isDirectory: false)
        let fileMode: mode_t = 0o600

        if shouldRotate(path: url.path, privileged: privileged, maxBytes: maxBytes) {
            let backup = url.path + ".1"
            var backupStat = stat()
            if lstat(backup, &backupStat) == 0 && (backupStat.st_mode & S_IFMT) == S_IFLNK {
                _ = unlink(backup)
            }
            _ = rename(url.path, backup)
        }

        let fd = open(url.path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, fileMode)
        guard fd >= 0 else { return nil }
        var info = stat()
        guard fstat(fd, &info) == 0, isValidatedLogFile(info, privileged: privileged) else {
            close(fd)
            return nil
        }
        if privileged, let reader = privilegedReaderUID, info.st_uid != reader {
            _ = fchown(fd, reader, 0)
        }
        // Explicitly apply 0600 permissions so logs are readable only by the session owner (and root).
        _ = fchmod(fd, fileMode)
        return fd
    }

    private static func ensureSecureDirectory(_ url: URL, privileged: Bool) -> Bool {
        let expectedUID: uid_t = privileged ? 0 : geteuid()
        let dirMode: mode_t = privileged ? 0o755 : 0o700
        var info = stat()
        if lstat(url.path, &info) != 0 {
            if errno != ENOENT { return false }
            let parent = url.deletingLastPathComponent()
            if !privileged {
                try? FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
            }
            if mkdir(url.path, dirMode) != 0 && errno != EEXIST {
                return false
            }
            guard lstat(url.path, &info) == 0 else { return false }
        }
        let forbiddenWriteBits: mode_t = privileged ? (S_IWGRP | S_IWOTH) : S_IWOTH
        guard (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == expectedUID,
              (info.st_mode & forbiddenWriteBits) == 0 else {
            return false
        }
        if privileged && (info.st_mode & 0o777) != dirMode {
            _ = chmod(url.path, dirMode)
        }
        return true
    }

    private static func shouldRotate(path: String, privileged: Bool, maxBytes: off_t) -> Bool {
        guard maxBytes > 0 else { return false }
        var info = stat()
        guard lstat(path, &info) == 0, isValidatedLogFile(info, privileged: privileged) else {
            return false
        }
        return info.st_size >= maxBytes
    }

    private static func writeAll(fd: Int32, data: Data) {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var written = 0
            while written < raw.count {
                let n = Darwin.write(fd, base.advanced(by: written), raw.count - written)
                if n <= 0 {
                    if errno == EINTR { continue }
                    break
                }
                written += n
            }
        }
    }

    private static func readTail(at url: URL, maxLines: Int) -> String? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
        let maxReadBytes: Int64 = 256 * 1024
        let size = Int64(info.st_size)
        let offset = max(0, size - maxReadBytes)
        if offset > 0 {
            _ = lseek(fd, off_t(offset), SEEK_SET)
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n < 0 {
                if errno == EINTR { continue }
                break
            }
            if n == 0 { break }
            data.append(buffer, count: n)
        }
        var text = String(decoding: data, as: UTF8.self)
        if offset > 0, let newline = text.firstIndex(of: "\n") {
            text = String(text[text.index(after: newline)...])
        }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        let trimmed = lines.last?.isEmpty == true ? lines.dropLast() : lines[...]
        return trimmed.suffix(maxLines).joined(separator: "\n")
    }

    private static func sanitize(_ message: String) -> String {
        message
            .replacingOccurrences(of: "\r\n", with: " ")
            .replacingOccurrences(of: "\n", with: " | ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func timestamp() -> String {
        var tv = timeval()
        gettimeofday(&tv, nil)
        var sec = tv.tv_sec
        var tmValue = tm()
        localtime_r(&sec, &tmValue)
        let ms = Int(tv.tv_usec / 1000)
        return String(
            format: "%04d-%02d-%02d %02d:%02d:%02d.%03d",
            Int(tmValue.tm_year) + 1900,
            Int(tmValue.tm_mon) + 1,
            Int(tmValue.tm_mday),
            Int(tmValue.tm_hour),
            Int(tmValue.tm_min),
            Int(tmValue.tm_sec),
            ms
        )
    }
}
