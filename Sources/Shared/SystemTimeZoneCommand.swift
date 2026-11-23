import Foundation

enum SystemTimeZoneCommand {
    static let preference = "systemTimeZoneWhileRouting"
    static let journal = "/var/db/local.splitwebonmac.time-zone-restore.json"

    static func run(_ arguments: [String]) throws {
        let process = Process()
        let errorPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-l", "JavaScript", "-e", script, "--"] + arguments
        process.standardError = errorPipe
        try process.run()
        let stderr = String(decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = stderr.isEmpty ? "Не удалось изменить системный часовой пояс." : stderr
            throw NSError(domain: "SplitWebOnMac", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: detail])
        }
    }

    // CoreTime controls location updates separately from systemsetup.
    static let script = """
        function run(argv) {
            ObjC.import("Foundation");
            ObjC.bindFunction("dlopen", ["void *", ["char *", "int"]]);
            $.dlopen("/System/Library/PrivateFrameworks/CoreTime.framework/Versions/A/CoreTime", 10);
            ObjC.bindFunction("TMIsAutomaticTimeZoneEnabled", ["bool", []]);
            if (argv[0] === "read") return String($.TMIsAutomaticTimeZoneEnabled());
            ObjC.bindFunction("TMSetAutomaticTimeZoneEnabled", ["void", ["bool"]]);
            ObjC.bindFunction("rename", ["int", ["char *", "char *"]]);
            ObjC.bindFunction("lchmod", ["int", ["char *", "unsigned short"]]);
            ObjC.bindFunction("notify_post", ["unsigned int", ["char *"]]);

            const files = $.NSFileManager.defaultManager;
            const journal = "/var/db/local.splitwebonmac.time-zone-restore.json";
            const zoneDirectory = "/var/db/timezone/zoneinfo/";
            const localtime = "/private/etc/localtime";
            function currentZone() {
                const link = ObjC.unwrap(files.destinationOfSymbolicLinkAtPathError(localtime, null));
                return link && link.includes("/zoneinfo/") ? link.split("/zoneinfo/")[1] : "";
            }
            function validZone(zone) {
                return typeof zone === "string" && zone.split("/").every(part =>
                    part !== "." && part !== ".." && /^[A-Za-z0-9_+.-]+$/.test(part)) &&
                    files.fileExistsAtPath(zoneDirectory + zone) &&
                    $.NSTimeZone.knownTimeZoneNames.containsObject(zone);
            }
            function setZone(zone) {
                if (!validZone(zone)) throw new Error("Недоступный часовой пояс.");
                if (currentZone() === zone) return;
                // Keep the previous link in place until its replacement is ready.
                const staged = localtime + ".splitweb-" + ObjC.unwrap($.NSUUID.UUID.UUIDString);
                if (!files.createSymbolicLinkAtPathWithDestinationPathError(staged, zoneDirectory + zone, null)) {
                    throw new Error("Не удалось подготовить часовой пояс " + zone + ".");
                }
                // Darwin applies the helper's restrictive umask to the link itself.
                if ($.lchmod(staged, 0o777) !== 0 || $.rename(staged, localtime) !== 0) {
                    files.removeItemAtPathError(staged, null);
                    throw new Error("Не удалось обновить системный часовой пояс.");
                }
                if (currentZone() !== zone) {
                    throw new Error("macOS не применила часовой пояс " + zone + ".");
                }
                $.notify_post("com.apple.system.timezone");
                $.NSDistributedNotificationCenter.defaultCenter.postNotificationNameObjectUserInfoOptions(
                    "NSSystemTimeZoneDidChangeDistributedNotification", null, null,
                    $.NSDistributedNotificationDeliverImmediately | $.NSDistributedNotificationPostToAllSessions);
            }
            function setAutomatic(enabled) {
                if ($.TMIsAutomaticTimeZoneEnabled() === enabled) return;
                $.TMSetAutomaticTimeZoneEnabled(enabled);
                for (let attempt = 0; attempt < 20; attempt++) {
                    if ($.TMIsAutomaticTimeZoneEnabled() === enabled) return;
                    $.NSThread.sleepForTimeInterval(0.1);
                }
                throw new Error("macOS не переключила автоопределение часового пояса.");
            }
            function restore() {
                if (!files.fileExistsAtPath(journal)) return;
                const saved = JSON.parse(ObjC.unwrap($.NSString.stringWithContentsOfFileEncodingError(
                    journal, $.NSUTF8StringEncoding, null)));
                if (!validZone(saved.zone) || typeof saved.automatic !== "boolean") {
                    throw new Error("Не удалось прочитать прежний часовой пояс.");
                }
                setZone(saved.zone);
                setAutomatic(saved.automatic);
                if (!files.removeItemAtPathError(journal, null)) {
                    throw new Error("Не удалось закрыть сессию часового пояса.");
                }
            }
            if (argv[0] === "restore") { restore(); return; }
            if (argv[0] !== "begin" || !validZone(argv[1]) || files.fileExistsAtPath(journal)) {
                throw new Error("Не удалось начать сессию часового пояса.");
            }
            const saved = {zone: currentZone(), automatic: $.TMIsAutomaticTimeZoneEnabled()};
            if (saved.zone === argv[1] && !saved.automatic) return;
            if (!validZone(saved.zone) || !$(JSON.stringify(saved)).writeToFileAtomicallyEncodingError(
                journal, true, $.NSUTF8StringEncoding, null)) {
                throw new Error("Не удалось сохранить прежний часовой пояс.");
            }
            try {
                setAutomatic(false);
                setZone(argv[1]);
            } catch (error) {
                restore();
                throw error;
            }
        }
        """
}
