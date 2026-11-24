import Foundation
import NetworkExtension
import OSLog

let routingLog = Logger(subsystem: Bundle.main.bundleIdentifier ?? "SplitLane", category: "routing")
routingLog.notice("Network extension process started")
NEProvider.startSystemExtensionMode()
dispatchMain()
