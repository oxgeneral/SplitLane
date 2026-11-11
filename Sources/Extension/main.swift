import Foundation
import NetworkExtension
import OSLog

let routingLog = Logger(subsystem: Bundle.main.bundleIdentifier ?? "SplitWebOnMac", category: "routing")
routingLog.notice("Network extension process started")
NEProvider.startSystemExtensionMode()
dispatchMain()
