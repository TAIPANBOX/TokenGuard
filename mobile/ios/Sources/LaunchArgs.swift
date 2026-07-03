import Foundation

/// Reads `-key value` launch arguments — used to drive the app from `simctl`
/// for screenshots and UI checks (auto-pair, open a run). No args ⇒ no effect,
/// so this is inert in normal use.
enum LaunchArgs {
    static func value(_ key: String) -> String? {
        let args = ProcessInfo.processInfo.arguments
        guard let index = args.firstIndex(of: key), index + 1 < args.count else { return nil }
        return args[index + 1]
    }
}
