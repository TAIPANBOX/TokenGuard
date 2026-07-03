import Foundation

/// Where the watch reads its fleet from. In W1 this comes from launch arguments
/// (to drive the simulator) or the last value persisted in UserDefaults; W2 will
/// receive it from the paired iPhone over WatchConnectivity.
struct WatchConfig: Equatable {
    var baseURL: URL
    var token: String
    var org: String

    static func current() -> WatchConfig? {
        let defaults = UserDefaults.standard
        let urlString = LaunchArgs.value("-planeURL") ?? defaults.string(forKey: "tf_base")
        let token = LaunchArgs.value("-token") ?? defaults.string(forKey: "tf_token")
        let org = LaunchArgs.value("-org") ?? defaults.string(forKey: "tf_org") ?? "acme"

        guard let urlString, let url = URL(string: urlString),
              let token, !token.isEmpty else { return nil }

        // Persist launch-arg values so a plain relaunch keeps working.
        defaults.set(urlString, forKey: "tf_base")
        defaults.set(token, forKey: "tf_token")
        defaults.set(org, forKey: "tf_org")
        return WatchConfig(baseURL: url, token: token, org: org)
    }
}
