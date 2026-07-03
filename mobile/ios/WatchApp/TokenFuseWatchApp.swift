import SwiftUI

/// TokenFuse on the wrist — a glance at the fleet's burn rate and, when one runs
/// hot, a two-tap kill (W3). Shares the design system, API layer and signing with
/// the iPhone app; W1 reads the fleet, W2 receives the session over WatchConnectivity.
@main
struct TokenFuseWatchApp: App {
    var body: some Scene {
        WindowGroup {
            WatchRootView()
        }
    }
}
