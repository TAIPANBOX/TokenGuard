import SwiftData
import SwiftUI

@main
struct TokenFusePocketApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            RootView()
                .preferredColorScheme(.dark)
        }
        .modelContainer(for: CachedRun.self)
    }
}
