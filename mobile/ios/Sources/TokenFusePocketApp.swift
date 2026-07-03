import SwiftData
import SwiftUI

@main
struct TokenFusePocketApp: App {
    var body: some Scene {
        WindowGroup {
            RootView()
                .preferredColorScheme(.dark)
        }
        .modelContainer(for: CachedRun.self)
    }
}
