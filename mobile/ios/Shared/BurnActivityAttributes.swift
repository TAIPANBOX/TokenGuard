import ActivityKit
import Foundation

/// Shared between the app (which starts/updates the activity) and the widget
/// extension (which renders it in the Dynamic Island + on the Lock Screen).
struct BurnAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        var spentMicrousd: Int64
        var budgetMicros: Int64
        var ratePerMin: Double

        var fraction: Double {
            budgetMicros > 0 ? Double(spentMicrousd) / Double(budgetMicros) : 0
        }
    }

    var runId: String
    var org: String
}
