@preconcurrency import ActivityKit
import Foundation

/// Starts/ends a burn Live Activity for a run. Updated locally by the app — no
/// push, so it works without an Apple Developer account (a real device or a
/// recent simulator shows it in the Dynamic Island + on the Lock Screen).
enum LiveBurn {
    static var isAvailable: Bool { ActivityAuthorizationInfo().areActivitiesEnabled }

    static func start(run: RunDisplay, org: String, rate: Double) -> Activity<BurnAttributes>? {
        guard isAvailable else { return nil }
        let attributes = BurnAttributes(runId: run.agg.runId, org: org)
        let state = BurnAttributes.ContentState(
            spentMicrousd: run.agg.spentMicrousd,
            budgetMicros: run.budgetMicros ?? 0,
            ratePerMin: rate
        )
        return try? Activity.request(
            attributes: attributes,
            content: ActivityContent(state: state, staleDate: nil)
        )
    }

    static func end(_ activity: Activity<BurnAttributes>) async {
        await activity.end(nil, dismissalPolicy: .immediate)
    }
}
