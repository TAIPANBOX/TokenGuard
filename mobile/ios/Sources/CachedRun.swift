import Foundation
import SwiftData

/// Last-known run state, persisted so the app shows the fleet instantly on cold
/// launch and offline. Refreshed from the plane on every successful load.
@Model
final class CachedRun {
    @Attribute(.unique) var key: String  // "org/runId"
    var org: String
    var runId: String
    var model: String
    var spentMicrousd: Int64
    var calls: Int
    var cacheHits: Int
    var steps: Int
    var lastSeenMillis: Int64
    var killed: Bool
    var budgetMicros: Int64  // 0 = no cap
    var updatedAt: Date

    init(org: String, run: RunDisplay, updatedAt: Date = .now) {
        self.key = "\(org)/\(run.agg.runId)"
        self.org = org
        self.runId = run.agg.runId
        self.model = run.agg.model
        self.spentMicrousd = run.agg.spentMicrousd
        self.calls = run.agg.calls
        self.cacheHits = run.agg.cacheHits
        self.steps = run.agg.steps
        self.lastSeenMillis = run.agg.lastSeenMillis
        self.killed = run.agg.killed
        self.budgetMicros = run.budgetMicros ?? 0
        self.updatedAt = updatedAt
    }

    /// Rebuild a display row from cache.
    var display: RunDisplay {
        RunDisplay(
            agg: RunAgg(
                runId: runId, model: model, spentMicrousd: spentMicrousd,
                calls: calls, cacheHits: cacheHits, steps: steps,
                lastSeenMillis: lastSeenMillis, killed: killed
            ),
            budgetMicros: budgetMicros > 0 ? budgetMicros : nil
        )
    }
}
