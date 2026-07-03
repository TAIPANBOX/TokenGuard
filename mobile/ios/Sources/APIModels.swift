import Foundation

// Typed models mirroring the control-plane contract (mobile/ios/openapi.json,
// generated from crates/cloud). Decoded with `.convertFromSnakeCase`, so the
// wire's `run_id` / `spent_microusd` map to these camelCase properties. Money
// is microdollars on the wire; converted to dollars for display.

struct RunAgg: Codable, Identifiable, Sendable, Hashable {
    let runId: String
    let model: String
    let spentMicrousd: Int64
    let calls: Int
    let cacheHits: Int
    let steps: Int
    let lastSeenMillis: Int64
    let killed: Bool

    var id: String { runId }
}

struct Summary: Codable, Sendable {
    let runs: Int
    let calls: Int
    let spentMicrousd: Int64
}

extension Int64 {
    /// Microdollars → dollars.
    var usd: Double { Double(self) / 1_000_000 }
}
