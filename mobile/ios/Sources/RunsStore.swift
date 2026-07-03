import Foundation
import Observation
import SwiftData

/// A run joined with its central budget, ready for display.
struct RunDisplay: Identifiable, Sendable, Hashable {
    let agg: RunAgg
    let budgetMicros: Int64?

    var id: String { agg.runId }
    var killed: Bool { agg.killed }
    var spent: Double { agg.spentMicrousd.usd }
    var budget: Double? { budgetMicros?.usd }
    var hasBudget: Bool { (budgetMicros ?? 0) > 0 }
    /// spent / budget, or 0 when no budget is set (fuse renders neutral).
    var fraction: Double {
        guard let b = budgetMicros, b > 0 else { return 0 }
        return Double(agg.spentMicrousd) / Double(b)
    }
}

/// Loads the fleet from the control plane and shapes it for the Runs screen.
@MainActor
@Observable
final class RunsStore {
    enum Phase: Equatable {
        case idle, loading, loaded, failed(String)
    }

    private(set) var phase: Phase = .idle
    private(set) var runs: [RunDisplay] = []
    private(set) var summary: Summary?
    private(set) var totalCapsMicros: Int64 = 0

    var totalCaps: Double { totalCapsMicros.usd }

    /// Load the fleet. On first entry the SwiftData cache is shown immediately
    /// (instant / offline), then the plane is refreshed and the cache rewritten.
    /// A network failure keeps the cached rows visible.
    func load(using client: APIClient, org: String, context: ModelContext?) async {
        if runs.isEmpty, let context, let cached = Self.readCache(org: org, context: context), !cached.isEmpty {
            runs = cached
            phase = .loaded
        } else if phase != .loaded {
            phase = .loading
        }

        do {
            async let runsReq = client.runs()
            async let summaryReq = client.summary()
            async let budgetsReq = client.budgets()
            let (runs, summary, budgets) = try await (runsReq, summaryReq, budgetsReq)

            self.summary = summary
            self.totalCapsMicros = budgets.values.reduce(0, +)
            self.runs = runs
                .map { RunDisplay(agg: $0, budgetMicros: budgets[$0.runId]) }
                .sorted { $0.fraction > $1.fraction }
            self.phase = .loaded
            if let context { Self.writeCache(org: org, runs: self.runs, context: context) }
        } catch {
            // Keep showing the cache if we have it; only surface an error when bare.
            if runs.isEmpty { self.phase = .failed(error.localizedDescription) }
        }
    }

    private static func readCache(org: String, context: ModelContext) -> [RunDisplay]? {
        let descriptor = FetchDescriptor<CachedRun>(predicate: #Predicate { $0.org == org })
        guard let cached = try? context.fetch(descriptor) else { return nil }
        return cached.map(\.display).sorted { $0.fraction > $1.fraction }
    }

    private static func writeCache(org: String, runs: [RunDisplay], context: ModelContext) {
        let descriptor = FetchDescriptor<CachedRun>(predicate: #Predicate { $0.org == org })
        for stale in (try? context.fetch(descriptor)) ?? [] { context.delete(stale) }
        for run in runs { context.insert(CachedRun(org: org, run: run)) }
        try? context.save()
    }
}
