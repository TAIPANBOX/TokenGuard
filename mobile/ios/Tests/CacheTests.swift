import SwiftData
import XCTest

@testable import TokenFusePocket

@MainActor
final class CacheTests: XCTestCase {
    private func inMemoryContext() throws -> ModelContext {
        let container = try ModelContainer(
            for: CachedRun.self,
            configurations: ModelConfiguration(isStoredInMemoryOnly: true)
        )
        return ModelContext(container)
    }

    func testCachedRunRoundTripsToDisplay() throws {
        let context = try inMemoryContext()
        let display = RunDisplay(
            agg: RunAgg(
                runId: "7f3a2b", model: "opus-4-8", spentMicrousd: 26_100_000,
                calls: 312, cacheHits: 4, steps: 41, lastSeenMillis: 100, killed: false
            ),
            budgetMicros: 25_000_000
        )
        context.insert(CachedRun(org: "acme", run: display))
        try context.save()

        let fetched = try context.fetch(FetchDescriptor<CachedRun>())
        XCTAssertEqual(fetched.count, 1)

        let restored = fetched[0].display
        XCTAssertEqual(restored.agg.runId, "7f3a2b")
        XCTAssertEqual(restored.agg.spentMicrousd, 26_100_000)
        XCTAssertEqual(restored.budget, 25.0)
        XCTAssertEqual(restored.agg.steps, 41)
    }

    func testNoBudgetCachesAsNoCap() throws {
        let context = try inMemoryContext()
        let display = RunDisplay(
            agg: RunAgg(
                runId: "4c07af", model: "haiku", spentMicrousd: 1_200_000,
                calls: 6, cacheHits: 0, steps: 6, lastSeenMillis: 0, killed: false
            ),
            budgetMicros: nil
        )
        context.insert(CachedRun(org: "acme", run: display))
        try context.save()

        let restored = try context.fetch(FetchDescriptor<CachedRun>())[0].display
        XCTAssertFalse(restored.hasBudget)
        XCTAssertNil(restored.budget)
    }
}
