import SwiftUI

/// The wrist glance: the fleet's burn rate up top, then every run as a fuse —
/// hottest first, over-cap in ember. Reads the live fleet from the plane
/// (shared `RunsStore`, no on-watch cache in W1).
struct WatchFleetView: View {
    let client: APIClient
    let org: String
    @State private var store = RunsStore()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 9) {
                header
                if store.totalCapsMicros > 0, let summary = store.summary {
                    Fuse(fraction: summary.spentMicrousd.usd / store.totalCaps, height: 7)
                }
                if case .failed = store.phase, store.runs.isEmpty {
                    Text("Can't reach the plane.")
                        .font(.system(size: 12)).foregroundStyle(Palette.ember)
                        .padding(.top, 6)
                } else if store.phase == .loading && store.runs.isEmpty {
                    ProgressView().tint(Palette.mint)
                        .frame(maxWidth: .infinity).padding(.top, 12)
                } else {
                    ForEach(store.runs) { run in
                        WatchRunRow(run: run)
                    }
                }
            }
            .padding(.horizontal, 3)
            .padding(.bottom, 6)
        }
        .containerBackground(Palette.ink.gradient, for: .navigation)
        .task { await store.load(using: client, org: org, context: nil) }
        .refreshable { await store.load(using: client, org: org, context: nil) }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text("FLEET BURN")
                .font(.system(size: 9, weight: .semibold)).tracking(1.4)
                .foregroundStyle(Palette.faint)
            HStack(alignment: .firstTextBaseline, spacing: 3) {
                Text(String(format: "%.2f", store.fleetRate))
                    .font(.system(size: 30, weight: .heavy)).monospacedDigit()
                Text("$/m").font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(Palette.amber)
                Spacer()
                if let summary = store.summary {
                    Text(usd(summary.spentMicrousd.usd))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Palette.dim)
                }
            }
        }
    }

    private func usd(_ value: Double) -> String { String(format: "$%.2f", value) }
}

/// One run on the wrist: id + spend, and its fuse when a cap is set.
struct WatchRunRow: View {
    let run: RunDisplay

    var body: some View {
        let heat = Heat.of(fraction: run.fraction)
        let over = !run.killed && run.hasBudget && heat == .over
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Text(run.agg.runId).font(.system(size: 13, design: .monospaced))
                if run.killed {
                    Text("KILLED").font(.system(size: 8, weight: .semibold)).tracking(0.6)
                        .foregroundStyle(Palette.faint)
                }
                Spacer()
                Text("$\(String(format: "%.2f", run.spent))")
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(over ? Palette.ember : (run.killed ? Palette.dim : Palette.fg))
            }
            if run.hasBudget {
                Fuse(fraction: run.fraction, height: 6)
            }
        }
        .padding(8)
        .background(
            over ? AnyShapeStyle(Palette.ember.opacity(0.08))
                 : AnyShapeStyle(Palette.panel.opacity(0.55)),
            in: RoundedRectangle(cornerRadius: 11)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 11)
                .stroke(over ? Palette.ember.opacity(0.4) : Palette.line)
        )
        .opacity(run.killed ? 0.5 : 1)
    }
}
