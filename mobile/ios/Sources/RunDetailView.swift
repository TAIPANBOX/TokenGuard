@preconcurrency import ActivityKit
import SwiftUI

/// One run in full: a big instrument readout, the fuse, stats, the slide-to-arm
/// kill breaker (Face ID + signed on-device), and Set budget. (Swift Charts burn
/// history joins in B6.)
struct RunDetailView: View {
    let run: RunDisplay
    let account: Account
    var onMutated: () async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var error: String?
    @State private var showBudget = false
    @State private var series: [SeriesBucket] = []
    @State private var rate: Double = 0
    @State private var activity: Activity<BurnAttributes>?

    private var heat: Heat { Heat.of(fraction: run.fraction) }

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    gauge
                    if !series.isEmpty { chartCard }
                    stats
                    if !run.killed { actions }
                }
                .padding(20)
            }
        }
        .task {
            series = (try? await account.reads.series(run: run.agg.runId, window: "1h", step: "60s")) ?? []
            rate = series.burnRatePerMin(stepSeconds: 60)
            // Screenshot hook: auto-start the Live Activity for this run.
            if LaunchArgs.value("-liveRun") == run.agg.runId, activity == nil {
                activity = LiveBurn.start(run: run, org: account.session.org, rate: rate)
            }
        }
        .foregroundStyle(Palette.fg)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Text(run.agg.runId).font(.system(.body, design: .monospaced)).foregroundStyle(Palette.dim)
            }
        }
        .sheet(isPresented: $showBudget) {
            BudgetSheet(run: run) { usd in setBudget(usd) }
        }
        .alert("Something went wrong", isPresented: errorBinding) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(error ?? "")
        }
    }

    private var gauge: some View {
        VStack(alignment: .center, spacing: 8) {
            Text(run.killed ? "SPENT · KILLED" : "SPENT")
                .font(.system(size: 10, weight: .semibold)).tracking(2)
                .foregroundStyle(run.killed ? Palette.dim : Palette.faint)
            Text(String(format: "$%.2f", run.spent))
                .font(.instrument(56)).monospacedDigit()
                .foregroundStyle(heat == .over && !run.killed ? Palette.ember : Palette.fg)
            if let budget = run.budget {
                Text("of $\(String(format: "%.2f", budget)) · \(Int((run.fraction * 100).rounded()))%\(rateSuffix)")
                    .font(.mono).foregroundStyle(Palette.dim)
                Fuse(fraction: run.fraction, height: 12).padding(.top, 6)
            } else {
                Text("no cap set\(rateSuffix)").font(.mono).foregroundStyle(Palette.faint)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

    private var rateSuffix: String {
        rate > 0 ? " · $\(String(format: "%.2f", rate))/min" : ""
    }

    private var chartCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("BURN · LAST HOUR")
                    .font(.system(size: 10, weight: .semibold)).tracking(1.4)
                    .foregroundStyle(Palette.faint)
                Spacer()
                if rate > 0 {
                    Text("$\(String(format: "%.2f", rate))/min")
                        .font(.mono).foregroundStyle(Palette.amber)
                }
            }
            BurnChart(buckets: series)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.panel, in: RoundedRectangle(cornerRadius: 18))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Palette.line))
    }

    private var stats: some View {
        HStack(spacing: 9) {
            StatTile(label: "Steps", value: "\(run.agg.steps)")
            StatTile(label: "Calls", value: "\(run.agg.calls)")
            StatTile(label: "Cache", value: "\(run.agg.cacheHits)")
        }
    }

    private var actions: some View {
        VStack(spacing: 16) {
            BreakerView { armAndKill() }
                .padding(.top, 4)
            Text("Kill is signed by this device · Face ID")
                .font(.system(size: 10, design: .monospaced)).foregroundStyle(Palette.faint)

            HStack(spacing: 10) {
                secondaryButton(icon: "dial.min", title: "Set budget") { showBudget = true }
                if LiveBurn.isAvailable {
                    secondaryButton(
                        icon: activity == nil ? "bolt.badge.clock" : "stop.circle",
                        title: activity == nil ? "Live Activity" : "Stop"
                    ) { toggleLiveActivity() }
                }
            }
        }
    }

    private func secondaryButton(icon: String, title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                Text(title)
            }
            .font(.system(size: 14, weight: .semibold))
            .frame(maxWidth: .infinity).padding(.vertical, 13)
            .foregroundStyle(Palette.iris)
            .background(Palette.panel, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Palette.line))
        }
        .disabled(busy)
    }

    private func toggleLiveActivity() {
        if let current = activity {
            activity = nil
            Task { await LiveBurn.end(current) }
        } else {
            activity = LiveBurn.start(run: run, org: account.session.org, rate: rate)
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { error != nil }, set: { if !$0 { error = nil } })
    }

    private func armAndKill() {
        Task {
            guard await Biometrics.confirm(reason: "Kill run \(run.agg.runId)") else { return }
            busy = true
            do {
                try await account.kill(run: run.agg.runId)
                await onMutated()
                dismiss()
            } catch {
                self.error = error.localizedDescription
                busy = false
            }
        }
    }

    private func setBudget(_ usd: Double) {
        Task {
            guard await Biometrics.confirm(reason: "Set budget for \(run.agg.runId)") else { return }
            busy = true
            do {
                try await account.setBudget(run: run.agg.runId, usd: usd)
                await onMutated()
                dismiss()
            } catch {
                self.error = error.localizedDescription
                busy = false
            }
        }
    }
}

struct StatTile: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label.uppercased())
                .font(.system(size: 9, weight: .semibold)).tracking(1.2)
                .foregroundStyle(Palette.faint)
            Text(value).font(.instrument(20)).monospacedDigit()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color(hex: 0x0C1117), in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).stroke(Palette.line))
    }
}

/// Enter a central budget (USD) for a run.
struct BudgetSheet: View {
    let run: RunDisplay
    var onSet: (Double) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var text = ""

    private var amount: Double? { Double(text.trimmingCharacters(in: .whitespaces)) }

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            VStack(alignment: .leading, spacing: 18) {
                Text("Set budget")
                    .font(.instrument(26))
                Text("Cap for run \(run.agg.runId), enforced across every gateway.")
                    .font(.mono).foregroundStyle(Palette.dim)

                HStack(spacing: 8) {
                    Text("$").font(.instrument(34)).foregroundStyle(Palette.amber)
                    TextField("0.00", text: $text)
                        .font(.instrument(34)).monospacedDigit()
                        .keyboardType(.decimalPad)
                }
                .padding(14)
                .background(Palette.panel, in: RoundedRectangle(cornerRadius: 14))
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Palette.line))

                Button {
                    if let amount { dismiss(); onSet(amount) }
                } label: {
                    Text("Set · Face ID")
                        .font(.system(size: 16, weight: .bold))
                        .frame(maxWidth: .infinity).padding(.vertical, 14)
                        .background(Palette.iris, in: RoundedRectangle(cornerRadius: 14))
                        .foregroundStyle(.white)
                }
                .disabled(amount == nil)
                .opacity(amount == nil ? 0.5 : 1)
                Spacer()
            }
            .padding(22)
        }
        .foregroundStyle(Palette.fg)
        .presentationDetents([.medium])
        .presentationBackground(Palette.ink)
    }
}
