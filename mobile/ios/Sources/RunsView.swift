import SwiftUI

/// The home deck, live from the paired plane: spent-today hero + fuse, then every
/// run as a fuse — hottest first, over-cap in ember. Long-press a run to kill it;
/// the request is signed on this device. (Per-run/fleet $/min join in B6; the
/// slide-to-arm + Face ID gate is B5.)
struct RunsView: View {
    let account: Account
    var onUnpair: () -> Void

    @Environment(\.modelContext) private var modelContext
    @State private var store = RunsStore()
    @State private var path: [RunDisplay] = []
    @State private var killTarget: RunDisplay?
    @State private var actionError: String?

    private var client: APIClient { account.reads }

    var body: some View {
        NavigationStack(path: $path) {
            ZStack {
                Palette.ink.ignoresSafeArea()
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        header
                        if case .failed(let message) = store.phase {
                            errorCard(message)
                        }
                        if let summary = store.summary {
                            heroCard(summary)
                        }
                        ForEach(store.runs) { run in
                            NavigationLink(value: run) { RunRow(run: run) }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    if !run.killed {
                                        Button(role: .destructive) { killTarget = run } label: {
                                            Label("Kill run", systemImage: "bolt.slash")
                                        }
                                    }
                                }
                        }
                        footerState
                    }
                    .padding(18)
                }
            }
            .navigationDestination(for: RunDisplay.self) { run in
                RunDetailView(run: run, account: account, onMutated: reload)
            }
            .toolbar(.hidden, for: .navigationBar)
            .task { await reload(); openRunIfRequested() }
            .refreshable { await reload() }
            .alert("Kill run \(killTarget?.id ?? "")?", isPresented: killAlertBinding, presenting: killTarget) { run in
                Button("Kill", role: .destructive) { kill(run) }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text("Signed on this iPhone and enforced across every gateway.")
            }
            .alert("Couldn't kill the run", isPresented: errorAlertBinding) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(actionError ?? "")
            }
        }
        .tint(Palette.iris)
        .foregroundStyle(Palette.fg)
    }

    private func reload() async {
        await store.load(using: client, org: account.session.org, context: modelContext)
    }

    private func openRunIfRequested() {
        if path.isEmpty, let id = LaunchArgs.value("-openRun"),
           let run = store.runs.first(where: { $0.id == id }) {
            path = [run]
        }
    }

    private var killAlertBinding: Binding<Bool> {
        Binding(get: { killTarget != nil }, set: { if !$0 { killTarget = nil } })
    }
    private var errorAlertBinding: Binding<Bool> {
        Binding(get: { actionError != nil }, set: { if !$0 { actionError = nil } })
    }

    private func kill(_ run: RunDisplay) {
        Task {
            do {
                try await account.kill(run: run.id)
                await reload()
            } catch {
                actionError = error.localizedDescription
            }
        }
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Runs").font(.instrument(32))
                HStack(spacing: 7) {
                    Circle().fill(store.phase == .loaded ? Palette.mint : Palette.faint)
                        .frame(width: 6, height: 6)
                    Text("\(account.session.org) · \(client.baseURL.host() ?? "plane")")
                        .font(.mono).foregroundStyle(Palette.dim)
                }
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background(Palette.panel, in: Capsule())
                .overlay(Capsule().stroke(Palette.line))
            }
            Spacer()
            Button(action: onUnpair) {
                Image(systemName: "iphone.slash")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Palette.iris)
                    .padding(9)
                    .background(Palette.panel, in: Circle())
                    .overlay(Circle().stroke(Palette.line))
            }
            .accessibilityLabel("Unpair this device")
        }
    }

    private func heroCard(_ summary: Summary) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("SPENT TODAY")
                .font(.system(size: 10, weight: .semibold)).tracking(2)
                .foregroundStyle(Palette.faint)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(usd(summary.spentMicrousd.usd))
                    .font(.instrument(46)).monospacedDigit()
                Spacer()
                Text("\(summary.runs) runs · \(summary.calls) calls")
                    .font(.mono).foregroundStyle(Palette.dim)
            }
            if store.totalCapsMicros > 0 {
                Fuse(fraction: summary.spentMicrousd.usd / store.totalCaps)
                HStack {
                    Text("caps \(usd(store.totalCaps))")
                    Spacer()
                    Text("\(Int((summary.spentMicrousd.usd / store.totalCaps * 100).rounded()))%")
                }
                .font(.mono).foregroundStyle(Palette.dim)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.panel, in: RoundedRectangle(cornerRadius: 20))
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(Palette.line))
    }

    private func errorCard(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("CAN'T REACH THE PLANE").font(.system(size: 10, weight: .semibold)).tracking(1.6)
                .foregroundStyle(Palette.ember)
            Text(message).font(.mono).foregroundStyle(Palette.dim)
            Button("Retry") { Task { await reload() } }
                .font(.system(size: 13, weight: .semibold)).foregroundStyle(Palette.iris)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.ember.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Palette.ember.opacity(0.3)))
    }

    @ViewBuilder private var footerState: some View {
        if store.phase == .loading && store.runs.isEmpty {
            ProgressView().tint(Palette.iris).frame(maxWidth: .infinity).padding(.top, 40)
        } else if store.phase == .loaded && store.runs.isEmpty {
            Text("No runs yet. Send traffic through a gateway and they'll appear here.")
                .font(.mono).foregroundStyle(Palette.faint)
                .frame(maxWidth: .infinity, alignment: .center).padding(.top, 40)
        }
    }

    private func usd(_ value: Double) -> String { String(format: "$%.2f", value) }
}

/// One run: id + status, model/steps + spend, and its fuse (when a cap is set).
struct RunRow: View {
    let run: RunDisplay

    var body: some View {
        let heat = Heat.of(fraction: run.fraction)
        let over = run.killed ? false : (run.hasBudget && heat == .over)
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text(run.agg.runId).font(.system(.callout, design: .monospaced))
                statusPill(heat: heat)
                Spacer()
                Text("$\(String(format: "%.2f", run.spent))")
                    .font(.mono).foregroundStyle(run.killed ? Palette.dim : Palette.fg)
            }
            HStack {
                Text("\(run.agg.model.isEmpty ? "—" : run.agg.model) · step \(run.agg.steps)")
                    .font(.mono).foregroundStyle(Palette.dim)
                Spacer()
                if let budget = run.budget {
                    Text("cap $\(String(format: "%.2f", budget))")
                        .font(.mono).foregroundStyle(Palette.dim)
                }
            }
            if run.hasBudget {
                Fuse(fraction: run.fraction)
            } else {
                Text("no cap set").font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Palette.faint)
            }
        }
        .padding(12)
        .background(
            over ? AnyShapeStyle(Palette.ember.opacity(0.06))
                 : AnyShapeStyle(Palette.panel.opacity(0.4)),
            in: RoundedRectangle(cornerRadius: 16)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(over ? Palette.ember.opacity(0.35) : Palette.line)
        )
        .opacity(run.killed ? 0.55 : 1)
    }

    @ViewBuilder private func statusPill(heat: Heat) -> some View {
        if run.killed {
            pill(text: "killed", color: Palette.faint)
        } else if run.hasBudget {
            StatusPill(heat: heat)
        } else {
            pill(text: "live", color: Palette.mint)
        }
    }

    private func pill(text: String, color: Color) -> some View {
        Text(text.uppercased())
            .font(.system(size: 9, weight: .semibold)).tracking(0.6)
            .foregroundStyle(color)
            .padding(.horizontal, 7).padding(.vertical, 3)
            .background(color.opacity(0.1), in: Capsule())
            .overlay(Capsule().stroke(color.opacity(0.3)))
    }
}
