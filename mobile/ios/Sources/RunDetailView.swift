import SwiftUI

/// One run in full: a big instrument readout, the fuse, stats, and a signed
/// Kill. (Swift Charts burn history joins in B6; the slide-to-arm + Face ID
/// gate is B5.)
struct RunDetailView: View {
    let run: RunDisplay
    let account: Account
    var onMutated: () async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var confirmKill = false
    @State private var busy = false
    @State private var error: String?

    private var heat: Heat { Heat.of(fraction: run.fraction) }

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    gauge
                    stats
                    if !run.killed { killButton }
                }
                .padding(20)
            }
        }
        .foregroundStyle(Palette.fg)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Text(run.agg.runId).font(.system(.body, design: .monospaced)).foregroundStyle(Palette.dim)
            }
        }
        .alert("Kill run \(run.agg.runId)?", isPresented: $confirmKill) {
            Button("Kill", role: .destructive) { kill() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Signed on this iPhone and enforced across every gateway.")
        }
        .alert("Couldn't kill the run", isPresented: errorBinding) {
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
                Text("of $\(String(format: "%.2f", budget)) · \(Int((run.fraction * 100).rounded()))%")
                    .font(.mono).foregroundStyle(Palette.dim)
                Fuse(fraction: run.fraction, height: 12).padding(.top, 6)
            } else {
                Text("no cap set").font(.mono).foregroundStyle(Palette.faint)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

    private var stats: some View {
        HStack(spacing: 9) {
            StatTile(label: "Steps", value: "\(run.agg.steps)")
            StatTile(label: "Calls", value: "\(run.agg.calls)")
            StatTile(label: "Cache", value: "\(run.agg.cacheHits)")
        }
    }

    private var killButton: some View {
        Button {
            confirmKill = true
        } label: {
            HStack {
                if busy { ProgressView().tint(.white) }
                Image(systemName: "bolt.slash.fill")
                Text(busy ? "Killing…" : "Kill run")
            }
            .font(.system(size: 16, weight: .bold))
            .frame(maxWidth: .infinity).padding(.vertical, 15)
            .background(
                LinearGradient(colors: [Color(hex: 0xFF6B60), Color(hex: 0xE23E33)],
                               startPoint: .top, endPoint: .bottom),
                in: RoundedRectangle(cornerRadius: 16)
            )
            .foregroundStyle(.white)
        }
        .disabled(busy)
        .padding(.top, 6)
        .overlay(alignment: .bottom) {
            Text("Signed by this device")
                .font(.system(size: 10, design: .monospaced)).foregroundStyle(Palette.faint)
                .offset(y: 22)
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { error != nil }, set: { if !$0 { error = nil } })
    }

    private func kill() {
        busy = true
        Task {
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
