import ActivityKit
import SwiftUI
import WidgetKit

/// The burn rate in the Dynamic Island and on the Lock Screen — the fuse, on the
/// system UI. Updated locally by the app (no push required).
struct BurnLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: BurnAttributes.self) { context in
            lockScreen(context.attributes, context.state)
                .padding(14)
                .activityBackground()
        } dynamicIsland: { context in
            let heat = Heat.of(fraction: context.state.fraction)
            return DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Label {
                        Text(context.attributes.runId).font(.system(.footnote, design: .monospaced))
                    } icon: {
                        Image(systemName: "bolt.fill").foregroundStyle(heat.accent)
                    }
                }
                DynamicIslandExpandedRegion(.trailing) {
                    Text("\(rate(context.state))/min")
                        .font(.system(.footnote, design: .monospaced)).foregroundStyle(Palette.amber)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(spacing: 6) {
                        HStack {
                            Text(money(context.state.spentMicrousd)).font(.system(size: 22, weight: .heavy)).monospacedDigit()
                            if context.state.budgetMicros > 0 {
                                Text("of \(money(context.state.budgetMicros))")
                                    .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                        Fuse(fraction: context.state.fraction, height: 8)
                    }
                }
            } compactLeading: {
                Image(systemName: "bolt.fill").foregroundStyle(heat.accent)
            } compactTrailing: {
                Text("\(rate(context.state))/m")
                    .font(.system(.caption2, design: .monospaced)).foregroundStyle(Palette.amber)
            } minimal: {
                Image(systemName: "bolt.fill").foregroundStyle(heat.accent)
            }
            .keylineTint(heat.accent)
        }
    }

    private func lockScreen(_ attributes: BurnAttributes, _ state: BurnAttributes.ContentState) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(attributes.runId, systemImage: "bolt.fill")
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(Heat.of(fraction: state.fraction).accent)
                Spacer()
                Text("\(rate(state))/min")
                    .font(.system(.footnote, design: .monospaced)).foregroundStyle(Palette.amber)
            }
            HStack(alignment: .firstTextBaseline) {
                Text(money(state.spentMicrousd)).font(.system(size: 26, weight: .heavy)).monospacedDigit()
                if state.budgetMicros > 0 {
                    Text("of \(money(state.budgetMicros))")
                        .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                }
                Spacer()
            }
            Fuse(fraction: state.fraction, height: 8)
        }
    }

    private func money(_ micros: Int64) -> String { String(format: "$%.2f", Double(micros) / 1_000_000) }
    private func rate(_ state: BurnAttributes.ContentState) -> String { String(format: "$%.2f", state.ratePerMin) }
}

private extension View {
    func activityBackground() -> some View {
        background(Palette.ink)
    }
}
