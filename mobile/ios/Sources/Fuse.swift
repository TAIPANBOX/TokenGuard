import SwiftUI

/// The signature component: a burn meter that heats as spend nears the budget.
/// Carried across every screen (list rows, run detail, the Dynamic Island).
struct Fuse: View {
    /// spent / budget — may exceed 1.0 to signal "over cap".
    var fraction: Double
    var height: CGFloat = 8

    var body: some View {
        let heat = Heat.of(fraction: fraction)
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Color(hex: 0x0C1117))
                Capsule()
                    .fill(
                        LinearGradient(
                            colors: heat.gradient,
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                    .frame(width: max(4, min(1.0, fraction) * geo.size.width))
                    .shadow(color: heat.accent.opacity(0.5), radius: heat.glow)
                    .animation(.easeOut(duration: 0.5), value: fraction)
            }
        }
        .frame(height: height)
        .overlay(Capsule().stroke(Palette.line, lineWidth: 1))
        .accessibilityElement()
        .accessibilityLabel("Burn \(Int((fraction * 100).rounded())) percent of budget")
    }
}

/// A small status pill coloured by heat.
struct StatusPill: View {
    let heat: Heat

    var body: some View {
        Text(heat.label.uppercased())
            .font(.system(size: 9, weight: .semibold))
            .tracking(0.6)
            .foregroundStyle(heat.accent)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(heat.accent.opacity(0.1), in: Capsule())
            .overlay(Capsule().stroke(heat.accent.opacity(0.35)))
    }
}
