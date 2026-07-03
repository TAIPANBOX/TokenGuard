import SwiftUI

/// The signature kill control — a physical breaker you slide to arm, then
/// release to fire. Deliberate by design; the parent gates the fire with Face ID
/// and signs the request on-device.
struct BreakerView: View {
    var idleLabel = "Slide to arm kill"
    var armedLabel = "Release to kill"
    var onFire: () -> Void

    @State private var offset: CGFloat = 0
    @State private var armed = false

    private let knob: CGFloat = 52
    private let height: CGFloat = 62

    var body: some View {
        GeometryReader { geo in
            let maxOffset = max(0, geo.size.width - knob - 8)
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 18)
                    .fill(Color(hex: 0x0C1117))
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(Palette.ember.opacity(0.3)))

                RoundedRectangle(cornerRadius: 18)
                    .fill(LinearGradient(
                        colors: [Palette.ember.opacity(0.30), Palette.ember.opacity(0.02)],
                        startPoint: .leading, endPoint: .trailing))
                    .frame(width: offset + knob + 4)

                Text(armed ? armedLabel : idleLabel)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(armed ? .white : Color(hex: 0xFFB3AD))
                    .frame(maxWidth: .infinity)
                    .padding(.leading, 30)

                knobView
                    .offset(x: offset + 4)
                    .gesture(
                        DragGesture(minimumDistance: 0)
                            .onChanged { value in
                                offset = min(maxOffset, max(0, value.translation.width))
                                armed = offset > maxOffset * 0.88
                            }
                            .onEnded { _ in
                                if armed { onFire() }
                                withAnimation(.spring(response: 0.3)) {
                                    offset = 0
                                    armed = false
                                }
                            }
                    )
            }
        }
        .frame(height: height)
        .accessibilityElement()
        .accessibilityLabel("Slide to arm kill")
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { onFire() }
    }

    private var knobView: some View {
        RoundedRectangle(cornerRadius: 14)
            .fill(LinearGradient(colors: [Color(hex: 0xFF6B60), Color(hex: 0xE23E33)],
                                 startPoint: .top, endPoint: .bottom))
            .frame(width: knob, height: knob)
            .overlay(
                Image(systemName: "power")
                    .font(.system(size: 22, weight: .bold))
                    .foregroundStyle(.white)
            )
            .shadow(color: Palette.ember.opacity(0.6), radius: 8, y: 3)
    }
}
