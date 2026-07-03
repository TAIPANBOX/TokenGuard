import SwiftUI

// The design system in code — mirrors docs/16-design-system.md. Colors, the
// "heat" semantics that drive the fuse, and the instrument type roles.

extension Color {
    /// From a 24-bit RGB hex, e.g. `0x46E3B4`.
    init(hex: UInt) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: 1
        )
    }
}

enum Palette {
    static let ink = Color(hex: 0x0A0E13)
    static let panel = Color(hex: 0x131A23)
    static let panel2 = Color(hex: 0x182230)
    static let fg = Color(hex: 0xEAF0F6)
    static let dim = Color(hex: 0x7E8B9A)
    static let faint = Color(hex: 0x4C596A)
    static let mint = Color(hex: 0x46E3B4)
    static let amber = Color(hex: 0xF4B23E)
    static let ember = Color(hex: 0xFF574B)
    static let iris = Color(hex: 0x6C7BFF)
    static let line = Color.white.opacity(0.08)
}

/// A run's spend against its budget, mapped to the fuse's temperature.
enum Heat: Equatable {
    case within, warming, over

    static func of(fraction: Double) -> Heat {
        if fraction >= 1.0 { return .over }
        if fraction >= 0.8 { return .warming }
        return .within
    }

    /// Left→right gradient stops for the fuse fill.
    var gradient: [Color] {
        switch self {
        case .within: return [Color(hex: 0x2FB98F), Palette.mint]
        case .warming: return [Palette.mint, Palette.amber]
        case .over: return [Palette.amber, Palette.ember]
        }
    }

    /// The single accent for pills, rates and glow.
    var accent: Color {
        switch self {
        case .within: return Palette.mint
        case .warming: return Palette.amber
        case .over: return Palette.ember
        }
    }

    var label: String {
        switch self {
        case .within: return "live"
        case .warming: return "near cap"
        case .over: return "over cap"
        }
    }

    var glow: Double {
        switch self {
        case .within: return 0
        case .warming: return 8
        case .over: return 10
        }
    }
}

/// The TokenFuse emblem — an amber→ember tile with a black-keyline bolt whose
/// interior is the ground showing through. The same mark as the app icon, the
/// web dashboard and the README. Drawn natively so it stays crisp at any size.
struct BrandMark: View {
    var size: CGFloat = 80

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.2237, style: .continuous)
            .fill(
                LinearGradient(
                    colors: [Color(hex: 0xF6B740), Color(hex: 0xFF574B)],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                )
            )
            .overlay(
                BoltShape()
                    .stroke(Palette.ink, style: StrokeStyle(
                        lineWidth: size * 0.07, lineCap: .round, lineJoin: .round))
                    .padding(size * 0.18)
            )
            .frame(width: size, height: size)
            .shadow(color: Color(hex: 0xF6B740).opacity(0.28), radius: size * 0.16, y: size * 0.04)
            .accessibilityLabel("TokenFuse")
    }
}

/// Lucide "zap" bolt (`M13 2 4 14h6l-1 8 9-12h-6z`), drawn in a 24-unit box and
/// fitted, centred, into the given rect.
struct BoltShape: Shape {
    func path(in rect: CGRect) -> Path {
        let pts: [CGPoint] = [
            .init(x: 13, y: 2), .init(x: 4, y: 14), .init(x: 10, y: 14),
            .init(x: 9, y: 22), .init(x: 18, y: 10), .init(x: 12, y: 10),
        ]
        let s = min(rect.width, rect.height) / 24
        let ox = rect.minX + (rect.width - 24 * s) / 2
        let oy = rect.minY + (rect.height - 24 * s) / 2
        var p = Path()
        for (i, pt) in pts.enumerated() {
            let cp = CGPoint(x: ox + pt.x * s, y: oy + pt.y * s)
            if i == 0 { p.move(to: cp) } else { p.addLine(to: cp) }
        }
        p.closeSubpath()
        return p
    }
}

extension Font {
    /// Big tabular instrument number — the number is the display typography.
    static func instrument(_ size: CGFloat) -> Font {
        .system(size: size, weight: .heavy, design: .default)
    }

    /// Data / ids / rates.
    static let mono = Font.system(.footnote, design: .monospaced)
}
