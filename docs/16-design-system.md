# 16 — Design system: TokenFuse

> 🎨 The **iOS / Apple Watch** implementation of this system now lives in the app
> repo: [github.com/TAIPANBOX/tokenfuse-mobile](https://github.com/TAIPANBOX/tokenfuse-mobile).
> The web dashboard here derives from the same system.

**Status:** approved direction (2026-07-03). The single source of truth for the
look of every surface — iOS app, Apple Watch, and the web dashboard. SwiftUI
(`ios/Sources/DesignSystem.swift` in the app repo) and the Next.js dashboard both
derive from the tokens here. Interactive reference mockups live in the app repo's
[`design/`](https://github.com/TAIPANBOX/tokenfuse-mobile/tree/main/design)
(`iphone.html`, `watch.html`, `web-dashboard.html`).

## Concept — "The Fuse Panel"

A fuse carries current until it must break the circuit. TokenFuse is the
panel where you watch the current (an agent's **burn rate**) and pull the
breaker (**kill**). One instrument carries the identity across every screen and
surface: the **fuse** — a burn meter that reads cool while you're under budget,
warms to amber, and turns ember at the cap.

## Color — function, not decoration

Color is a live instrument reading. The fuse and status colors are **semantic**
(a run's spend fraction), not brand accents. Interactive chrome uses a single
non-semantic accent (`iris`) so "you can act here" never collides with "this is
hot".

| Token | Hex | Role |
|---|---|---|
| `ink` | `#0A0E13` | ground (blue-biased near-black, chosen not defaulted) |
| `panel` | `#131A23` | raised glass surface |
| `panel2` | `#182230` | selected / elevated surface |
| `fg` | `#EAF0F6` | primary text (cool white) |
| `dim` | `#7E8B9A` | secondary text |
| `faint` | `#4C596A` | labels, hairline captions |
| `line` | `rgba(255,255,255,.08)` | hairline borders |
| **`mint`** | `#46E3B4` | **within budget** (< 80%) |
| **`amber`** | `#F4B23E` | **warming** (80–99%) |
| **`ember`** | `#FF574B` | **over cap / kill** (≥ 100%, and destructive actions only) |
| `iris` | `#6C7BFF` | interactive chrome only (links, selection, focus) |

**Rules.** Neutrals are biased cool toward the accents (not pure grey). `ember`
is reserved for over-cap state and destructive actions — never decorative.
`iris` never encodes state; semantic hues never style a button's "tap here".

### The fuse gradient (by heat)

- **within** — `#2FB98F → #46E3B4`, no glow.
- **warming** — `#46E3B4 → #F4B23E`, soft amber glow.
- **over** — `#F4B23E → #FF574B`, ember glow.

Heat is `fraction = spent / budget`: `< 0.8` within, `0.8–1.0` warming, `≥ 1.0`
over. The fill can exceed 100% width visually to signal "over cap".

## Type — the number is the hero

Native Apple system fonts (SF), so the app is authentically iOS and needs no
embedding.

- **Instrument** — SF Pro Display, `heavy`, tight tracking (~ -0.03em),
  **tabular / monospaced digits**. Used for the big burn-rate and spend numbers;
  the number itself is the display typography.
- **UI / body** — SF Pro Text (system default).
- **Data** — SF Mono for run ids, `$/min`, timestamps, budgets, model names.
- Uppercase labels get `.16–.22em` letter-spacing; keep them small and faint.

## Layout & information design

A dashboard is scanned and operated, not read. Summary before detail: the fleet
burn rate leads, then each run as a fuse. State reads at a glance from **form**
(pill, fuse color, ember row highlight), not just number. The one over cap sorts
itself to the top, in ember.

Signature interactions:

- **Kill is a physical breaker, not a button.** iPhone: slide-to-arm →
  Face ID → fire. Watch: Digital Crown (or Ultra Action Button) to arm → tap.
  Dashboard: Kill → Confirm (armed). The request is signed on-device (Secure
  Enclave) — reinforced in copy at every kill.
- **Live, not polled.** Burn rate ticks and the event feed streams from the
  control plane's SSE (`/v1/stream`); the Dynamic Island / Live Activity / Lock
  Screen carry the burn rate so you glance, not open.

## Motion

Restrained and purposeful: the active fuse's live tick, the breaker drag, a scan
sweep on pairing. Everything honors `prefers-reduced-motion` (and the SwiftUI
equivalent, `accessibilityReduceMotion`).

## Surfaces

One product, three surfaces, one identity:

- **iPhone / iPad** — native SwiftUI app (`mobile/ios/`).
- **Apple Watch** — Series + Ultra (v1.1); the Ultra Action Button arms the kill.
- **Web dashboard** — `cloud/dashboard` (Next.js), restyled to these tokens.

The API layer for the app and the dashboard is generated from the same
`openapi.json` (see [14-mobile-companion.md](14-mobile-companion.md), A6), so the
data contract is shared just as the visual language is.
