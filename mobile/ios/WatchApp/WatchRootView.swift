import SwiftUI

/// Entry point: show the fleet when the watch has a plane to read, otherwise a
/// short "pair on your iPhone" note (WatchConnectivity fills this in at W2).
struct WatchRootView: View {
    @State private var config = WatchConfig.current()

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            if let config {
                WatchFleetView(
                    client: APIClient(baseURL: config.baseURL, token: config.token),
                    org: config.org
                )
            } else {
                unpaired
            }
        }
        .foregroundStyle(Palette.fg)
    }

    private var unpaired: some View {
        VStack(spacing: 10) {
            BrandMark(size: 46)
            Text("Open TokenFuse on your iPhone to pair, then it appears here.")
                .font(.system(size: 13))
                .multilineTextAlignment(.center)
                .foregroundStyle(Palette.dim)
        }
        .padding()
    }
}
