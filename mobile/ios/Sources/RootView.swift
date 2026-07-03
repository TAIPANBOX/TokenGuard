import SwiftUI

/// Shows the fleet when a paired session exists, otherwise the pairing screen.
/// The session (device token + signing key) lives in the Keychain.
struct RootView: View {
    @State private var account: Account?
    @State private var restored = false

    var body: some View {
        Group {
            if let account {
                RunsView(account: account, onUnpair: unpair)
            } else {
                PairView { account = $0 }
            }
        }
        .task {
            guard !restored else { return }
            restored = true
            if let (session, key) = SessionStore.load() {
                account = Account(session: session, key: key)
            }
        }
        .onChange(of: Router.shared.apnsToken) { _, token in
            if let account, let token {
                Task { await account.registerAPNs(token: token) }
            }
        }
    }

    private func unpair() {
        SessionStore.clear()
        account = nil
    }
}
