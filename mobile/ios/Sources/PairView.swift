import SwiftUI
import UIKit

/// First run: pair this device to an org. The dashboard shows a one-time code
/// (QR on device; entered by hand in the simulator). A P-256 key is generated
/// here — in the Secure Enclave on hardware — and only its public half is sent.
struct PairView: View {
    var onPaired: (Account) -> Void

    @State private var url = "http://localhost:4100"
    @State private var code = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            VStack(alignment: .leading, spacing: 20) {
                Spacer()
                brand
                VStack(alignment: .leading, spacing: 14) {
                    field(label: "PLANE URL", text: $url, placeholder: "https://…")
                    field(label: "PAIRING CODE", text: $code, placeholder: "8-char code")
                }
                if let error {
                    Text(error).font(.mono).foregroundStyle(Palette.ember)
                }
                Button(action: pair) {
                    HStack {
                        if busy { ProgressView().tint(.white) }
                        Text(busy ? "Pairing…" : "Pair this iPhone")
                            .font(.system(size: 16, weight: .bold))
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 14)
                    .background(Palette.iris, in: RoundedRectangle(cornerRadius: 14))
                    .foregroundStyle(.white)
                }
                .disabled(busy || url.isEmpty || code.isEmpty)
                .opacity(busy || url.isEmpty || code.isEmpty ? 0.5 : 1)

                seal
                Spacer()
            }
            .padding(22)
        }
        .foregroundStyle(Palette.fg)
        .task {
            // Screenshot / UI-check hook: pair automatically from launch args.
            if !busy, let u = LaunchArgs.value("-autoPairURL"), let c = LaunchArgs.value("-autoPairCode") {
                url = u
                code = c
                pair()
            }
        }
    }

    private var brand: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("TokenFuse").font(.instrument(30))
            Text("Hold the breaker on your agents.")
                .font(.system(size: 15)).foregroundStyle(Palette.dim)
        }
    }

    private var seal: some View {
        HStack(spacing: 10) {
            Image(systemName: "lock.shield")
                .font(.system(size: 20)).foregroundStyle(Palette.mint)
            Text("A signing key is generated on this iPhone. Kills are signed here — a stolen token alone can't stop your agents.")
                .font(.mono).foregroundStyle(Palette.dim)
        }
        .padding(12)
        .background(Palette.mint.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Palette.mint.opacity(0.22)))
    }

    private func field(label: String, text: Binding<String>, placeholder: String) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(label).font(.system(size: 10, weight: .semibold)).tracking(1.6)
                .foregroundStyle(Palette.faint)
            TextField(placeholder, text: text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.system(.body, design: .monospaced))
                .padding(12)
                .background(Palette.panel, in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Palette.line))
        }
    }

    private func pair() {
        error = nil
        busy = true
        let planeURL = url
        let pairingCode = code.trimmingCharacters(in: .whitespaces)
        let name = UIDevice.current.name
        Task {
            do {
                let (session, key) = try await PairingService.pair(planeURL: planeURL, code: pairingCode, deviceName: name)
                SessionStore.save(session, key: key)
                onPaired(Account(session: session, key: key))
            } catch {
                self.error = error.localizedDescription
                busy = false
            }
        }
    }
}
