import Foundation

/// A paired device's identity + read token. Persisted in the Keychain alongside
/// the signing key material.
struct DeviceSession: Codable, Sendable {
    var planeURL: String
    var deviceId: String
    var deviceToken: String
    var org: String
    var role: String
}

/// Persistence for the paired session + signing key (Keychain).
enum SessionStore {
    static func save(_ session: DeviceSession, key: DeviceKey) {
        guard let data = try? JSONEncoder().encode(session) else { return }
        Keychain.set(data, for: "session")
        let (kind, material) = key.persist()
        Keychain.set(Data(kind.utf8), for: "keyKind")
        Keychain.set(material, for: "keyMaterial")
    }

    static func load() -> (DeviceSession, DeviceKey)? {
        guard
            let sessionData = Keychain.get("session"),
            let session = try? JSONDecoder().decode(DeviceSession.self, from: sessionData),
            let kindData = Keychain.get("keyKind"),
            let material = Keychain.get("keyMaterial"),
            let key = try? DeviceKeyFactory.restore(kind: String(decoding: kindData, as: UTF8.self), material: material)
        else { return nil }
        return (session, key)
    }

    static func clear() {
        ["session", "keyKind", "keyMaterial"].forEach(Keychain.delete)
    }
}

/// Redeems a pairing code: generates a device key, submits the public key, and
/// returns the resulting session + key.
enum PairingService {
    struct PairError: LocalizedError {
        let errorDescription: String?
    }

    static func pair(planeURL: String, code: String, deviceName: String) async throws -> (DeviceSession, DeviceKey) {
        guard let base = URL(string: planeURL), base.scheme != nil else {
            throw PairError(errorDescription: "That doesn't look like a URL.")
        }
        let key = try DeviceKeyFactory.generate()
        let payload: [String: String] = [
            "code": code,
            "pubkey_b64": key.publicKeyX963.base64EncodedString(),
            "platform": "ios",
            "name": deviceName,
        ]
        var request = URLRequest(url: base.appending(path: "v1/pair"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        request.httpBody = try JSONSerialization.data(withJSONObject: payload)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw PairError(errorDescription: "No response from the plane.")
        }
        guard http.statusCode == 200 else {
            throw PairError(errorDescription: "Pairing failed — the code may be wrong or expired.")
        }

        struct PairResponse: Decodable {
            let deviceId: String
            let org: String
            let role: String
            let deviceToken: String
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let result = try decoder.decode(PairResponse.self, from: data)
        let session = DeviceSession(
            planeURL: planeURL,
            deviceId: result.deviceId,
            deviceToken: result.deviceToken,
            org: result.org,
            role: result.role
        )
        return (session, key)
    }
}

/// The signed-in device: read client (device token) + signed mutations.
@MainActor
@Observable
final class Account {
    let session: DeviceSession
    private let key: DeviceKey
    let reads: APIClient

    init(session: DeviceSession, key: DeviceKey) {
        self.session = session
        self.key = key
        let base = URL(string: session.planeURL) ?? URL(string: "http://localhost")!
        self.reads = APIClient(baseURL: base, token: session.deviceToken)
    }

    func kill(run: String) async throws {
        let request = try signedRequest(method: "POST", path: "/v1/runs/\(run)/kill", body: Data())
        try await send(request)
    }

    func setBudget(run: String, usd: Double) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["budget_usd": usd])
        let request = try signedRequest(method: "POST", path: "/v1/runs/\(run)/budget", body: body)
        try await send(request)
    }

    /// Register this device's APNs token (signed, best-effort — no-op if remote
    /// registration never succeeds, e.g. without the aps entitlement).
    func registerAPNs(token: Data) async {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        guard
            let body = try? JSONSerialization.data(withJSONObject: ["token": hex]),
            let request = try? signedRequest(method: "POST", path: "/v1/devices/\(session.deviceId)/apns", body: body)
        else { return }
        try? await send(request)
    }

    /// Build an Enclave-signed request (docs/14 §4.2). Signing happens here,
    /// synchronously, so the key never crosses an await boundary.
    private func signedRequest(method: String, path: String, body: Data) throws -> URLRequest {
        let base = URL(string: session.planeURL) ?? URL(string: "http://localhost")!
        let ts = Int(Date().timeIntervalSince1970)
        let nonce = UUID().uuidString
        let canonical = Canonical.string(method: method, path: path, body: body, ts: ts, nonce: nonce)
        let signature = try key.sign(Data(canonical.utf8)).base64EncodedString()

        var request = URLRequest(url: base.appending(path: String(path.drop(while: { $0 == "/" }))))
        request.httpMethod = method
        if !body.isEmpty {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "content-type")
        }
        request.setValue("Bearer \(session.deviceToken)", forHTTPHeaderField: "Authorization")
        request.setValue(session.deviceId, forHTTPHeaderField: "X-Fuse-Device")
        request.setValue(String(ts), forHTTPHeaderField: "X-Fuse-TS")
        request.setValue(nonce, forHTTPHeaderField: "X-Fuse-Nonce")
        request.setValue(signature, forHTTPHeaderField: "X-Fuse-Sig")
        return request
    }

    private func send(_ request: URLRequest) async throws {
        let (_, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw APIClient.ClientError.notHTTP }
        guard (200..<300).contains(http.statusCode) else { throw APIClient.ClientError.http(http.statusCode) }
    }
}
