import CryptoKit
import XCTest

@testable import TokenFuse

/// The client crypto that authorizes mutations. Wire interop with the Rust
/// server (p256) is proven live; these lock down the format + a sign/verify
/// round-trip locally.
final class SigningTests: XCTestCase {
    func testCanonicalStringMatchesTheServerFormat() {
        let canonical = Canonical.string(
            method: "POST", path: "/v1/runs/r1/kill", body: Data(), ts: 100, nonce: "n1"
        )
        // Five LF-joined lines; empty-body SHA-256 in lowercase hex.
        let lines = canonical.split(separator: "\n", omittingEmptySubsequences: false)
        XCTAssertEqual(lines.count, 5)
        XCTAssertEqual(lines[0], "POST")
        XCTAssertEqual(lines[1], "/v1/runs/r1/kill")
        XCTAssertEqual(lines[2], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(lines[3], "100")
        XCTAssertEqual(lines[4], "n1")
    }

    func testCanonicalHashesTheBody() {
        let body = Data(#"{"budget_usd":2.5}"#.utf8)
        let canonical = Canonical.string(method: "POST", path: "/p", body: body, ts: 1, nonce: "n")
        let expected = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(canonical.contains(expected))
    }

    func testSoftwareKeySignsAndVerifies() throws {
        let priv = P256.Signing.PrivateKey()
        let key = SoftwareDeviceKey(key: priv)

        // Public key is SEC1/X9.63 uncompressed (65 bytes).
        XCTAssertEqual(key.publicKeyX963.count, 65)

        let canonical = Canonical.string(method: "POST", path: "/v1/runs/r1/kill", body: Data(), ts: 100, nonce: "n1")
        let raw = try key.sign(Data(canonical.utf8))
        XCTAssertEqual(raw.count, 64, "ES256 raw r‖s is 64 bytes")

        // The signature verifies with the matching public key (as the server does).
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        XCTAssertTrue(priv.publicKey.isValidSignature(signature, for: Data(canonical.utf8)))
    }

    func testKeyPersistsAndRestores() throws {
        let key = try DeviceKeyFactory.generate()
        let (kind, material) = key.persist()
        let restored = try DeviceKeyFactory.restore(kind: kind, material: material)
        XCTAssertEqual(restored.publicKeyX963, key.publicKeyX963)
    }
}
