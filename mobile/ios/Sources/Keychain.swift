import Foundation
import Security

/// Small-secret storage (device token + signing key material). Prefers the
/// Keychain; on unsigned simulator/dev builds the Keychain lacks the entitlement
/// (`errSecMissingEntitlement`, -34018), so it transparently falls back to a
/// protected file in the app sandbox. A signed device always uses the Keychain.
enum Keychain {
    private static let service = "com.taipanbox.tokenfuse.pocket"

    static func set(_ data: Data, for account: String) {
        delete(account)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        if SecItemAdd(query as CFDictionary, nil) != errSecSuccess {
            try? data.write(to: fallbackURL(account), options: [.completeFileProtection])
        }
    }

    static func get(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data {
            return data
        }
        return try? Data(contentsOf: fallbackURL(account))
    }

    static func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
        try? FileManager.default.removeItem(at: fallbackURL(account))
    }

    private static func fallbackURL(_ account: String) -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("tf-secrets", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent(account)
    }
}
