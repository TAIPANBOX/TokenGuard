import LocalAuthentication

/// Face ID / passcode gate in front of destructive, signed actions. On a bare
/// simulator with no biometry or passcode enrolled it allows through — the
/// slide-to-arm gesture was already the deliberate confirmation; a real device
/// always has a passcode, so this evaluates there.
enum Biometrics {
    static func confirm(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        let policy: LAPolicy
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            policy = .deviceOwnerAuthenticationWithBiometrics
        } else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            policy = .deviceOwnerAuthentication
        } else {
            return true
        }
        return await withCheckedContinuation { continuation in
            context.evaluatePolicy(policy, localizedReason: reason) { success, _ in
                continuation.resume(returning: success)
            }
        }
    }
}
