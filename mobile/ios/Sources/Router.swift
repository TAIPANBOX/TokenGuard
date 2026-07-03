import Foundation
import Observation

/// A tiny shared bus for cross-cutting navigation/signals that originate outside
/// the view tree (notification taps, the APNs token from the app delegate).
@MainActor
@Observable
final class Router {
    static let shared = Router()
    /// A run to deep-link to (from a notification tap or a launch arg).
    var openRun: String?
    /// The APNs device token, once the system hands it over.
    var apnsToken: Data?

    private init() {}
}
