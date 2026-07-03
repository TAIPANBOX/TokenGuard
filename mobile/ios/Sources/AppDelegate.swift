import UIKit
import UserNotifications

/// Bridges UIKit push plumbing into the SwiftUI app: relays the APNs token and
/// notification taps through `Router`. Real remote delivery needs the `aps`
/// entitlement (an Apple Developer account); without it registration simply
/// fails and push stays off — everything else works.
@MainActor
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        Router.shared.apnsToken = deviceToken
    }

    func application(
        _ application: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        // No aps entitlement (unsigned / no Apple Developer) — remote push off.
    }

    // Show alerts while the app is foregrounded (e.g. simctl push during a demo).
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    // Tapping a push deep-links to its run.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let runId = response.notification.request.content.userInfo["run_id"] as? String
        Task { @MainActor in
            if let runId { Router.shared.openRun = runId }
        }
        completionHandler()
    }
}

/// Notification permission + remote registration.
enum Notifications {
    static func requestIfNeeded() async {
        let center = UNUserNotificationCenter.current()
        guard await center.notificationSettings().authorizationStatus == .notDetermined else { return }
        let granted = (try? await center.requestAuthorization(options: [.alert, .badge, .sound])) ?? false
        if granted {
            await MainActor.run { UIApplication.shared.registerForRemoteNotifications() }
        }
    }
}
