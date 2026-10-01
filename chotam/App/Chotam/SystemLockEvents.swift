import AppKit
import ChotamAppModel

/// The system events that lock the identity at once (SECURITY.md D29).
///
/// Sleep and fast user switching are documented `NSWorkspace` notifications. macOS has
/// no public API for "the screen locked" or "the screen saver started", so those use
/// the distributed notifications many apps rely on. They must be checked by hand on
/// each new macOS release (§5.28).
@MainActor
final class SystemLockEvents {
    private var observers: [(center: NotificationCenter, token: any NSObjectProtocol)] = []

    init(onLock: @escaping @MainActor (LockReason) -> Void) {
        let workspace = NSWorkspace.shared.notificationCenter
        observe(workspace, NSWorkspace.willSleepNotification, .sleep, onLock)
        observe(workspace, NSWorkspace.sessionDidResignActiveNotification, .sessionSwitched, onLock)

        let distributed = DistributedNotificationCenter.default()
        observe(distributed, Notification.Name("com.apple.screenIsLocked"), .screenLocked, onLock)
        observe(distributed, Notification.Name("com.apple.screensaver.didstart"), .screenSaverStarted, onLock)
    }

    private func observe(
        _ center: NotificationCenter, _ name: Notification.Name, _ reason: LockReason,
        _ onLock: @escaping @MainActor (LockReason) -> Void
    ) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { onLock(reason) }
        }
        observers.append((center, token))
    }
}
