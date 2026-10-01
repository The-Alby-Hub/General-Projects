import Foundation

/// Why the identity was locked (SECURITY.md D29).
public enum LockReason: Sendable, Equatable {
    /// The user chose Lock.
    case manual
    /// Chotam is quitting, including when its window is closed.
    case quit
    case screenLocked
    case screenSaverStarted
    case sleep
    /// Fast user switching: another user took over the screen.
    case sessionSwitched
    /// No key press, click or scroll in Chotam for the idle timeout.
    case idle

    /// Shown under the unlock field, so a lock is never a mystery.
    public var explanation: String {
        switch self {
        case .manual: "Locked."
        case .quit: "Locked."
        case .screenLocked: "Locked because the screen was locked."
        case .screenSaverStarted: "Locked because the screen saver started."
        case .sleep: "Locked because the Mac went to sleep."
        case .sessionSwitched: "Locked because another user switched in."
        case .idle: "Locked after a period of inactivity."
        }
    }
}

/// The idle timeout setting: 1, 5, 10 or 30 minutes, 10 by default, never "never"
/// (SECURITY.md D29). Stored in `UserDefaults`: Chotam's only preference, not secret.
public enum IdleTimeout {
    public static let choices = [1, 5, 10, 30]
    public static let defaultMinutes = 10
    public static let defaultsKey = "idleLockMinutes"

    /// The stored choice, or the default if nothing valid is stored.
    public static func minutes(in defaults: UserDefaults) -> Int {
        let stored = defaults.integer(forKey: defaultsKey)
        return choices.contains(stored) ? stored : defaultMinutes
    }

    /// Stores `minutes` if it's one of the choices; anything else is ignored.
    public static func store(_ minutes: Int, in defaults: UserDefaults) {
        guard choices.contains(minutes) else { return }
        defaults.set(minutes, forKey: defaultsKey)
    }
}

/// Tracks activity for the idle timeout. Times are passed in, so tests need no waiting.
///
/// Idle means no input in Chotam's windows for `timeout` (the app feeds key presses,
/// clicks and scrolls from a local event monitor). A running operation counts as
/// activity, so the idle timeout never cuts one off; when it ends, the clock restarts.
@MainActor
public final class IdleClock {
    public var timeout: TimeInterval
    public private(set) var lastActivity: Date
    public private(set) var runningOperations = 0

    public init(timeout: TimeInterval, now: Date) {
        self.timeout = timeout
        self.lastActivity = now
    }

    public func noteActivity(at now: Date) {
        lastActivity = max(lastActivity, now)
    }

    public func operationStarted(at now: Date) {
        runningOperations += 1
        noteActivity(at: now)
    }

    public func operationEnded(at now: Date) {
        runningOperations = max(0, runningOperations - 1)
        noteActivity(at: now)
    }

    public func isIdle(at now: Date) -> Bool {
        runningOperations == 0 && now.timeIntervalSince(lastActivity) >= timeout
    }
}
