import EncryptionCore
import Foundation
import Observation

/// The app's top-level state: the identity, and when it locks (SECURITY.md D29).
///
/// The app target feeds it what only AppKit can see: input in Chotam's windows
/// (`noteActivity`), a periodic `checkIdle`, and system events (`systemEvent`). The
/// decisions are made here, so they're tested without AppKit.
@MainActor
@Observable
public final class AppSession {
    public let identity: IdentityModel
    /// The idle timeout in minutes: one of `IdleTimeout.choices`.
    public private(set) var idleMinutes: Int

    private let idle: IdleClock
    private let defaults: UserDefaults

    public init(store: any IdentityStore, defaults: UserDefaults, now: Date = Date()) {
        self.defaults = defaults
        let minutes = IdleTimeout.minutes(in: defaults)
        idleMinutes = minutes
        idle = IdleClock(timeout: TimeInterval(minutes * 60), now: now)
        identity = IdentityModel(store: store)
    }

    // MARK: Settings

    public func setIdleMinutes(_ minutes: Int) {
        guard IdleTimeout.choices.contains(minutes) else { return }
        IdleTimeout.store(minutes, in: defaults)
        idleMinutes = minutes
        idle.timeout = TimeInterval(minutes * 60)
    }

    // MARK: Activity and idle

    /// A key press, click or scroll in one of Chotam's windows.
    public func noteActivity(at now: Date = Date()) {
        idle.noteActivity(at: now)
    }

    /// Called every few seconds by the app, and when the Mac wakes. Locks if idle.
    public func checkIdle(at now: Date = Date()) {
        guard identity.holdsKeys, idle.isIdle(at: now) else { return }
        identity.lock(reason: .idle)
    }

    /// A file operation started or ended: while one runs, the idle timeout waits.
    public func operationStarted(at now: Date = Date()) {
        idle.operationStarted(at: now)
    }

    public func operationEnded(at now: Date = Date()) {
        idle.operationEnded(at: now)
    }

    // MARK: System events

    /// Quit, screen lock, screen saver, sleep, fast user switching: lock at once.
    public func systemEvent(_ reason: LockReason) {
        identity.lock(reason: reason)
    }
}
