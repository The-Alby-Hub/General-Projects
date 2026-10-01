import Foundation
import XCTest
@testable import ChotamAppModel
@testable import EncryptionCore

/// When the identity locks (SECURITY.md D29): the idle timeout and its setting, system
/// events, and running operations. Times are passed in; nothing waits.
final class AppSessionTests: XCTestCase {
    private let start = Date(timeIntervalSinceReferenceDate: 800_000_000)

    @MainActor
    private func unlockedSession(defaults: UserDefaults = scratchDefaults()) async throws -> (TestStore, AppSession) {
        let store = try TestStore()
        try store.makeExisting()
        let session = AppSession(store: store, defaults: defaults, now: start)
        await session.identity.load()
        await session.identity.unlock(passphrase: testPassphrase, keyFile: nil)
        XCTAssertTrue(session.identity.isUnlocked)
        return (store, session)
    }

    // MARK: The setting

    @MainActor
    func testIdleTimeoutDefaultsTo10MinutesAndOnlyAcceptsTheChoices() {
        let defaults = scratchDefaults()
        XCTAssertEqual(IdleTimeout.choices, [1, 5, 10, 30], "no 'never'")
        XCTAssertEqual(IdleTimeout.minutes(in: defaults), 10)

        IdleTimeout.store(5, in: defaults)
        XCTAssertEqual(IdleTimeout.minutes(in: defaults), 5)
        IdleTimeout.store(0, in: defaults)
        IdleTimeout.store(1440, in: defaults)
        XCTAssertEqual(IdleTimeout.minutes(in: defaults), 5, "other values are ignored")

        // A value written by something else falls back to the default.
        defaults.set(7, forKey: IdleTimeout.defaultsKey)
        XCTAssertEqual(IdleTimeout.minutes(in: defaults), 10)
        defaults.set("never", forKey: IdleTimeout.defaultsKey)
        XCTAssertEqual(IdleTimeout.minutes(in: defaults), 10)
    }

    @MainActor
    func testSessionReadsAndWritesTheSetting() throws {
        let defaults = scratchDefaults()
        IdleTimeout.store(30, in: defaults)
        let session = AppSession(store: try TestStore(), defaults: defaults, now: start)
        XCTAssertEqual(session.idleMinutes, 30)
        session.setIdleMinutes(1)
        XCTAssertEqual(session.idleMinutes, 1)
        XCTAssertEqual(defaults.integer(forKey: IdleTimeout.defaultsKey), 1)
        session.setIdleMinutes(0)
        XCTAssertEqual(session.idleMinutes, 1, "refused")
    }

    // MARK: Idle

    @MainActor
    func testLocksAfterTheIdleTimeoutAndNotBefore() async throws {
        let (_, session) = try await unlockedSession()
        session.noteActivity(at: start)
        session.checkIdle(at: start.addingTimeInterval(9 * 60 + 59))
        XCTAssertTrue(session.identity.isUnlocked)

        session.noteActivity(at: start.addingTimeInterval(9 * 60))
        session.checkIdle(at: start.addingTimeInterval(18 * 60))
        XCTAssertTrue(session.identity.isUnlocked, "activity restarted the clock")

        session.checkIdle(at: start.addingTimeInterval(19 * 60))
        XCTAssertFalse(session.identity.isUnlocked)
        XCTAssertEqual(session.identity.lastLockReason, .idle)
    }

    @MainActor
    func testShorterTimeoutAppliesAtOnce() async throws {
        let (_, session) = try await unlockedSession()
        session.noteActivity(at: start)
        session.setIdleMinutes(1)
        session.checkIdle(at: start.addingTimeInterval(61))
        XCTAssertFalse(session.identity.isUnlocked)
    }

    @MainActor
    func testRunningOperationCountsAsActivity() async throws {
        let (_, session) = try await unlockedSession()
        session.noteActivity(at: start)
        session.operationStarted(at: start.addingTimeInterval(60))
        session.checkIdle(at: start.addingTimeInterval(3600))
        XCTAssertTrue(session.identity.isUnlocked, "never locks in the middle of an operation")

        // When it ends, the clock restarts from then.
        session.operationEnded(at: start.addingTimeInterval(3600))
        session.checkIdle(at: start.addingTimeInterval(3600 + 9 * 60))
        XCTAssertTrue(session.identity.isUnlocked)
        session.checkIdle(at: start.addingTimeInterval(3600 + 10 * 60))
        XCTAssertFalse(session.identity.isUnlocked)
    }

    @MainActor
    func testIdleCheckIsHarmlessWhenLocked() async throws {
        let (_, session) = try await unlockedSession()
        session.identity.lock(reason: .manual)
        session.checkIdle(at: start.addingTimeInterval(86_400))
        XCTAssertNil(session.identity.lastLockReason, "no second lock, no new reason")
    }

    // MARK: System events

    @MainActor
    func testEverySystemEventLocks() async throws {
        let events: [LockReason] = [.quit, .screenLocked, .screenSaverStarted, .sleep, .sessionSwitched]
        for event in events {
            let (_, session) = try await unlockedSession()
            let identity = try XCTUnwrap(session.identity.unlockedIdentity)
            session.systemEvent(event)
            XCTAssertTrue(identity.isLocked, "\(event)")
            XCTAssertEqual(session.identity.state.name, "locked")
            XCTAssertFalse(event.explanation.isEmpty)
        }
    }
}
