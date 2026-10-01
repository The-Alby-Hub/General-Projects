import Foundation
import XCTest
@testable import ChotamAppModel
@testable import EncryptionCore

/// The identity flows the views drive: create, confirm, lock, unlock, restore, forget,
/// and "a lock always wins" (SECURITY.md D29, D34).
final class IdentityModelTests: XCTestCase {
    @MainActor
    func testNoIdentityThenCreateShowsThePassphraseOnce() async throws {
        let store = try TestStore()
        let model = IdentityModel(store: store)
        XCTAssertEqual(model.state.name, "loading")
        await model.load()
        XCTAssertEqual(model.state.name, "noIdentity")

        await model.create(name: "  Alice  ", keyFile: nil)
        guard case .newPassphrase(let publicIdentity, let reveal) = model.state else {
            return XCTFail("expected the passphrase, got \(model.state.name)")
        }
        XCTAssertEqual(publicIdentity.suggestedName, "Alice", "the name is trimmed")
        XCTAssertEqual(reveal.words.count, IdentityPassphrase.defaultWordCount)
        XCTAssertEqual(reveal.words.map(\.number), Array(1 ... IdentityPassphrase.defaultWordCount))
        XCTAssertTrue(model.holdsKeys)
        XCTAssertNil(model.contacts, "no contacts until the passphrase is confirmed")

        model.confirmPassphraseWrittenDown()
        XCTAssertEqual(model.state.name, "unlocked")
        XCTAssertNotNil(model.contacts)
        XCTAssertEqual(model.unlockedIdentity?.publicIdentity, publicIdentity)
        XCTAssertEqual(try store.storedIdentity(), publicIdentity)

        // The words are gone from the state, and the same words unlock it again.
        model.lock(reason: .manual)
        XCTAssertEqual(model.state.name, "locked")
        await model.unlock(passphrase: reveal.words.map(\.text).joined(separator: " "), keyFile: nil)
        XCTAssertEqual(model.state.name, "unlocked")
    }

    @MainActor
    func testLockDropsKeysAndContacts() async throws {
        let store = try TestStore()
        try store.makeExisting()
        let model = IdentityModel(store: store)
        await model.load()
        await model.unlock(passphrase: testPassphrase, keyFile: nil)
        let identity = try XCTUnwrap(model.unlockedIdentity)
        XCTAssertNotNil(model.contacts)

        let recorder = LockRecorder()
        model.onLock = { recorder.reasons.append($0) }
        model.lock(reason: .screenLocked)

        XCTAssertTrue(identity.isLocked, "the keys are wiped")
        XCTAssertFalse(model.holdsKeys)
        XCTAssertNil(model.contacts)
        XCTAssertEqual(model.state.name, "locked")
        XCTAssertEqual(model.lastLockReason, .screenLocked)
        XCTAssertEqual(recorder.reasons, [.screenLocked])

        // Locking again is harmless; a manual lock shows no reason.
        await model.unlock(passphrase: testPassphrase, keyFile: nil)
        model.lock(reason: .manual)
        XCTAssertNil(model.lastLockReason)
    }

    @MainActor
    func testWrongPassphraseShowsThePublicMessage() async throws {
        let store = try TestStore()
        try store.makeExisting()
        let model = IdentityModel(store: store)
        await model.load()

        await model.unlock(passphrase: "absolute able abroad abruptly absence absinthe absolve", keyFile: nil)
        XCTAssertEqual(model.state.name, "locked")
        XCTAssertEqual(model.message, "Wrong passphrase or key file.")

        await model.unlock(passphrase: "not a passphrase", keyFile: nil)
        XCTAssertEqual(model.message, "A passphrase is 7 to 10 different words from Chotam's word list.")
        XCTAssertFalse(model.isWorking)
    }

    @MainActor
    func testKeyFileIsRequiredBeforeUnlocking() async throws {
        let store = try TestStore()
        let keyFile = try store.file("key.bin", Array(repeating: 7, count: 1000))
        try store.makeExisting(keyFile: keyFile)
        let model = IdentityModel(store: store)
        await model.load()
        XCTAssertTrue(model.requiresKeyFile, "known while locked, from the public .pqid")

        await model.unlock(passphrase: testPassphrase, keyFile: nil)
        XCTAssertEqual(model.message, "This identity needs its key file.")
        await model.unlock(passphrase: testPassphrase, keyFile: keyFile)
        XCTAssertEqual(model.state.name, "unlocked")
    }

    /// A lock that arrives while the keys are still being derived wins: the unlocked
    /// identity is locked and dropped when it arrives.
    @MainActor
    func testLockDuringUnlockWins() async throws {
        let store = try TestStore(pauseUnlock: true)
        try store.makeExisting()
        let model = IdentityModel(store: store)
        await model.load()

        let unlocking = Task { await model.unlock(passphrase: testPassphrase, keyFile: nil) }
        await waitUntilSignalled(store.entered)
        XCTAssertTrue(model.isWorking)
        model.lock(reason: .sleep)
        store.resume.signal()
        await unlocking.value

        XCTAssertEqual(model.state.name, "locked")
        XCTAssertFalse(model.holdsKeys)
        XCTAssertNil(model.contacts)
        XCTAssertFalse(model.isWorking)
    }

    /// A lock while the new passphrase is on screen drops the keys but keeps the words,
    /// so they can still be written down; confirming then leads to the locked state.
    @MainActor
    func testLockWhileShowingThePassphraseKeepsTheWords() async throws {
        let store = try TestStore()
        let model = IdentityModel(store: store)
        await model.load()
        await model.create(name: "Alice", keyFile: nil)
        XCTAssertTrue(model.holdsKeys)

        model.lock(reason: .idle)
        XCTAssertFalse(model.holdsKeys)
        XCTAssertEqual(model.state.name, "newPassphrase", "the words stay on screen")

        model.confirmPassphraseWrittenDown()
        XCTAssertEqual(model.state.name, "locked")
    }

    @MainActor
    func testStartOverForgetsTheNewIdentity() async throws {
        let store = try TestStore()
        let model = IdentityModel(store: store)
        await model.load()
        await model.create(name: "Alice", keyFile: nil)
        await model.startOver()
        XCTAssertEqual(model.state.name, "noIdentity")
        XCTAssertNil(try store.storedIdentity())
        XCTAssertFalse(model.holdsKeys)
    }

    @MainActor
    func testRestoreOnANewMac() async throws {
        let original = try TestStore()
        let mine = try original.makeExisting(name: "Alice")
        let newMac = try TestStore()
        let model = IdentityModel(store: newMac)
        await model.load()
        XCTAssertEqual(model.state.name, "noIdentity")

        await model.restore(mine, passphrase: "absolute able abroad abruptly absence absinthe absolve", keyFile: nil)
        XCTAssertEqual(model.message, "Wrong passphrase or key file.")
        XCTAssertNil(try newMac.storedIdentity(), "nothing stored for a wrong passphrase")

        await model.restore(mine, passphrase: testPassphrase.uppercased(), keyFile: nil)
        XCTAssertEqual(model.state.name, "unlocked")
        XCTAssertEqual(try newMac.storedIdentity(), mine)
    }

    @MainActor
    func testForgetThisMac() async throws {
        let store = try TestStore()
        try store.makeExisting()
        let model = IdentityModel(store: store)
        await model.load()
        await model.unlock(passphrase: testPassphrase, keyFile: nil)
        let identity = try XCTUnwrap(model.unlockedIdentity)

        await model.forgetThisMac()
        XCTAssertTrue(identity.isLocked)
        XCTAssertEqual(model.state.name, "noIdentity")
        XCTAssertNil(try store.storedIdentity())
    }

    @MainActor
    func testDamagedIdentityFileIsReportedNotThrown() async throws {
        let store = try TestStore()
        try FileManager.default.createDirectory(at: store.vault.folder, withIntermediateDirectories: true)
        try Data("not an identity".utf8).write(to: store.vault.folder.appendingPathComponent("identity.pqid"))
        let model = IdentityModel(store: store)
        await model.load()
        guard case .unreadable(let message) = model.state else {
            return XCTFail("expected unreadable, got \(model.state.name)")
        }
        XCTAssertEqual(message, "This isn't a valid Chotam identity, or it was damaged.")

        // "Forget this Mac" is the way out.
        await model.forgetThisMac()
        XCTAssertEqual(model.state.name, "noIdentity")
    }

    @MainActor
    func testOnlyOneSlowCallAtATime() async throws {
        let store = try TestStore(pauseUnlock: true)
        try store.makeExisting()
        let model = IdentityModel(store: store)
        await model.load()

        let first = Task { await model.unlock(passphrase: testPassphrase, keyFile: nil) }
        await waitUntilSignalled(store.entered)
        await model.forgetThisMac()
        XCTAssertEqual(model.message, "Chotam is still busy. Try again when it's done.")
        XCTAssertNotNil(try store.storedIdentity(), "the second call did nothing")
        store.resume.signal()
        await first.value
        XCTAssertEqual(model.state.name, "unlocked")
    }
}

@MainActor
final class LockRecorder {
    var reasons: [LockReason] = []
}
