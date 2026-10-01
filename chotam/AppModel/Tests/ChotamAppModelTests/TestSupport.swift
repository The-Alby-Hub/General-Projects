import Foundation
import XCTest
@testable import ChotamAppModel
@testable import EncryptionCore

/// A canonical, well-formed passphrase for test identities (7 EFF words).
let testPassphrase = "agreement curve flakily ligament pretty shrimp unbundle"

/// A real `IdentityVault` in a temp folder, creating identities at the cheapest KDF
/// cost an identity may declare (ops 3, 256 MiB), so tests stay fast. Unlocking uses
/// the cost stored in the identity, so it's cheap too.
///
/// `pauseUnlock` lets a test hold an unlock in the middle of its derivation, to check
/// that a lock arriving meanwhile wins.
final class TestStore: IdentityStore, @unchecked Sendable {
    let folder: URL
    let vault: IdentityVault
    /// When set, `unlock` signals `entered` and waits for `resume` before returning.
    let pauseUnlock: Bool
    let entered = DispatchSemaphore(value: 0)
    let resume = DispatchSemaphore(value: 0)

    init(pauseUnlock: Bool = false) throws {
        folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("chotam-appmodel-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        vault = IdentityVault(folder: folder.appendingPathComponent("Chotam", isDirectory: true))
        self.pauseUnlock = pauseUnlock
    }

    deinit {
        try? FileManager.default.removeItem(at: folder)
    }

    func storedIdentity() throws(IdentityError) -> PublicIdentity? {
        try vault.storedIdentity()
    }

    func create(name: String, keyFile: URL?) throws(IdentityError) -> NewIdentity {
        let passphrase = try IdentityPassphrase.generate()
        let identity = try vault.createIdentity(
            name: name, passphrase: passphrase, keyFile: keyFile, cost: IdentityFormat.minimumKDFCost)
        return NewIdentity(identity: identity, passphrase: passphrase)
    }

    func unlock(passphrase: String, keyFile: URL?) throws(IdentityError) -> Identity {
        let identity = try vault.unlock(passphrase: passphrase, keyFile: keyFile)
        if pauseUnlock {
            entered.signal()
            resume.wait()
        }
        return identity
    }

    func restore(_ identity: PublicIdentity, passphrase: String, keyFile: URL?) throws(IdentityError) -> Identity {
        try vault.restore(identity, passphrase: passphrase, keyFile: keyFile)
    }

    func forgetThisMac() throws(IdentityError) {
        try vault.forgetThisMac()
    }

    /// Stores an identity with `testPassphrase` directly, as if made in an earlier session.
    @discardableResult
    func makeExisting(name: String = "Me", keyFile: URL? = nil) throws -> PublicIdentity {
        let identity = try vault.createIdentity(
            name: name, passphrase: testPassphrase, keyFile: keyFile, cost: IdentityFormat.minimumKDFCost)
        identity.lock()
        return identity.publicIdentity
    }

    /// Writes `bytes` to a file in the temp folder.
    func file(_ name: String, _ bytes: [UInt8]) throws -> URL {
        let url = folder.appendingPathComponent(name)
        try Data(bytes).write(to: url)
        return url
    }
}

/// Someone else's public identity, from their own vault.
func someoneElse(_ name: String) throws -> PublicIdentity {
    let store = try TestStore()
    return try store.makeExisting(name: name)
}

/// Waits for a semaphore without blocking the main actor.
func waitUntilSignalled(_ semaphore: DispatchSemaphore) async {
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        DispatchQueue.global().async {
            semaphore.wait()
            continuation.resume()
        }
    }
}

/// A fresh, empty `UserDefaults` that never touches the real preferences.
func scratchDefaults() -> UserDefaults {
    let name = "chotam-tests-\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: name)!
    defaults.removePersistentDomain(forName: name)
    return defaults
}

extension IdentityModel.State {
    var name: String {
        switch self {
        case .loading: "loading"
        case .noIdentity: "noIdentity"
        case .unreadable: "unreadable"
        case .locked: "locked"
        case .newPassphrase: "newPassphrase"
        case .unlocked: "unlocked"
        }
    }
}
