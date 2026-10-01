import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// The passphrase-derived identity (SECURITY.md D17, D18): creating, unlocking,
/// restoring on another Mac, locking and forgetting, with nothing secret on disk.
final class IdentityVaultTests: XCTestCase {
    // MARK: Create and unlock

    func testCreateThenUnlock() throws {
        let vault = try TestVault()
        XCTAssertNil(try vault.vault.storedIdentity())
        let created = try vault.create(name: "Alice")
        XCTAssertEqual(created.name, "Alice")
        XCTAssertFalse(created.isLocked)
        XCTAssertFalse(created.requiresKeyFile)
        XCTAssertEqual(try vault.vault.storedIdentity(), created.publicIdentity)

        // Same passphrase, typed differently: same identity.
        let unlocked = try vault.unlock(IdentityVectors.typedPassphrase)
        XCTAssertEqual(unlocked.publicIdentity, created.publicIdentity)
        XCTAssertEqual(unlocked.fingerprint, created.fingerprint)
        XCTAssertEqual(unlocked.publicIdentity.kdf.cost, IdentityFormat.minimumKDFCost)
    }

    /// The public API generates the passphrase: 7 distinct EFF words, never chosen by
    /// the user, at the default cost (1 GiB, ops 8).
    func testPublicCreateGeneratesThePassphrase() throws {
        let vault = try TestVault()
        let created = try vault.vault.createIdentity(name: "Alice")
        let words = created.passphrase.split(separator: " ")
        XCTAssertEqual(words.count, 7)
        XCTAssertEqual(Set(words).count, 7)
        XCTAssertTrue(IdentityPassphrase.isWellFormed(created.passphrase))
        XCTAssertEqual(created.identity.publicIdentity.kdf.cost, IdentityFormat.defaultKDFCost)
        XCTAssertEqual(IdentityFormat.defaultKDFCost, Argon2id.Cost(opsLimit: 8, memLimit: 1 << 30))
        // And it unlocks.
        created.identity.lock()
        XCTAssertEqual(try vault.vault.unlock(passphrase: created.passphrase).fingerprint, created.identity.fingerprint)
    }

    func testExportedIdentityImports() throws {
        let vault = try TestVault()
        let me = try vault.create(name: "Alice")
        let imported = try PublicIdentity(importing: me.publicIdentity.exportedData)
        XCTAssertEqual(imported, me.publicIdentity)
        XCTAssertEqual(imported.suggestedName, "Alice")
        XCTAssertEqual(try PublicIdentity(importingString: me.publicIdentity.exportedString), me.publicIdentity)
    }

    /// A fresh random salt per identity: the same passphrase twice gives two identities.
    func testSamePassphraseNewSaltIsAnotherIdentity() throws {
        let a = try TestVault().create()
        let b = try TestVault().create()
        XCTAssertNotEqual(a.publicIdentity.kdf.salt, b.publicIdentity.kdf.salt)
        XCTAssertNotEqual(a.fingerprint, b.fingerprint)
    }

    func testOnlyOneIdentityPerVault() throws {
        let vault = try TestVault()
        _ = try vault.create()
        assertIdentityError(.identityExists) { _ = try vault.create(name: "Second") }
        assertIdentityError(.identityExists) {
            _ = try vault.vault.restore(try PQIDCodec.decode(try IdentityVectors.pqid()), passphrase: IdentityVectors.typedPassphrase)
        }
    }

    func testNamesAreChecked() throws {
        let vault = try TestVault()
        for name in ["", "   ", "Al\u{202E}ice", String(repeating: "x", count: 65)] {
            assertIdentityError(.invalidName, name) { _ = try vault.create(name: name) }
        }
        XCTAssertFalse(fileExists(vault.identityFile))
    }

    // MARK: Wrong input

    func testWrongPassphrase() throws {
        let vault = try TestVault()
        _ = try vault.create()
        // Well-formed, but not the right words.
        assertIdentityError(.wrongPassphrase) {
            _ = try vault.unlock("agreement curve flakily ligament pretty shrimp unbaked")
        }
        assertIdentityError(.wrongPassphrase) {
            _ = try vault.unlock("curve agreement flakily ligament pretty shrimp unbundle")  // order matters
        }
    }

    /// Malformed passphrases are refused before any Argon2id work.
    func testPassphraseShapeIsCheckedFirst() throws {
        let vault = try TestVault()
        _ = try vault.create()
        let malformed = [
            "", "agreement curve flakily ligament pretty shrimp",  // 6 words
            "agreement curve flakily ligament pretty shrimp shrimp",  // repeated word
            "agreement curve flakily ligament pretty shrimp unbundlex",  // not a word
            "agreement-curve-flakily-ligament-pretty-shrimp-unbundle",  // one "word"
            "correct horse battery staple and four more",  // "correct", … are not all EFF words
            Array(repeating: "abacus", count: 11).joined(separator: " "),
        ]
        for passphrase in malformed {
            assertIdentityError(.invalidPassphrase, passphrase) { _ = try vault.unlock(passphrase) }
        }
        assertIdentityError(.invalidPassphrase) {
            _ = try TestVault().create(passphrase: "a strong but user-chosen password!")
        }
    }

    func testUnlockWithoutAnIdentity() throws {
        assertIdentityError(.noIdentity) { _ = try TestVault().unlock() }
    }

    func testDamagedIdentityFileIsReported() throws {
        let vault = try TestVault()
        _ = try vault.create()
        var bytes = try readFile(vault.identityFile)
        bytes[3240] ^= 0x01  // inside the signed KDF salt
        try Data(bytes).write(to: vault.identityFile)
        assertIdentityError(.invalidIdentity) { _ = try vault.vault.storedIdentity() }
        assertIdentityError(.invalidIdentity) { _ = try vault.unlock() }
        // Oversized: refused unread.
        try Data(count: 1_000_000).write(to: vault.identityFile)
        assertIdentityError(.invalidIdentity) { _ = try vault.vault.storedIdentity() }
    }

    // MARK: Restore on a new Mac

    /// The golden .pqid from the independent implementation, restored from its
    /// passphrase: proves the whole derivation (FORMAT.md §9.6) end to end.
    func testRestoreGoldenIdentity() throws {
        let vault = try TestVault()
        let golden = try PQIDCodec.decode(try IdentityVectors.pqid())
        let identity = try vault.vault.restore(golden, passphrase: IdentityVectors.typedPassphrase)
        XCTAssertEqual(identity.fingerprint.description, IdentityVectors.fingerprint)
        XCTAssertEqual(try readFile(vault.identityFile), try IdentityVectors.pqid())
        identity.lock()
        XCTAssertEqual(try vault.unlock().fingerprint.description, IdentityVectors.fingerprint)
    }

    /// A wrong passphrase stores nothing.
    func testRestoreWithWrongPassphraseStoresNothing() throws {
        let vault = try TestVault()
        let golden = try PQIDCodec.decode(try IdentityVectors.pqid())
        assertIdentityError(.wrongPassphrase) {
            _ = try vault.vault.restore(golden, passphrase: "agreement curve flakily ligament pretty shrimp unbaked")
        }
        XCTAssertNil(try vault.vault.storedIdentity())
        XCTAssertFalse(fileExists(vault.vault.folder))
    }

    // MARK: Key file

    func testKeyFileGoldenIdentity() throws {
        let vault = try TestVault()
        let keyFile = try vault.scratch.write(IdentityVectors.keyFile, to: "key.bin")
        let golden = try PQIDCodec.decode(try vector(IdentityVectors.keyFilePQIDFile))
        XCTAssertTrue(golden.kdf.requiresKeyFile)
        // Public, so the app can ask for the key file before unlocking (Phase 6).
        XCTAssertTrue(golden.requiresKeyFile)
        XCTAssertFalse(try PQIDCodec.decode(try vector(IdentityVectors.pqidFile)).requiresKeyFile)

        assertIdentityError(.keyFileRequired) { _ = try vault.vault.restore(golden, passphrase: IdentityVectors.typedPassphrase) }
        let wrongFile = try vault.scratch.write(IdentityVectors.keyFile.dropLast() + [0], to: "wrong.bin")
        assertIdentityError(.wrongPassphrase) {
            _ = try vault.vault.restore(golden, passphrase: IdentityVectors.typedPassphrase, keyFile: wrongFile)
        }
        let identity = try vault.vault.restore(golden, passphrase: IdentityVectors.typedPassphrase, keyFile: keyFile)
        XCTAssertEqual(identity.fingerprint.description, IdentityVectors.keyFileFingerprint)
        XCTAssertTrue(identity.requiresKeyFile)
        try identity.withKeys { keys in
            XCTAssertEqual([UInt8](keys.xwing.seedRepresentation), IdentityVectors.keyFileXWingSeed)
        }
    }

    func testCreateWithKeyFile() throws {
        let vault = try TestVault()
        let keyFile = try vault.scratch.write(Array(repeating: 0x5A, count: 3_000_000), to: "photo.jpg")
        let created = try vault.create(keyFile: keyFile)
        XCTAssertTrue(created.requiresKeyFile)

        assertIdentityError(.keyFileRequired) { _ = try vault.unlock() }
        XCTAssertEqual(try vault.unlock(keyFile: keyFile).fingerprint, created.fingerprint)
        // The passphrase alone, against the same salt, is a different identity.
        let withoutKeyFile = try TestVault().create()
        XCTAssertNotEqual(withoutKeyFile.fingerprint, created.fingerprint)
    }

    func testKeyFileRules() throws {
        let vault = try TestVault()
        let empty = try vault.scratch.write([], to: "empty")
        assertIdentityError(.keyFileUnusable) { _ = try vault.create(keyFile: empty) }
        assertIdentityError(.keyFileUnusable) { _ = try vault.create(keyFile: vault.scratch.url("missing")) }
        assertIdentityError(.keyFileUnusable) { _ = try vault.create(keyFile: vault.scratch.folder) }
        XCTAssertFalse(fileExists(vault.identityFile))

        _ = try vault.create()
        let extra = try vault.scratch.write([1, 2, 3], to: "extra")
        assertIdentityError(.keyFileNotUsed) { _ = try vault.unlock(keyFile: extra) }
    }

    // MARK: Locking

    func testLockDropsTheKeys() throws {
        let vault = try TestVault()
        let identity = try vault.create()
        XCTAssertNoThrow(try identity.withKeys { _ in })
        identity.lock()
        identity.lock()  // idempotent
        XCTAssertTrue(identity.isLocked)
        XCTAssertThrowsError(try identity.withKeys { _ in }) {
            XCTAssertEqual($0 as? IdentityError, .locked)
        }
        // Public information stays available.
        XCTAssertEqual(identity.name, "Me")
        XCTAssertFalse(identity.publicIdentity.exportedData.isEmpty)
    }

    // MARK: Forget

    func testForgetThisMacRemovesEverything() throws {
        let vault = try TestVault()
        let identity = try vault.create()
        _ = try identity.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        XCTAssertTrue(fileExists(vault.contactsFile))

        try vault.vault.forgetThisMac()
        XCTAssertFalse(fileExists(vault.identityFile))
        XCTAssertFalse(fileExists(vault.contactsFile))
        XCTAssertNil(try vault.vault.storedIdentity())
        XCTAssertNoThrow(try vault.vault.forgetThisMac())  // nothing left: not an error
        assertIdentityError(.noIdentity) { _ = try vault.unlock() }
    }

    /// A contacts file left over without its identity is removed before a new identity
    /// is stored: it belongs to nobody.
    func testStaleContactsFileIsDiscarded() throws {
        let vault = try TestVault()
        let first = try vault.create()
        _ = try first.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        try FileManager.default.removeItem(at: vault.identityFile)

        let second = try vault.create(name: "New")
        XCTAssertFalse(fileExists(vault.contactsFile))
        XCTAssertEqual(try second.contacts(), [])
    }

    // MARK: What exists on disk

    /// Exactly two files, both public or encrypted, owner-only, and no secret in either.
    func testOnlyPublicOrEncryptedFilesOnDisk() throws {
        let vault = try TestVault()
        let identity = try vault.create()
        _ = try identity.importContact(try SomeoneElse().publicIdentity, name: "Bob")

        let names = try FileManager.default.contentsOfDirectory(atPath: vault.vault.folder.path).sorted()
        XCTAssertEqual(names, ["contacts.chotam", "identity.pqid"])
        let secrets: [[UInt8]] = try identity.withKeys { keys in
            [[UInt8](keys.xwing.seedRepresentation), [UInt8](keys.mldsa.seedRepresentation),
             [UInt8](keys.ed25519.rawRepresentation), keys.contactsKey.withUnsafeBytes { Array($0) }]
        }
        for name in names {
            let url = vault.vault.folder.appendingPathComponent(name)
            XCTAssertEqual(try permissions(url), 0o600, name)
            let bytes = try readFile(url)
            for secret in secrets {
                XCTAssertFalse(bytes.containsSubsequence(secret), name)
            }
            XCTAssertFalse(bytes.containsSubsequence(Array(IdentityVectors.canonicalPassphrase.utf8)), name)
            XCTAssertFalse(bytes.containsSubsequence(Array("agreement".utf8)), name)
        }
    }
}
