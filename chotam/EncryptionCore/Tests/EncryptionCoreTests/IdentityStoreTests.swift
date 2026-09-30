import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Your own identity, through the storage abstraction with an in-memory store and a
/// fake Secure Enclave (SECURITY.md D7, D8). The real Keychain and Secure Enclave are
/// covered by the app-hosted tests in Phase 6.
final class IdentityStoreTests: XCTestCase {
    // MARK: Create and load

    func testCreateThenLoad() throws {
        let keyring = TestKeyring()
        XCTAssertNil(try keyring.store.myIdentity())

        let created = try keyring.store.createIdentity(name: "Alice")
        XCTAssertEqual(created.name, "Alice")
        XCTAssertEqual(created.signingKeyStorage, .secureEnclave)
        XCTAssertEqual(created.encryptionKeyStorage, .keychain)

        let loaded = try XCTUnwrap(try keyring.store.myIdentity())
        XCTAssertEqual(loaded.publicIdentity, created.publicIdentity)
        XCTAssertEqual(loaded.fingerprint, created.fingerprint)
        XCTAssertEqual(loaded.signingKeyStorage, .secureEnclave)
        XCTAssertEqual(loaded.publicIdentity.exportedData, created.publicIdentity.exportedData)
    }

    /// The exported identity imports cleanly: self-signed with the stored signing key.
    func testExportedIdentityImports() throws {
        let identity = try TestKeyring().store.createIdentity(name: "Alice")
        let imported = try PublicIdentity(importingString: identity.publicIdentity.exportedString)
        XCTAssertEqual(imported, identity.publicIdentity)
        XCTAssertEqual(imported.suggestedName, "Alice")
    }

    func testPrivateKeysLoadAndMatch() throws {
        for behaviour in [FakeSecureEnclave.Behaviour.available, .unavailable] {
            let identity = try TestKeyring(secureEnclave: behaviour).store.createIdentity(name: "Alice")

            let signer = try identity.signer()
            XCTAssertEqual(KeyID.signing(signer.publicKey), identity.publicIdentity.signingKeyID)
            let message = Array("Chotam v1 signature test".utf8)
            let signature = try signer.signature(for: message)
            XCTAssertTrue(identity.publicIdentity.signingKey.isValidSignature(signature, for: message))

            let decryptionKey = try identity.decryptionKey()
            XCTAssertEqual(KeyID.encryption(decryptionKey.publicKey), identity.publicIdentity.encryptionKeyID)
            let encapsulation = try identity.publicIdentity.encryptionKey.encapsulate()
            XCTAssertEqual(try decryptionKey.decapsulate(encapsulation.encapsulated), encapsulation.sharedSecret)
        }
    }

    func testOnlyOneIdentity() throws {
        let keyring = TestKeyring()
        let first = try keyring.store.createIdentity(name: "Alice")
        let before = keyring.items.snapshot
        assertIdentityError(.identityExists) { _ = try keyring.store.createIdentity(name: "Alice again") }
        // The existing identity is untouched.
        XCTAssertEqual(keyring.items.snapshot, before)
        XCTAssertEqual(try keyring.store.myIdentity()?.publicIdentity, first.publicIdentity)
    }

    func testNamesAreChecked() {
        let keyring = TestKeyring()
        for name in ["", "   ", String(repeating: "a", count: 65), "a\u{202E}b", "a\nb"] {
            assertIdentityError(.invalidName, name) { _ = try keyring.store.createIdentity(name: name) }
        }
        XCTAssertTrue(keyring.items.snapshot.isEmpty)
    }

    // MARK: Where each key goes (D7)

    func testSecureEnclaveLayout() throws {
        let keyring = TestKeyring(secureEnclave: .available)
        _ = try keyring.store.createIdentity(name: "Alice")
        let items = keyring.items.snapshot
        XCTAssertEqual(Set(items.keys), [.encryptionKey, .signingKey, .ownIdentity])
        // X-Wing: private key material behind user presence.
        XCTAssertEqual(items[.encryptionKey]?.protection, .userPresence)
        XCTAssertEqual(items[.encryptionKey]?.data.count, 64)
        // ML-DSA: a Secure Enclave handle; the Secure Enclave enforces user presence.
        XCTAssertEqual(items[.signingKey]?.protection, ItemProtection.whenUnlocked)
        XCTAssertTrue([UInt8](items[.signingKey]!.data).starts(with: FakeSecureEnclave.handlePrefix))
        // Public record: no prompt needed to show your fingerprint.
        XCTAssertEqual(items[.ownIdentity]?.protection, ItemProtection.whenUnlocked)
    }

    /// If the Secure Enclave can't make the key, it goes in the Keychain, behind user
    /// presence, and the identity says so.
    func testKeychainFallbackLayout() throws {
        let keyring = TestKeyring(secureEnclave: .unavailable)
        let identity = try keyring.store.createIdentity(name: "Alice")
        XCTAssertEqual(identity.signingKeyStorage, .keychain)
        XCTAssertEqual(try keyring.store.myIdentity()?.signingKeyStorage, .keychain)
        let items = keyring.items.snapshot
        XCTAssertEqual(items[.signingKey]?.protection, .userPresence)
        XCTAssertEqual(items[.signingKey]?.data.count, 64)
        XCTAssertEqual(items[.encryptionKey]?.protection, .userPresence)
    }

    /// Every item without user presence must hold only public data or an SE handle.
    func testNoPrivateSeedIsStoredUnprotected() throws {
        for behaviour in [FakeSecureEnclave.Behaviour.available, .unavailable] {
            let keyring = TestKeyring(secureEnclave: behaviour)
            _ = try keyring.store.createIdentity(name: "Alice")
            let items = keyring.items.snapshot
            let xwingSeed = Array([UInt8](items[.encryptionKey]!.data).prefix(32))
            for (item, entry) in items where entry.protection == .whenUnlocked {
                XCTAssertFalse([UInt8](entry.data).containsSubsequence(xwingSeed), "\(item)")
            }
            if behaviour == .unavailable {
                let mldsaSeed = Array([UInt8](items[.signingKey]!.data).prefix(32))
                for (item, entry) in items where entry.protection == .whenUnlocked {
                    XCTAssertFalse([UInt8](entry.data).containsSubsequence(mldsaSeed), "\(item)")
                }
            }
        }
    }

    // MARK: Failures leave nothing behind

    func testFailedWritesLeaveNoIdentity() throws {
        for failing in 1 ... 3 {
            let keyring = TestKeyring()
            keyring.items.failAddNumber = failing
            XCTAssertThrowsError(try keyring.store.createIdentity(name: "Alice"), "write \(failing)")
            XCTAssertTrue(keyring.items.snapshot.isEmpty, "write \(failing)")
            XCTAssertNil(try keyring.store.myIdentity())
            // And it works on the next try.
            keyring.items.failAddNumber = nil
            XCTAssertNoThrow(try keyring.store.createIdentity(name: "Alice"))
        }
    }

    /// Cancelling the one prompt at creation (the self-signature) cancels creation. It
    /// never falls back to the Keychain.
    func testCancelledPromptDoesNotFallBack() throws {
        let keyring = TestKeyring(secureEnclave: .cancelsSigning)
        assertIdentityError(.cancelled) { _ = try keyring.store.createIdentity(name: "Alice") }
        XCTAssertTrue(keyring.items.snapshot.isEmpty)
    }

    func testLeftoversFromAnInterruptedCreationAreReplaced() throws {
        let keyring = TestKeyring()
        keyring.items.set(Data([1, 2, 3]), for: .encryptionKey, protection: .userPresence)
        keyring.items.set(Data([4, 5, 6]), for: .signingKey)
        let identity = try keyring.store.createIdentity(name: "Alice")
        XCTAssertNoThrow(try identity.decryptionKey())
    }

    /// If the Keychain can't be read, creating must fail without deleting anything:
    /// an identity might be there.
    func testUnreadableKeychainDeletesNothing() throws {
        let keyring = TestKeyring()
        _ = try keyring.store.createIdentity(name: "Alice")
        let before = keyring.items.snapshot
        keyring.items.failCopies = true
        assertIdentityError(.secureStorageUnavailable) { _ = try keyring.store.createIdentity(name: "Bob") }
        keyring.items.failCopies = false
        XCTAssertEqual(keyring.items.snapshot, before)
    }

    // MARK: Loading private keys

    func testCancelledPromptWhenLoadingKeys() throws {
        let keyring = TestKeyring(secureEnclave: .unavailable)
        let identity = try keyring.store.createIdentity(name: "Alice")
        keyring.items.cancelProtectedReads = true
        assertIdentityError(.cancelled) { _ = try identity.decryptionKey() }
        assertIdentityError(.cancelled) { _ = try identity.signer() }
    }

    func testDamagedPrivateKeyItemsAreRejected() throws {
        let keyring = TestKeyring()
        let identity = try keyring.store.createIdentity(name: "Alice")
        var encryption = [UInt8](keyring.items.snapshot[.encryptionKey]!.data)
        encryption[5] ^= 0x01
        keyring.items.set(Data(encryption), for: .encryptionKey, protection: .userPresence)
        assertIdentityError(.unexpected) { _ = try identity.decryptionKey() }
    }

    /// A valid key that isn't this identity's is never used.
    func testSwappedPrivateKeyIsRejected() throws {
        let keyring = TestKeyring(secureEnclave: .unavailable)
        let identity = try keyring.store.createIdentity(name: "Alice")
        let other = try SomeoneElse()
        keyring.items.set(other.xwing.integrityCheckedRepresentation, for: .encryptionKey, protection: .userPresence)
        keyring.items.set(other.mldsa.integrityCheckedRepresentation, for: .signingKey, protection: .userPresence)
        assertIdentityError(.unexpected) { _ = try identity.decryptionKey() }
        assertIdentityError(.unexpected) { _ = try identity.signer() }
    }

    func testDamagedPublicRecord() throws {
        let keyring = TestKeyring()
        _ = try keyring.store.createIdentity(name: "Alice")
        var record = [UInt8](keyring.items.snapshot[.ownIdentity]!.data)
        record[record.count - 10] ^= 0x01  // inside the self-signature
        keyring.items.set(Data(record), for: .ownIdentity)
        assertIdentityError(.unexpected) { _ = try keyring.store.myIdentity() }
    }

    // MARK: Delete

    func testDeleteRemovesEverything() throws {
        let keyring = TestKeyring()
        let identity = try keyring.store.createIdentity(name: "Alice")
        let contact = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        try keyring.store.deleteMyIdentity()
        XCTAssertNil(try keyring.store.myIdentity())
        XCTAssertEqual(Set(keyring.items.snapshot.keys), [.contact(contact.publicIdentity.encryptionKeyID)])
        assertIdentityError(.noIdentity) { _ = try identity.decryptionKey() }
        assertIdentityError(.noIdentity) { _ = try identity.signer() }
        // Contacts are kept; a new identity can be made.
        XCTAssertEqual(try keyring.store.contacts().count, 1)
        XCTAssertNoThrow(try keyring.store.createIdentity(name: "Alice"))
    }
}
