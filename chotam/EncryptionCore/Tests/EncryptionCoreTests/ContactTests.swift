import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Contacts (SECURITY.md D14, D15): unverified by default, verified only on request,
/// never two contacts (or you and a contact) sharing a key, kept in a file encrypted
/// with a key derived from your passphrase.
final class ContactTests: XCTestCase {
    private var vault: TestVault!
    private var me: Identity!

    override func setUpWithError() throws {
        vault = try TestVault()
        me = try vault.create()
    }

    override func tearDown() {
        me = nil
        vault = nil
    }

    func testImportedContactsStartUnverified() throws {
        let bob = try SomeoneElse()
        let contact = try me.importContact(bob.publicIdentity, name: "Bob")
        XCTAssertFalse(contact.isVerified)
        XCTAssertEqual(contact.name, "Bob")
        XCTAssertEqual(contact.fingerprint, bob.publicIdentity.fingerprint)
        XCTAssertEqual(try me.contacts(), [contact])
        XCTAssertFalse(try me.contacts()[0].isVerified)
    }

    /// The local name is the user's choice; the suggested one is only a suggestion.
    func testLocalNameIsIndependentOfSuggestedName() throws {
        let contact = try me.importContact(try SomeoneElse(name: "Totally Your Bank").publicIdentity, name: "Unknown sender")
        XCTAssertEqual(try me.contacts()[0].name, "Unknown sender")
        XCTAssertEqual(contact.publicIdentity.suggestedName, "Totally Your Bank")
    }

    /// Contacts survive locking: a fresh unlock (same passphrase) reads the same file.
    func testContactsPersistAcrossUnlocks() throws {
        let contact = try me.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        let verified = try me.markVerified(contact)
        XCTAssertTrue(verified.isVerified)
        XCTAssertEqual(verified.publicIdentity, contact.publicIdentity)

        me.lock()
        let again = try vault.unlock()
        XCTAssertEqual(try again.contacts().map(\.isVerified), [true])
        XCTAssertEqual(try again.contacts().map(\.name), ["Bob"])
    }

    func testRenameKeepsKeysAndStatus() throws {
        let contact = try me.markVerified(try me.importContact(try SomeoneElse().publicIdentity, name: "Bob"))
        let renamed = try me.rename(contact, to: "Robert")
        XCTAssertEqual(renamed.name, "Robert")
        XCTAssertTrue(renamed.isVerified)
        XCTAssertEqual(try me.contacts(), [renamed])
        assertIdentityError(.invalidName) { _ = try me.rename(renamed, to: "") }
    }

    func testRemove() throws {
        let bob = try me.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        let carol = try me.importContact(try SomeoneElse().publicIdentity, name: "Carol")
        try me.remove(bob)
        XCTAssertEqual(try me.contacts(), [carol])
        XCTAssertNoThrow(try me.remove(bob))  // already gone
        assertIdentityError(.contactNotFound) { _ = try me.markVerified(bob) }
    }

    func testContactsAreSortedByName() throws {
        for name in ["Carol", "alice", "Bob"] {
            _ = try me.importContact(try SomeoneElse().publicIdentity, name: name)
        }
        XCTAssertEqual(try me.contacts().map(\.name), ["alice", "Bob", "Carol"])
    }

    // MARK: Refusals

    func testCannotImportYourOwnIdentity() throws {
        let copy = try PublicIdentity(importing: me.publicIdentity.exportedData)
        assertIdentityError(.isYourOwnIdentity) { _ = try me.importContact(copy, name: "Me") }
        XCTAssertTrue(try me.contacts().isEmpty)
    }

    func testCannotImportTheSameIdentityTwice() throws {
        let bob = try SomeoneElse()
        _ = try me.importContact(bob.publicIdentity, name: "Bob")
        assertIdentityError(.alreadyAContact) { _ = try me.importContact(bob.publicIdentity, name: "Bob 2") }
        XCTAssertEqual(try me.contacts().count, 1)
    }

    /// Mallory pairs one of Bob's keys with his own (which he can self-sign). It must
    /// not become a second contact sharing Bob's key: not the encryption key, and not
    /// either half of the signing key.
    func testCannotImportAnIdentitySharingAnyKey() throws {
        let bob = try SomeoneElse(name: "Bob")
        _ = try me.importContact(bob.publicIdentity, name: "Bob")
        let mallory = try SomeoneElse(name: "Mallory")
        func mallorysWith(_ change: (inout RawPQID) -> Void, signedBy ed: Curve25519.Signing.PrivateKey, _ ml: MLDSA65.PrivateKey) throws -> PublicIdentity {
            var raw = RawPQID(
                encryptionKey: mallory.publicIdentity.encryptionKeyBytes,
                mldsaKey: mallory.publicIdentity.mldsaKeyBytes,
                ed25519Key: mallory.publicIdentity.ed25519KeyBytes)
            change(&raw)
            return try PQIDCodec.decode(try raw.signed(by: ed, ml))
        }
        let sharingEncryption = try mallorysWith({ $0.encryptionKey = bob.publicIdentity.encryptionKeyBytes }, signedBy: mallory.ed25519, mallory.mldsa)
        assertIdentityError(.alreadyAContact) { _ = try me.importContact(sharingEncryption, name: "Mallory") }
        // Only possible with Bob's private key, but refused regardless.
        let sharingEd25519 = try mallorysWith({ $0.ed25519Key = bob.publicIdentity.ed25519KeyBytes }, signedBy: bob.ed25519, mallory.mldsa)
        assertIdentityError(.alreadyAContact) { _ = try me.importContact(sharingEd25519, name: "Mallory") }
        let sharingMLDSA = try mallorysWith({ $0.mldsaKey = bob.publicIdentity.mldsaKeyBytes }, signedBy: mallory.ed25519, bob.mldsa)
        assertIdentityError(.alreadyAContact) { _ = try me.importContact(sharingMLDSA, name: "Mallory") }

        // Likewise for a key of your own: Mallory's signing keys with your encryption key.
        let withMyKey = try mallorysWith({ $0.encryptionKey = me.publicIdentity.encryptionKeyBytes }, signedBy: mallory.ed25519, mallory.mldsa)
        assertIdentityError(.isYourOwnIdentity) { _ = try me.importContact(withMyKey, name: "Mallory") }
        XCTAssertEqual(try me.contacts().count, 1)
    }

    func testNamesAreChecked() throws {
        let bob = try SomeoneElse().publicIdentity
        for name in ["", " ", "a\u{2067}b", String(repeating: "é", count: 33)] {
            assertIdentityError(.invalidName, name) { _ = try me.importContact(bob, name: name) }
        }
    }

    // MARK: Locked

    func testContactsNeedAnUnlockedIdentity() throws {
        let bob = try me.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        me.lock()
        XCTAssertTrue(me.isLocked)
        assertIdentityError(.locked) { _ = try me.contacts() }
        assertIdentityError(.locked) { _ = try me.importContact(try SomeoneElse().publicIdentity, name: "Carol") }
        assertIdentityError(.locked) { _ = try me.markVerified(bob) }
        assertIdentityError(.locked) { try me.remove(bob) }
    }

    // MARK: The file

    /// Encrypted: neither names, keys nor the verified flags are readable.
    func testFileRevealsNothing() throws {
        let bob = try SomeoneElse(name: "Bob")
        _ = try me.markVerified(try me.importContact(bob.publicIdentity, name: "Robert Smith"))
        let file = try readFile(vault.contactsFile)
        XCTAssertEqual(Array(file.prefix(8)), Array("CHOTAMCF".utf8))
        XCTAssertFalse(file.containsSubsequence(Array("Robert Smith".utf8)))
        XCTAssertFalse(file.containsSubsequence(Array("CHOTAMID".utf8)))
        XCTAssertFalse(file.containsSubsequence(Array(bob.publicIdentity.encryptionKeyBytes.prefix(32))))
        XCTAssertEqual(try permissions(vault.contactsFile), 0o600)
    }

    /// Any change to the file is detected; nothing is trusted.
    func testTamperedFileIsRejected() throws {
        _ = try me.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        let original = try readFile(vault.contactsFile)
        for offset in [0, 9, 10, 41, 42, 53, 54, 100, original.count - 1] {
            var bytes = original
            bytes[offset] ^= 0x01
            try Data(bytes).write(to: vault.contactsFile)
            assertIdentityError(.contactsDamaged, "offset \(offset)") { _ = try me.contacts() }
        }
        try Data(original.dropLast()).write(to: vault.contactsFile)
        assertIdentityError(.contactsDamaged) { _ = try me.contacts() }
        try Data(count: IdentityFormat.contactsMaxFileSize + 1).write(to: vault.contactsFile)
        assertIdentityError(.contactsDamaged) { _ = try me.contacts() }
        try Data(original).write(to: vault.contactsFile)
        XCTAssertEqual(try me.contacts().count, 1)
    }

    /// Another identity's contacts file can't be read, even with the same passphrase.
    func testFileIsBoundToItsIdentity() throws {
        _ = try me.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        let mine = try readFile(vault.contactsFile)

        let other = try TestVault()
        let someoneElse = try other.create()  // same passphrase, different salt: another identity
        XCTAssertNotEqual(someoneElse.fingerprint, me.fingerprint)
        try Data(mine).write(to: other.contactsFile)
        assertIdentityError(.contactsDamaged) { _ = try someoneElse.contacts() }
    }

    /// Writing a key in the right format but under the wrong key fails too.
    func testFileSealedWithAnotherKeyIsRejected() throws {
        let forged = try ContactsFile.encode(
            [Contact(name: "Mallory", isVerified: true, publicIdentity: try SomeoneElse().publicIdentity)],
            owner: me.publicIdentity.encryptionKeyID, key: SymmetricKey(size: .bits256))
        try vault.vault.writeFile(IdentityFormat.contactsFileName, forged, replacing: false)
        assertIdentityError(.contactsDamaged) { _ = try me.contacts() }
    }

    func testFileRoundTripAndEntryRules() throws {
        let key = SymmetricKey(size: .bits256)
        let owner = me.publicIdentity.encryptionKeyID
        let identity = try PQIDCodec.decode(try IdentityVectors.pqid())
        for verified in [false, true] {
            let contact = Contact(name: "Alice 🔑", isVerified: verified, publicIdentity: identity)
            let decoded = try ContactsFile.decode(try ContactsFile.encode([contact], owner: owner, key: key), owner: owner, key: key)
            XCTAssertEqual(decoded, [contact])
            XCTAssertEqual(decoded[0].isVerified, verified)
            XCTAssertEqual(decoded[0].name, "Alice 🔑")
        }
        XCTAssertEqual(try ContactsFile.decode(try ContactsFile.encode([], owner: owner, key: key), owner: owner, key: key), [])
        // Two saves never share a nonce.
        let a = try ContactsFile.encode([], owner: owner, key: key)
        let b = try ContactsFile.encode([], owner: owner, key: key)
        XCTAssertNotEqual(Array(a[42 ..< 54]), Array(b[42 ..< 54]))
    }

    // MARK: Phase 5b lookup

    func testLookupBySigningKeyID() throws {
        let bob = try me.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        XCTAssertEqual(try me.contact(signingKeyID: bob.publicIdentity.signingKeyID), bob)
        XCTAssertNil(try me.contact(signingKeyID: bob.publicIdentity.encryptionKeyID))
    }
}
