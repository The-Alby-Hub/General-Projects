import Foundation
import XCTest
@testable import EncryptionCore

/// Contacts (SECURITY.md D14, D15): unverified by default, verified only on request,
/// never two contacts (or you and a contact) sharing a key.
final class ContactTests: XCTestCase {
    func testImportedContactsStartUnverified() throws {
        let keyring = TestKeyring()
        let bob = try SomeoneElse()
        let contact = try keyring.store.importContact(bob.publicIdentity, name: "Bob")
        XCTAssertFalse(contact.isVerified)
        XCTAssertEqual(contact.name, "Bob")
        XCTAssertEqual(contact.fingerprint, bob.publicIdentity.fingerprint)
        XCTAssertEqual(try keyring.store.contacts(), [contact])
        XCTAssertFalse(try keyring.store.contacts()[0].isVerified)
    }

    /// The local name is the user's choice; the suggested one is only a suggestion.
    func testLocalNameIsIndependentOfSuggestedName() throws {
        let keyring = TestKeyring()
        let contact = try keyring.store.importContact(try SomeoneElse(name: "Totally Your Bank").publicIdentity, name: "Unknown sender")
        XCTAssertEqual(try keyring.store.contacts()[0].name, "Unknown sender")
        XCTAssertEqual(contact.publicIdentity.suggestedName, "Totally Your Bank")
    }

    func testMarkVerifiedPersists() throws {
        let keyring = TestKeyring()
        let contact = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        let verified = try keyring.store.markVerified(contact)
        XCTAssertTrue(verified.isVerified)
        XCTAssertEqual(verified.publicIdentity, contact.publicIdentity)

        // A fresh store over the same items sees it too.
        let reopened = IdentityStore(items: keyring.items, secureEnclave: FakeSecureEnclave(behaviour: .available))
        XCTAssertEqual(try reopened.contacts().map(\.isVerified), [true])
    }

    func testRenameKeepsKeysAndStatus() throws {
        let keyring = TestKeyring()
        let contact = try keyring.store.markVerified(try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Bob"))
        let renamed = try keyring.store.rename(contact, to: "Robert")
        XCTAssertEqual(renamed.name, "Robert")
        XCTAssertTrue(renamed.isVerified)
        XCTAssertEqual(try keyring.store.contacts(), [renamed])
        assertIdentityError(.invalidName) { _ = try keyring.store.rename(renamed, to: "") }
    }

    func testRemove() throws {
        let keyring = TestKeyring()
        let bob = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        let carol = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Carol")
        try keyring.store.remove(bob)
        XCTAssertEqual(try keyring.store.contacts(), [carol])
        XCTAssertNoThrow(try keyring.store.remove(bob))  // already gone
        assertIdentityError(.contactNotFound) { _ = try keyring.store.markVerified(bob) }
    }

    func testContactsAreSortedByName() throws {
        let keyring = TestKeyring()
        for name in ["Carol", "alice", "Bob"] {
            _ = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: name)
        }
        XCTAssertEqual(try keyring.store.contacts().map(\.name), ["alice", "Bob", "Carol"])
    }

    // MARK: Refusals

    func testCannotImportYourOwnIdentity() throws {
        let keyring = TestKeyring()
        let me = try keyring.store.createIdentity(name: "Me")
        let copy = try PublicIdentity(importing: me.publicIdentity.exportedData)
        assertIdentityError(.isYourOwnIdentity) { _ = try keyring.store.importContact(copy, name: "Me") }
        XCTAssertTrue(try keyring.store.contacts().isEmpty)
    }

    func testCannotImportTheSameIdentityTwice() throws {
        let keyring = TestKeyring()
        let bob = try SomeoneElse()
        _ = try keyring.store.importContact(bob.publicIdentity, name: "Bob")
        assertIdentityError(.alreadyAContact) { _ = try keyring.store.importContact(bob.publicIdentity, name: "Bob 2") }
        XCTAssertEqual(try keyring.store.contacts().count, 1)
    }

    /// Mallory pairs Bob's encryption key with his own signing key (which he can
    /// self-sign). It must not become a second contact sharing Bob's key.
    func testCannotImportAnIdentitySharingAKey() throws {
        let keyring = TestKeyring()
        let bob = try SomeoneElse(name: "Bob")
        _ = try keyring.store.importContact(bob.publicIdentity, name: "Bob")
        let mallory = try SomeoneElse(name: "Mallory")
        let mixed = try PQIDCodec.decode(try RawPQID(
            encryptionKey: bob.publicIdentity.encryptionKeyBytes,
            signingKey: mallory.publicIdentity.signingKeyBytes).signed(by: mallory.mldsa))
        assertIdentityError(.alreadyAContact) { _ = try keyring.store.importContact(mixed, name: "Mallory") }

        // Likewise for a key of your own: Mallory's signing key with your encryption key.
        let me = try keyring.store.createIdentity(name: "Me")
        let withMyKey = try PQIDCodec.decode(try RawPQID(
            encryptionKey: me.publicIdentity.encryptionKeyBytes,
            signingKey: mallory.publicIdentity.signingKeyBytes).signed(by: mallory.mldsa))
        assertIdentityError(.isYourOwnIdentity) { _ = try keyring.store.importContact(withMyKey, name: "Mallory") }
        XCTAssertEqual(try keyring.store.contacts().count, 1)
    }

    func testNamesAreChecked() throws {
        let keyring = TestKeyring()
        let bob = try SomeoneElse().publicIdentity
        for name in ["", " ", "a\u{2067}b", String(repeating: "é", count: 33)] {
            assertIdentityError(.invalidName, name) { _ = try keyring.store.importContact(bob, name: name) }
        }
    }

    // MARK: Damaged items

    func testDamagedContactRecordIsSkipped() throws {
        let keyring = TestKeyring()
        let bob = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        let carol = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Carol")
        let item = StoredItem.contact(bob.publicIdentity.encryptionKeyID)
        var record = [UInt8](keyring.items.snapshot[item]!.data)
        record[record.count - 5] ^= 0x01  // inside the embedded self-signature
        keyring.items.set(Data(record), for: item)
        XCTAssertEqual(try keyring.store.contacts(), [carol])
    }

    /// A valid record stored under another contact's name is not trusted.
    func testMisfiledContactRecordIsSkipped() throws {
        let keyring = TestKeyring()
        let bob = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        let bobItem = StoredItem.contact(bob.publicIdentity.encryptionKeyID)
        let record = keyring.items.snapshot[bobItem]!.data
        try keyring.store.remove(bob)
        keyring.items.set(record, for: StoredItem(collection: .contacts, account: String(repeating: "0", count: 64)))
        XCTAssertTrue(try keyring.store.contacts().isEmpty)
    }

    func testRecordRoundTrip() throws {
        let identity = try PQIDCodec.decode(try IdentityVectors.pqid())
        for verified in [false, true] {
            let record = ContactRecord(name: "Alice 🔑", isVerified: verified, publicIdentity: identity)
            let decoded = try ContactRecord.decode(try record.encode())
            XCTAssertEqual(decoded.name, "Alice 🔑")
            XCTAssertEqual(decoded.isVerified, verified)
            XCTAssertEqual(decoded.publicIdentity, identity)
        }
        var bytes = try ContactRecord(name: "A", isVerified: true, publicIdentity: identity).encode()
        bytes[10] = 2  // verified must be 0 or 1
        assertCoreFailure(.storedRecordDamaged) { _ = try ContactRecord.decode(bytes) }
    }

    // MARK: Phase 5 lookup

    func testLookupBySigningKeyID() throws {
        let keyring = TestKeyring()
        let bob = try keyring.store.importContact(try SomeoneElse().publicIdentity, name: "Bob")
        XCTAssertEqual(try keyring.store.contact(signingKeyID: bob.publicIdentity.signingKeyID), bob)
        XCTAssertNil(try keyring.store.contact(signingKeyID: bob.publicIdentity.encryptionKeyID))
    }
}
