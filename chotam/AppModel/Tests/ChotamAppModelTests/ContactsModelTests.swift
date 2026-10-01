import Foundation
import XCTest
@testable import ChotamAppModel
@testable import EncryptionCore

/// Importing, verifying, renaming and removing contacts through the view model, with
/// the public messages the views show.
final class ContactsModelTests: XCTestCase {
    @MainActor
    private func unlockedModel() async throws -> (TestStore, IdentityModel, ContactsModel) {
        let store = try TestStore()
        try store.makeExisting(name: "Me")
        let model = IdentityModel(store: store)
        await model.load()
        await model.unlock(passphrase: testPassphrase, keyFile: nil)
        return (store, model, try XCTUnwrap(model.contacts))
    }

    @MainActor
    func testImportFromFileBytesStartsUnverified() async throws {
        let (_, _, contacts) = try await unlockedModel()
        let bob = try someoneElse("Bob")
        XCTAssertEqual(contacts.contacts, [])

        let pending = try XCTUnwrap(contacts.prepareImport(data: bob.exportedData))
        XCTAssertEqual(pending.suggestedName, "Bob")
        XCTAssertEqual(pending.fingerprint.groups.count, 8)
        XCTAssertEqual(pending.fingerprint.groups.map(\.number), Array(1 ... 8))
        XCTAssertEqual(pending.fingerprint.groups.map(\.text), bob.fingerprint.groups)

        let added = try XCTUnwrap(contacts.add(pending, name: "  Bob Smith "))
        XCTAssertEqual(added.name, "Bob Smith")
        XCTAssertFalse(added.isVerified, "imports always start unverified")
        XCTAssertEqual(contacts.contacts, [added])
    }

    @MainActor
    func testImportFromPastedString() async throws {
        let (_, _, contacts) = try await unlockedModel()
        let carol = try someoneElse("Carol")
        let pasted = "\n  " + carol.exportedString + "\n"
        let pending = try XCTUnwrap(contacts.prepareImport(string: pasted))
        XCTAssertEqual(pending.publicIdentity, carol)

        XCTAssertNil(contacts.prepareImport(string: "   "))
        XCTAssertEqual(contacts.message, "Paste an identity first.")
        XCTAssertNil(contacts.prepareImport(string: "bm90IGFuIGlkZW50aXR5"))
        XCTAssertEqual(contacts.message, "This isn't a valid Chotam identity, or it was damaged.")
    }

    @MainActor
    func testRefusesYourOwnIdentityAndDuplicates() async throws {
        let (_, model, contacts) = try await unlockedModel()
        let mine = try XCTUnwrap(model.publicIdentity)
        let pendingSelf = try XCTUnwrap(contacts.prepareImport(data: mine.exportedData))
        XCTAssertNil(contacts.add(pendingSelf, name: "Me again"))
        XCTAssertEqual(contacts.message, "This is your own identity.")

        let bob = try someoneElse("Bob")
        let pending = try XCTUnwrap(contacts.prepareImport(data: bob.exportedData))
        XCTAssertNotNil(contacts.add(pending, name: "Bob"))
        XCTAssertNil(contacts.add(pending, name: "Bob twice"))
        XCTAssertEqual(contacts.message, "One of this identity's keys already belongs to a contact.")
        XCTAssertEqual(contacts.contacts.count, 1)
    }

    @MainActor
    func testVerifyRenameRemoveAndSorting() async throws {
        let (_, _, contacts) = try await unlockedModel()
        for name in ["zoe", "Bob", "alice"] {
            let pending = try XCTUnwrap(contacts.prepareImport(data: try someoneElse(name).exportedData))
            XCTAssertNotNil(contacts.add(pending, name: name))
        }
        XCTAssertEqual(contacts.contacts.map(\.name), ["alice", "Bob", "zoe"], "sorted by name, ignoring case")

        let bob = try XCTUnwrap(contacts.contacts.first { $0.name == "Bob" })
        let verified = try XCTUnwrap(contacts.markVerified(bob))
        XCTAssertTrue(verified.isVerified)
        XCTAssertEqual(contacts.contact(id: bob.id)?.isVerified, true)

        let renamed = try XCTUnwrap(contacts.rename(verified, to: "Robert"))
        XCTAssertEqual(renamed.name, "Robert")
        XCTAssertTrue(renamed.isVerified, "renaming keeps the verified status")
        XCTAssertNil(contacts.rename(renamed, to: ""))
        XCTAssertEqual(contacts.message, "Names must be 1 to 64 bytes long and can't contain control characters.")

        XCTAssertTrue(contacts.remove(renamed))
        XCTAssertEqual(contacts.contacts.map(\.name), ["alice", "zoe"])
        XCTAssertTrue(contacts.remove(renamed), "removing one that's already gone isn't an error")
        XCTAssertNil(contacts.message)
        XCTAssertNil(contacts.markVerified(renamed))
        XCTAssertEqual(contacts.message, "This contact no longer exists.")
    }

    @MainActor
    func testContactsSurviveLockAndUnlock() async throws {
        let (_, model, contacts) = try await unlockedModel()
        let pending = try XCTUnwrap(contacts.prepareImport(data: try someoneElse("Bob").exportedData))
        XCTAssertNotNil(contacts.add(pending, name: "Bob"))

        model.lock(reason: .manual)
        XCTAssertNil(model.contacts)
        // A view still holding the old model gets the public "locked" message, not a crash.
        contacts.reload()
        XCTAssertEqual(contacts.contacts, [])
        XCTAssertEqual(contacts.message, "Your identity is locked. Unlock it with your passphrase.")

        await model.unlock(passphrase: testPassphrase, keyFile: nil)
        XCTAssertEqual(model.contacts?.contacts.map(\.name), ["Bob"])
    }

    @MainActor
    func testFingerprintComparison() throws {
        let bob = try someoneElse("Bob")
        let matches: (String) -> Bool = { bob.fingerprint.matches($0) }
        XCTAssertEqual(FingerprintMatch(typed: "  ", matches: matches), .notTyped)
        XCTAssertEqual(FingerprintMatch(typed: bob.fingerprint.description.lowercased(), matches: matches), .matches)
        XCTAssertEqual(FingerprintMatch(typed: "0000 0000 0000 0000 0000 0000 0000 0000", matches: matches), .doesNotMatch)
        let display = FingerprintDisplay(groups: bob.fingerprint.groups)
        XCTAssertTrue(display.spokenText.hasPrefix("1 \(bob.fingerprint.groups[0]), 2 "))
    }
}
