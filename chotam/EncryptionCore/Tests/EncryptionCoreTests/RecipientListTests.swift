import Foundation
import XCTest
@testable import EncryptionCore

/// Choosing recipients: an unverified contact can only be included through an
/// explicit confirmation of exactly those contacts.
final class RecipientListTests: XCTestCase {
    private func contacts(verified: Int, unverified: Int) throws -> ((), [Contact]) {
        var result: [Contact] = []
        for i in 0 ..< verified + unverified {
            result.append(Contact(
                name: "Contact \(i)", isVerified: i < verified, publicIdentity: try SomeoneElse().publicIdentity))
        }
        return ((), result)
    }

    func testVerifiedContactsNeedNoConfirmation() throws {
        let (_, all) = try contacts(verified: 3, unverified: 0)
        XCTAssertEqual(try RecipientList(all).contacts, all)
    }

    func testUnverifiedContactsNeedConfirmation() throws {
        let (_, all) = try contacts(verified: 2, unverified: 2)
        do {
            _ = try RecipientList(all)
            XCTFail("an unverified contact was accepted without confirmation")
        } catch let error as RecipientSelectionError {
            guard case .needsConfirmation(let request) = error else { return XCTFail("unexpected \(error)") }
            // Exactly the unverified ones are named, for the dialog.
            XCTAssertEqual(request.unverifiedContacts, Array(all[2...]))
            // Confirming gives back the whole selection, in order.
            XCTAssertEqual(request.confirm().contacts, all)
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testOnlyUnverifiedContactsStillNeedConfirmation() throws {
        let (_, all) = try contacts(verified: 0, unverified: 1)
        XCTAssertThrowsError(try RecipientList(all)) { error in
            guard case .needsConfirmation(let request)? = error as? RecipientSelectionError else {
                return XCTFail("unexpected \(error)")
            }
            XCTAssertEqual(request.unverifiedContacts, all)
        }
    }

    /// The structural checks come first: an invalid selection never produces a
    /// confirmation request.
    func testRejectsEmptyAndDuplicateSelections() throws {
        let (_, all) = try contacts(verified: 1, unverified: 1)
        XCTAssertThrowsError(try RecipientList([])) { XCTAssertEqual($0 as? RecipientSelectionError, .noRecipients) }
        XCTAssertThrowsError(try RecipientList([all[0], all[0]])) {
            XCTAssertEqual($0 as? RecipientSelectionError, .duplicateRecipient)
        }
        XCTAssertThrowsError(try RecipientList([all[1], all[0], all[1]])) {
            XCTAssertEqual($0 as? RecipientSelectionError, .duplicateRecipient)
        }
    }

    /// 63 contacts: the 64th stanza is always the sender's own (encrypt to self).
    func testAtMost63Recipients() throws {
        let (_, all) = try contacts(verified: 64, unverified: 0)
        XCTAssertEqual(try RecipientList(Array(all.prefix(63))).contacts.count, 63)
        XCTAssertThrowsError(try RecipientList(all)) {
            XCTAssertEqual($0 as? RecipientSelectionError, .tooManyRecipients)
        }
    }
}
