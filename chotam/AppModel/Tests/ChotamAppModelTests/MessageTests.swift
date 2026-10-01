import Foundation
import XCTest
@testable import ChotamAppModel
@testable import EncryptionCore

/// The app shows the core's public messages exactly, and never a system error's own
/// text, which can contain paths (SECURITY.md §8).
final class MessageTests: XCTestCase {
    func testChotamErrorsShowTheirPublicMessage() {
        XCTAssertEqual(UserMessage.text(for: DecryptionError.failed), "Decryption failed: file is damaged or not for you.")
        XCTAssertEqual(UserMessage.text(for: IdentityError.wrongPassphrase), "Wrong passphrase or key file.")
        XCTAssertEqual(UserMessage.text(for: EncryptionError.file(.outputExists)), FileProblem.outputExists.errorDescription)
        XCTAssertEqual(UserMessage.text(for: AppProblem.busy), "Chotam is still busy. Try again when it's done.")
        XCTAssertEqual(UserMessage.text(for: RecipientSelectionError.noRecipients), "Choose at least one recipient.")
    }

    func testSystemErrorsNeverLeakPaths() {
        let path = "/Users/alice/Secret Plans/budget.xlsx"
        let errors: [any Error] = [
            NSError(domain: NSCocoaErrorDomain, code: NSFileReadNoSuchFileError, userInfo: [NSFilePathErrorKey: path]),
            NSError(domain: NSPOSIXErrorDomain, code: Int(EACCES), userInfo: [NSLocalizedDescriptionKey: path]),
            CocoaError(.fileWriteOutOfSpace, userInfo: [NSFilePathErrorKey: path]),
        ]
        for error in errors {
            let text = UserMessage.text(for: error)
            XCTAssertEqual(text, UserMessage.generic)
            XCTAssertFalse(text.contains("alice"))
        }
    }

    func testEveryAppProblemHasAFixedMessage() {
        for problem: AppProblem in [.identityFileUnreadable, .nothingToImport, .exportFailed, .busy] {
            let text = UserMessage.text(for: problem)
            XCTAssertNotEqual(text, UserMessage.generic)
            XCTAssertFalse(text.contains("/"))
        }
    }

    func testIdentityFileReadingIsBounded() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("chotam-msg-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }

        let small = folder.appendingPathComponent("a.pqid")
        try Data(repeating: 1, count: 100).write(to: small)
        XCTAssertEqual(try IdentityFile.read(small).count, 100)

        let huge = folder.appendingPathComponent("b.pqid")
        try Data(repeating: 1, count: IdentityFile.readLimit + 1).write(to: huge)
        XCTAssertThrowsError(try IdentityFile.read(huge)) { XCTAssertEqual($0 as? AppProblem, .identityFileUnreadable) }
        XCTAssertThrowsError(try IdentityFile.read(folder.appendingPathComponent("missing.pqid"))) {
            XCTAssertEqual($0 as? AppProblem, .identityFileUnreadable)
        }
    }

    func testExportWritesExactlyThePublicBytes() throws {
        let alice = try someoneElse("Alice")
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("chotam-export-\(UUID().uuidString).pqid")
        defer { try? FileManager.default.removeItem(at: url) }
        try IdentityFile.export(alice, to: url)
        let written = try Data(contentsOf: url)
        XCTAssertEqual(written, alice.exportedData)
        XCTAssertEqual(try IdentityImport.parse(data: try IdentityFile.read(url)), alice)
        XCTAssertThrowsError(try IdentityFile.export(alice, to: URL(fileURLWithPath: "/nonexistent-\(UUID())/x.pqid"))) {
            XCTAssertEqual($0 as? AppProblem, .exportFailed)
        }
    }

    func testExportName() throws {
        let alice = try someoneElse("Alice")
        XCTAssertEqual(IdentityFile.exportName(for: alice), "Alice.pqid")
        XCTAssertEqual(IdentityFile.exportName(for: try someoneElse("a/b:c")), "a b c.pqid")
        XCTAssertEqual(IdentityFile.exportName(for: try someoneElse(".hidden")), "Identity.pqid")
    }

    func testPassphraseRevealNumbersTheWords() {
        let reveal = PassphraseReveal("alpha  bravo\tcharlie drop-down echo foxtrot golf")
        XCTAssertEqual(reveal.words.map(\.text), ["alpha", "bravo", "charlie", "drop-down", "echo", "foxtrot", "golf"])
        XCTAssertEqual(reveal.words.map(\.number), [1, 2, 3, 4, 5, 6, 7])
        XCTAssertEqual(reveal.confirmationText, "I've written down all 7 words, in order.")
    }
}
