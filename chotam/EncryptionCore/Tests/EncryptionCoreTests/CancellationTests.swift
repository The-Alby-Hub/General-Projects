import Foundation
import XCTest
@testable import EncryptionCore

/// Cancelling at any point, in either pass, must leave nothing behind: no temp file, no
/// partial output, nothing at the destination, the input untouched. Cancellation unwinds
/// exactly like a failure, so the same `defer`s delete the temp file and release and
/// wipe the keys and buffers (SECURITY.md §7.3).
///
/// `ProgressHook` is internal until Phase 6 makes it public.
final class CancellationTests: XCTestCase {
    private let c = Fixtures.chunk

    /// Cancels once at least `fraction` of the expected total has been read, and records
    /// every progress report.
    private final class Canceller {
        let fraction: Double
        private(set) var reports: [(completed: Int64, total: Int64)] = []
        private(set) var cancelled = false

        init(at fraction: Double) {
            self.fraction = fraction
        }

        var hook: ProgressHook {
            ProgressHook(
                report: { [unowned self] completed, total in reports.append((completed, total)) },
                isCancelled: { [unowned self] in
                    guard let last = reports.last, last.total > 0 else { return fraction <= 0 }
                    if Double(last.completed) >= fraction * Double(last.total) {
                        cancelled = true
                    }
                    return cancelled
                })
        }
    }

    private func assertCleanedUp(_ probe: OutputProbe, file: StaticString = #filePath, line: UInt = #line) {
        for temp in probe.tempFiles {
            XCTAssertFalse(fileExists(temp), "temp file left behind", file: file, line: line)
            if !temp.lastPathComponent.hasPrefix(".") {
                XCTAssertFalse(
                    fileExists(temp.deletingLastPathComponent()), "temp folder left behind", file: file, line: line)
            }
        }
    }

    private func decryptError(_ body: () throws(DecryptionError) -> DecryptedFile) -> DecryptionError? {
        do {
            _ = try body()
            return nil
        } catch {
            return error
        }
    }

    private func encryptError(_ body: () throws(EncryptionError) -> URL) -> EncryptionError? {
        do {
            _ = try body()
            return nil
        } catch {
            return error
        }
    }

    /// Alice → Bob, an encrypted file of about 6 chunks, in a fresh scratch folder.
    private func setUpRecipientFile() throws -> (s: Scratch, alice: Person, bob: Person, list: RecipientList, input: URL, encrypted: URL) {
        let alice = try Person("Alice")
        let bob = try Person("Bob")
        let list = try RecipientList([try alice.add(bob)])
        try bob.add(alice)
        let s = try Scratch()
        let input = try s.write(Fixtures.pattern(6 * c + 123), to: "Report.pdf")
        let encrypted = try FileProcessor.encrypt(input, to: .folder(s.folder), using: .recipients(list, signedBy: alice.identity))
        return (s, alice, bob, list, input, encrypted)
    }

    // MARK: Encrypting

    func testCancellingARecipientEncryptionLeavesNothing() throws {
        let (s, alice, _, list, input, _) = try setUpRecipientFile()
        defer { s.remove() }
        let before = try s.snapshot()
        for fraction in [0.0, 0.3, 0.7, 1.0] {
            let canceller = Canceller(at: fraction)
            let probe = OutputProbe()
            XCTAssertEqual(
                encryptError {
                    try FileProcessor.encrypt(
                        input, to: .file(s.url("new.enc")), using: .recipients(list, signedBy: alice.identity),
                        hooks: probe.hooks, progress: canceller.hook)
                },
                .cancelled, "at \(fraction)")
            if fraction > 0, fraction < 1 {
                XCTAssertFalse(probe.tempFiles.isEmpty, "cancelled mid-write at \(fraction)")
            }
            assertCleanedUp(probe)
            XCTAssertEqual(try s.snapshot(), before, "at \(fraction)")
        }
        // The identity is untouched: the same request without cancelling works.
        XCTAssertNoThrow(try FileProcessor.encrypt(input, to: .file(s.url("new.enc")), using: .recipients(list, signedBy: alice.identity)))
    }

    func testCancellingAPasswordEncryptionLeavesNothing() throws {
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write(Fixtures.pattern(5 * c), to: "Report.pdf")
        let before = try s.snapshot()
        for fraction in [0.0, 0.5, 1.0] {
            let canceller = Canceller(at: fraction)
            let probe = OutputProbe()
            XCTAssertEqual(
                encryptError {
                    try FileProcessor.encrypt(
                        input, to: .folder(s.folder),
                        using: .password(PasswordFixtures.password, cost: PasswordFixtures.fast),
                        hooks: probe.hooks, progress: canceller.hook)
                },
                .cancelled, "at \(fraction)")
            assertCleanedUp(probe)
            XCTAssertEqual(try s.snapshot(), before, "at \(fraction)")
        }
    }

    // MARK: Decrypting

    /// Pass 1 is the first half of the progress (the file is read twice). Cancelled
    /// there, nothing has been unwrapped or written: not even a temp file exists.
    func testCancellingDecryptionInPassOneCreatesNothing() throws {
        let (s, _, bob, _, _, encrypted) = try setUpRecipientFile()
        defer { s.remove() }
        let out = try s.makeFolder("out")
        let before = try s.snapshot()
        for fraction in [0.0, 0.1, 0.25, 0.45] {
            let canceller = Canceller(at: fraction)
            let probe = OutputProbe()
            XCTAssertEqual(
                decryptError {
                    try FileProcessor.decrypt(
                        encrypted, to: .folder(out), using: .identity(bob.identity), hooks: probe.hooks,
                        progress: canceller.hook)
                },
                .cancelled, "at \(fraction)")
            XCTAssertEqual(probe.tempFiles, [], "nothing is written in pass 1 (at \(fraction))")
            XCTAssertEqual(try s.snapshot(), before, "at \(fraction)")
        }
    }

    /// Pass 2 is the second half. Cancelled there, plaintext has already gone into the
    /// temp file: it must be deleted, and nothing may appear at the destination.
    func testCancellingDecryptionInPassTwoDeletesThePartialPlaintext() throws {
        let (s, _, bob, _, _, encrypted) = try setUpRecipientFile()
        defer { s.remove() }
        let out = try s.makeFolder("out")
        let before = try s.snapshot()
        for fraction in [0.6, 0.8, 0.95, 1.0] {
            let canceller = Canceller(at: fraction)
            let probe = OutputProbe()
            XCTAssertEqual(
                decryptError {
                    try FileProcessor.decrypt(
                        encrypted, to: .folder(out), using: .identity(bob.identity), hooks: probe.hooks,
                        progress: canceller.hook)
                },
                .cancelled, "at \(fraction)")
            XCTAssertFalse(probe.tempFiles.isEmpty, "pass 2 had started writing (at \(fraction))")
            assertCleanedUp(probe)
            XCTAssertEqual(try s.snapshot(), before, "at \(fraction)")
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: out.path), [])
        }
        // Replacing an existing file: cancelled, the old file is untouched.
        let existing = try s.write([9, 9, 9], to: "existing.pdf")
        let canceller = Canceller(at: 0.9)
        XCTAssertEqual(
            decryptError {
                try FileProcessor.decrypt(
                    encrypted, to: .file(existing, replacingExisting: true), using: .identity(bob.identity),
                    hooks: AtomicOutput.Hooks(), progress: canceller.hook)
            },
            .cancelled)
        XCTAssertEqual(try readFile(existing), [9, 9, 9])
    }

    func testCancellingAPasswordDecryptionLeavesNothing() throws {
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write(Fixtures.pattern(5 * c), to: "Report.pdf")
        let encrypted = try FileProcessor.encrypt(
            input, to: .folder(s.folder), using: .password(PasswordFixtures.password, cost: PasswordFixtures.fast))
        let out = try s.makeFolder("out")
        let before = try s.snapshot()
        for fraction in [0.0, 0.5, 1.0] {
            let canceller = Canceller(at: fraction)
            let probe = OutputProbe()
            XCTAssertEqual(
                decryptError {
                    try FileProcessor.decrypt(
                        encrypted, to: .folder(out), using: .password(PasswordFixtures.password), hooks: probe.hooks,
                        progress: canceller.hook)
                },
                .cancelled, "at \(fraction)")
            assertCleanedUp(probe)
            XCTAssertEqual(try s.snapshot(), before, "at \(fraction)")
        }
    }

    // MARK: Progress

    func testProgressCountsBothPassesAndEndsAtTheTotal() throws {
        let (s, alice, bob, list, input, encrypted) = try setUpRecipientFile()
        defer { s.remove() }
        let inputSize = Int64(try readFile(input).count)
        let encryptedSize = Int64(try readFile(encrypted).count)

        let decrypting = Canceller(at: 2)  // never cancels
        _ = try FileProcessor.decrypt(
            encrypted, to: .folder(try s.makeFolder("out")), using: .identity(bob.identity), hooks: AtomicOutput.Hooks(),
            progress: decrypting.hook)
        XCTAssertEqual(decrypting.reports.last?.completed, 2 * encryptedSize)
        XCTAssertTrue(decrypting.reports.allSatisfy { $0.total == 2 * encryptedSize })
        let completed = decrypting.reports.map { $0.completed }
        XCTAssertEqual(completed, completed.sorted(), "progress never goes backwards")

        let encrypting = Canceller(at: 2)
        _ = try FileProcessor.encrypt(
            input, to: .file(s.url("again.enc")), using: .recipients(list, signedBy: alice.identity),
            hooks: AtomicOutput.Hooks(), progress: encrypting.hook)
        XCTAssertEqual(encrypting.reports.last?.completed, inputSize)
        XCTAssertTrue(encrypting.reports.allSatisfy { $0.total == inputSize })
    }
}
