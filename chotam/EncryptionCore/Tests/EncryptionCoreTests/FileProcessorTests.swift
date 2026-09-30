import Foundation
import XCTest
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
@testable import EncryptionCore

/// The public file API through real files: round trips, safe writes and cleanup,
/// restored filenames, and the public errors (SECURITY.md D9, D12, D13).
///
/// Argon2id runs at the cheapest accepted cost, except in
/// `testPublicAPIWritesTheSensitiveCost`.
final class FileProcessorTests: XCTestCase {
    private let c = Fixtures.chunk
    private let fast = EncryptionMode.password(PasswordFixtures.password, cost: PasswordFixtures.fast)
    private let key = DecryptionMode.password(PasswordFixtures.password)
    private let wrongKey = DecryptionMode.password("correct horse battery stapler")

    // MARK: Helpers

    /// Writes `Report.pdf` into the scratch folder and encrypts it beside itself.
    private func makeEncrypted(
        _ s: Scratch, contents: [UInt8], name: String = "Report.pdf"
    ) throws -> (input: URL, encrypted: URL) {
        let input = try s.write(contents, to: name)
        let encrypted = try FileProcessor.encrypt(input, to: .folder(s.folder), using: fast)
        return (input, encrypted)
    }

    private func assertThrows<E: Error & Equatable>(
        _ expected: E, _ message: String = "",
        file: StaticString = #filePath, line: UInt = #line,
        _ body: () throws -> Void
    ) {
        do {
            try body()
            XCTFail("expected \(expected) \(message)", file: file, line: line)
        } catch let error as E {
            XCTAssertEqual(error, expected, message, file: file, line: line)
        } catch {
            XCTFail("unexpected error \(error) \(message)", file: file, line: line)
        }
    }

    /// Every temp file is gone, and so is the private folder it was made in. (A
    /// hidden `.chotam-…` fallback lives in the destination folder, which stays.)
    private func assertCleanedUp(_ probe: OutputProbe, file: StaticString = #filePath, line: UInt = #line) {
        for temp in probe.tempFiles {
            XCTAssertFalse(fileExists(temp), "temp file left behind", file: file, line: line)
            if !temp.lastPathComponent.hasPrefix(".") {
                XCTAssertFalse(
                    fileExists(temp.deletingLastPathComponent()), "temp folder left behind",
                    file: file, line: line)
            }
        }
    }

    private func flipLastByte(_ url: URL) throws {
        var bytes = try readFile(url)
        bytes[bytes.count - 1] ^= 0x01
        try Data(bytes).write(to: url)
    }

    // MARK: Round trips

    /// "Report.pdf" makes a 12-byte metadata record, so `c - 12` and `2c - 12` fill
    /// exactly one and exactly two chunks.
    func testRoundTripsThroughRealFiles() throws {
        for size in [0, 1, c - 12, 2 * c - 12, 3 * c + 7] {
            let s = try Scratch()
            defer { s.remove() }
            let contents = Fixtures.pattern(size, seed: UInt64(size) &+ 5)
            let input = try s.write(contents, to: "Report.pdf")
            let probe = OutputProbe()

            let encrypted = try FileProcessor.encrypt(
                input, to: .folder(s.folder), using: fast, hooks: probe.hooks)
            XCTAssertEqual(encrypted.lastPathComponent, "Report.pdf.enc")
            XCTAssertEqual(Array(try readFile(encrypted).prefix(9)), FormatV1.magic + [0, 1, 1])

            let destination = s.url("Restored.pdf")
            let decrypted = try FileProcessor.decrypt(
                encrypted, to: .file(destination), using: key, hooks: probe.hooks)
            XCTAssertEqual(decrypted, DecryptedFile(url: destination, storedFilename: "Report.pdf"))
            XCTAssertEqual(try readFile(destination), contents, "size \(size)")

            // The original is never modified or removed.
            XCTAssertEqual(try readFile(input), contents, "size \(size)")
            XCTAssertEqual(Set(try s.snapshot().keys), ["Report.pdf", "Report.pdf.enc", "Restored.pdf"])
            XCTAssertEqual(probe.tempFiles.count, 2)
            assertCleanedUp(probe)
        }
    }

    /// The public entry points, which always use the SENSITIVE preset (ops 4, 1 GiB).
    func testPublicAPIWritesTheSensitiveCost() throws {
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write([1, 2, 3], to: "a.txt")
        let encrypted = try FileProcessor.encrypt(
            input, to: .folder(s.folder), using: .password(PasswordFixtures.password))
        let header = try HeaderCodec.decode(
            Array(try readFile(encrypted).prefix(FormatV1.passwordHeaderLength)))
        guard case .password(let parameters) = header.parameters else {
            return XCTFail("not a password-mode header")
        }
        XCTAssertEqual(parameters.opsLimit, 4)
        XCTAssertEqual(parameters.memLimit, 1 << 30)

        let decrypted = try FileProcessor.decrypt(
            encrypted, to: .folder(try s.makeFolder("out")), using: .password(PasswordFixtures.password))
        XCTAssertEqual(try readFile(decrypted.url), [1, 2, 3])
        XCTAssertEqual(decrypted.url.lastPathComponent, "a.txt")
    }

    /// Both the temp file and the result are readable by the owner only.
    func testOutputsAreOwnerOnly() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (_, encrypted) = try makeEncrypted(s, contents: [1, 2, 3])
        XCTAssertEqual(try permissions(encrypted), 0o600)
        let decrypted = try FileProcessor.decrypt(encrypted, to: .file(s.url("out.pdf")), using: key)
        XCTAssertEqual(try permissions(decrypted.url), 0o600)
    }

    func testSuggestedNames() {
        func url(_ name: String) -> URL { URL(fileURLWithPath: "/tmp").appendingPathComponent(name) }
        XCTAssertEqual(FileProcessor.encryptedName(for: url("Document.pdf")), "Document.pdf.enc")
        XCTAssertEqual(FileProcessor.decryptedName(for: url("Document.pdf.enc")), "Document.pdf")
        XCTAssertEqual(FileProcessor.decryptedName(for: url("Document.pdf.ENC")), "Document.pdf")
        XCTAssertEqual(FileProcessor.decryptedName(for: url("attachment")), "attachment.decrypted")
        XCTAssertEqual(FileProcessor.decryptedName(for: url(".enc")), ".enc.decrypted")
    }

    // MARK: Restored filename (D12)

    /// The `.enc` was renamed in transit; decrypting into a folder brings the name back.
    func testFolderDestinationRestoresTheStoredName() throws {
        let s = try Scratch()
        defer { s.remove() }
        let contents = Fixtures.pattern(1000)
        let (_, encrypted) = try makeEncrypted(s, contents: contents)
        let renamed = s.url("a1b2c3.enc")
        try FileManager.default.moveItem(at: encrypted, to: renamed)
        let out = try s.makeFolder("out")

        let decrypted = try FileProcessor.decrypt(renamed, to: .folder(out), using: key)
        XCTAssertEqual(decrypted.url.lastPathComponent, "Report.pdf")
        XCTAssertEqual(
            decrypted.url.deletingLastPathComponent().standardizedFileURL.path,
            out.standardizedFileURL.path)
        XCTAssertEqual(decrypted.storedFilename, "Report.pdf")
        XCTAssertEqual(try readFile(decrypted.url), contents)
    }

    func testFolderDestinationNeverReplacesAndCountsUp() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (_, encrypted) = try makeEncrypted(s, contents: [7, 7, 7])
        try s.makeFolder("out")
        try s.write([1], to: "out/Report.pdf")
        try s.write([2], to: "out/Report 2.pdf")

        let third = try FileProcessor.decrypt(encrypted, to: .folder(s.url("out")), using: key)
        XCTAssertEqual(third.url.lastPathComponent, "Report 3.pdf")
        let fourth = try FileProcessor.decrypt(encrypted, to: .folder(s.url("out")), using: key)
        XCTAssertEqual(fourth.url.lastPathComponent, "Report 4.pdf")

        XCTAssertEqual(try readFile(s.url("out/Report.pdf")), [1])
        XCTAssertEqual(try readFile(s.url("out/Report 2.pdf")), [2])
        XCTAssertEqual(try readFile(third.url), [7, 7, 7])
        XCTAssertEqual(try readFile(fourth.url), [7, 7, 7])
    }

    /// `Report 2.pdf.enc`, not `Report.pdf 2.enc`, so it decrypts to a sensible name.
    func testEncryptingIntoAFolderCountsUpToo() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (input, first) = try makeEncrypted(s, contents: [1, 2])
        let firstBytes = try readFile(first)
        let second = try FileProcessor.encrypt(input, to: .folder(s.folder), using: fast)
        XCTAssertEqual(second.lastPathComponent, "Report 2.pdf.enc")
        XCTAssertEqual(try readFile(first), firstBytes)
        XCTAssertEqual(FileProcessor.decryptedName(for: second), "Report 2.pdf")
    }

    /// Names the decoder accepts but that must not name a new file fall back to the
    /// encrypted file's own name. The stored name is still returned, for display.
    func testUnsafeStoredNamesAreNotUsed() throws {
        let unsafe = [".zshrc", String(repeating: "x", count: 300), "a:b.txt"]
        for stored in unsafe {
            let s = try Scratch()
            defer { s.remove() }
            try s.write(try passwordSeal([1, 2, 3], filename: stored), to: "secret.enc")
            let out = try s.makeFolder("out")

            let decrypted = try FileProcessor.decrypt(s.url("secret.enc"), to: .folder(out), using: key)
            XCTAssertEqual(decrypted.url.lastPathComponent, "secret", stored)
            XCTAssertEqual(decrypted.storedFilename, stored)
            XCTAssertEqual(try s.snapshot().keys.sorted(), ["out", "out/secret", "secret.enc"], stored)
        }
    }

    func testFallbackNamesWithoutAStoredName() throws {
        let cases: [(input: String, expected: String)] = [
            ("blob", "blob.decrypted"),
            (".hidden.enc", OutputNaming.fallbackName),
        ]
        for (inputName, expected) in cases {
            let s = try Scratch()
            defer { s.remove() }
            try s.write(try passwordSeal([4, 5], filename: nil), to: inputName)
            let out = try s.makeFolder("out")
            let decrypted = try FileProcessor.decrypt(s.url(inputName), to: .folder(out), using: key)
            XCTAssertEqual(decrypted.url.lastPathComponent, expected, inputName)
            XCTAssertNil(decrypted.storedFilename)
        }
    }

    /// An exact destination is used as given; the stored name is only reported.
    func testExactDestinationIgnoresTheStoredName() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (_, encrypted) = try makeEncrypted(s, contents: [1])
        let decrypted = try FileProcessor.decrypt(encrypted, to: .file(s.url("chosen.bin")), using: key)
        XCTAssertEqual(decrypted.url, s.url("chosen.bin"))
        XCTAssertEqual(decrypted.storedFilename, "Report.pdf")
        XCTAssertEqual(Set(try s.snapshot().keys), ["Report.pdf", "Report.pdf.enc", "chosen.bin"])
    }

    // MARK: Simulated failures leave nothing behind

    func testMidWriteFailureWhileEncryptingLeavesNothing() throws {
        for useFolder in [true, false] {
            let s = try Scratch()
            defer { s.remove() }
            let input = try s.write(Fixtures.pattern(3 * c), to: "Report.pdf")
            let before = try s.snapshot()
            let probe = OutputProbe()
            // Fails after the header and the whole first chunk are on disk.
            probe.failWriteAt = FormatV1.passwordHeaderLength + Fixtures.sealedChunk
            let destination: Destination = useFolder ? .folder(s.folder) : .file(s.url("Report.pdf.enc"))

            assertThrows(EncryptionError.file(.writeFailed), "folder: \(useFolder)") {
                _ = try FileProcessor.encrypt(input, to: destination, using: fast, hooks: probe.hooks)
            }
            XCTAssertEqual(probe.tempFiles.count, 1)
            assertCleanedUp(probe)
            XCTAssertEqual(try s.snapshot(), before, "no partial output; the original is intact")
        }
    }

    func testMidWriteFailureWhileDecryptingLeavesNothing() throws {
        for useFolder in [true, false] {
            let s = try Scratch()
            defer { s.remove() }
            let (_, encrypted) = try makeEncrypted(s, contents: Fixtures.pattern(3 * c))
            let out = try s.makeFolder("out")
            let before = try s.snapshot()
            let probe = OutputProbe()
            probe.failWriteAt = 1  // the first chunk's plaintext is written, then the next write fails
            let destination: Destination = useFolder ? .folder(out) : .file(s.url("out/Report.pdf"))

            assertThrows(DecryptionError.file(.writeFailed), "folder: \(useFolder)") {
                _ = try FileProcessor.decrypt(encrypted, to: destination, using: key, hooks: probe.hooks)
            }
            XCTAssertEqual(probe.tempFiles.count, 1)
            assertCleanedUp(probe)
            XCTAssertEqual(try s.snapshot(), before)
        }
    }

    /// Everything is written, then committing it fails.
    func testFailureAtCommitLeavesNothing() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (input, encrypted) = try makeEncrypted(s, contents: Fixtures.pattern(2 * c))
        let out = try s.makeFolder("out")
        let before = try s.snapshot()

        let encryptProbe = OutputProbe()
        encryptProbe.failAtCommit = true
        assertThrows(EncryptionError.file(.writeFailed)) {
            _ = try FileProcessor.encrypt(input, to: .folder(out), using: fast, hooks: encryptProbe.hooks)
        }
        let decryptProbe = OutputProbe()
        decryptProbe.failAtCommit = true
        assertThrows(DecryptionError.file(.writeFailed)) {
            _ = try FileProcessor.decrypt(encrypted, to: .folder(out), using: key, hooks: decryptProbe.hooks)
        }
        for probe in [encryptProbe, decryptProbe] {
            XCTAssertEqual(probe.tempFiles.count, 1)
            assertCleanedUp(probe)
        }
        XCTAssertEqual(try s.snapshot(), before)
    }

    // MARK: Existing outputs

    func testExistingOutputSurvivesAFailedReplacement() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (input, encrypted) = try makeEncrypted(s, contents: Fixtures.pattern(3 * c), name: "Report.pdf")
        let existingEnc = try s.write([0xAA, 0xBB], to: "Existing.enc")
        let existingPlain = try s.write([0xCC], to: "Existing.pdf")
        let before = try s.snapshot()

        // Encrypting over an existing file fails mid-write.
        let probe = OutputProbe()
        probe.failWriteAt = FormatV1.passwordHeaderLength + Fixtures.sealedChunk
        assertThrows(EncryptionError.file(.writeFailed)) {
            _ = try FileProcessor.encrypt(
                input, to: .file(existingEnc, replacingExisting: true), using: fast, hooks: probe.hooks)
        }
        // Decrypting over an existing file fails mid-write.
        let decryptProbe = OutputProbe()
        decryptProbe.failWriteAt = 1
        assertThrows(DecryptionError.file(.writeFailed)) {
            _ = try FileProcessor.decrypt(
                encrypted, to: .file(existingPlain, replacingExisting: true), using: key,
                hooks: decryptProbe.hooks)
        }
        // Decrypting over an existing file with a wrong password.
        assertThrows(DecryptionError.failed) {
            _ = try FileProcessor.decrypt(
                encrypted, to: .file(existingPlain, replacingExisting: true), using: wrongKey)
        }
        XCTAssertEqual(try s.snapshot(), before)

        // A tampered final chunk: detected only after earlier chunks were written.
        try flipLastByte(encrypted)
        let tamperedBefore = try s.snapshot()
        assertThrows(DecryptionError.failed) {
            _ = try FileProcessor.decrypt(
                encrypted, to: .file(existingPlain, replacingExisting: true), using: key)
        }
        XCTAssertEqual(try s.snapshot(), tamperedBefore)
        assertCleanedUp(probe)
        assertCleanedUp(decryptProbe)
    }

    func testReplacingAnExistingOutputWhenAllowed() throws {
        let s = try Scratch()
        defer { s.remove() }
        let contents = Fixtures.pattern(c + 5)
        let (input, encrypted) = try makeEncrypted(s, contents: contents)
        let existingPlain = try s.write([0xCC], to: "Existing.pdf")
        let existingEnc = try s.write([0xAA], to: "Existing.enc")

        let decrypted = try FileProcessor.decrypt(
            encrypted, to: .file(existingPlain, replacingExisting: true), using: key)
        XCTAssertEqual(try readFile(existingPlain), contents)
        XCTAssertEqual(try readFile(decrypted.url), contents)
        XCTAssertEqual(try permissions(existingPlain), 0o600)

        _ = try FileProcessor.encrypt(input, to: .file(existingEnc, replacingExisting: true), using: fast)
        let reopened = try FileProcessor.decrypt(existingEnc, to: .file(s.url("again.pdf")), using: key)
        XCTAssertEqual(try readFile(reopened.url), contents)
        XCTAssertEqual(
            Set(try s.snapshot().keys),
            ["Report.pdf", "Report.pdf.enc", "Existing.pdf", "Existing.enc", "again.pdf"])
    }

    /// Without permission to replace, an existing output is refused before any
    /// work: no temp file, no Argon2id.
    func testExistingOutputIsRefusedUpFront() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (input, encrypted) = try makeEncrypted(s, contents: [1, 2, 3])
        let existing = try s.write([9], to: "Existing.pdf")
        let before = try s.snapshot()
        let probe = OutputProbe()

        assertThrows(EncryptionError.file(.outputExists)) {
            _ = try FileProcessor.encrypt(input, to: .file(existing), using: fast, hooks: probe.hooks)
        }
        assertThrows(DecryptionError.file(.outputExists)) {
            _ = try FileProcessor.decrypt(encrypted, to: .file(existing), using: key, hooks: probe.hooks)
        }
        // Cheap password and name checks come before looking at the destination.
        assertThrows(EncryptionError.weakPassword) {
            _ = try FileProcessor.encrypt(
                input, to: .file(existing), using: .password("short", cost: PasswordFixtures.fast))
        }
        XCTAssertEqual(probe.tempFiles, [])
        XCTAssertEqual(try s.snapshot(), before)
    }

    // MARK: Decryption failures

    /// A wrong password or a tampered header fails at the commitment check, before
    /// any chunk is opened, so no temp file is ever created.
    func testWrongPasswordOrTamperedHeaderCreatesNothing() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (_, encrypted) = try makeEncrypted(s, contents: Fixtures.pattern(3 * c))
        var tampered = try readFile(encrypted)
        tampered[HeaderOffsets.hkdfSalt] ^= 0x01
        let tamperedURL = try s.write(tampered, to: "tampered.enc")
        let out = try s.makeFolder("out")
        let before = try s.snapshot()
        let probe = OutputProbe()

        for destination in [Destination.folder(out), .file(s.url("out/x.pdf"))] {
            assertThrows(DecryptionError.failed) {
                _ = try FileProcessor.decrypt(encrypted, to: destination, using: wrongKey, hooks: probe.hooks)
            }
            assertThrows(DecryptionError.failed) {
                _ = try FileProcessor.decrypt(tamperedURL, to: destination, using: key, hooks: probe.hooks)
            }
        }
        XCTAssertEqual(probe.tempFiles, [], "no file may be created")
        XCTAssertEqual(try s.snapshot(), before)
    }

    /// Tampering in the last chunk is found after earlier plaintext reached the temp
    /// file. That file is deleted and nothing gets an output name.
    func testTamperedLastChunkDeletesTheTempFile() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (_, encrypted) = try makeEncrypted(s, contents: Fixtures.pattern(3 * c + 5))
        try flipLastByte(encrypted)
        let out = try s.makeFolder("out")
        let before = try s.snapshot()
        let probe = OutputProbe()

        assertThrows(DecryptionError.failed) {
            _ = try FileProcessor.decrypt(encrypted, to: .folder(out), using: key, hooks: probe.hooks)
        }
        XCTAssertEqual(probe.tempFiles.count, 1)
        assertCleanedUp(probe)
        XCTAssertEqual(try s.snapshot(), before)
    }

    func testGarbageFilesGiveOnlyTheGenericMessage() throws {
        let s = try Scratch()
        defer { s.remove() }
        let out = try s.makeFolder("out")
        let inputs: [(String, [UInt8])] = [
            ("garbage.enc", Fixtures.pattern(500)),
            ("empty.enc", []),
            ("magic.enc", FormatV1.magic),
            ("header-only.enc", Array(try passwordSeal([1]).prefix(FormatV1.passwordHeaderLength))),
        ]
        let probe = OutputProbe()
        for (name, bytes) in inputs {
            let url = try s.write(bytes, to: name)
            do {
                _ = try FileProcessor.decrypt(url, to: .folder(out), using: key, hooks: probe.hooks)
                XCTFail("expected failure: \(name)")
            } catch let error as DecryptionError {
                XCTAssertEqual(error, .failed, name)
                XCTAssertEqual(error.localizedDescription, DecryptionFailed.message, name)
            } catch {
                XCTFail("unexpected error \(error): \(name)")
            }
        }
        XCTAssertEqual(probe.tempFiles, [])
        XCTAssertEqual(try s.snapshot().keys.filter { $0.hasPrefix("out/") }, [])
    }

    // MARK: Refused inputs and destinations

    func testWeakPasswordsAndUnstorableNamesAreRefused() throws {
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write([1], to: "Report.pdf")
        let spoofed = try s.write([1], to: "invoice\u{202E}fdp.exe")
        let newline = try s.write([1], to: "line\nbreak.txt")
        let long = try s.write([1], to: String(repeating: "x", count: 248) + ".txt")  // 252 bytes; +".enc" = 256
        let before = try s.snapshot()
        let probe = OutputProbe()

        for weak in ["", "short", "Password12345678", "aaaaaaaaaaaaaaaaaaaa"] {
            assertThrows(EncryptionError.weakPassword, weak) {
                _ = try FileProcessor.encrypt(
                    input, to: .folder(s.folder), using: .password(weak, cost: PasswordFixtures.fast),
                    hooks: probe.hooks)
            }
        }
        for bad in [spoofed, newline, long] {
            assertThrows(EncryptionError.invalidFilename, bad.lastPathComponent.debugDescription) {
                _ = try FileProcessor.encrypt(bad, to: .folder(s.folder), using: fast, hooks: probe.hooks)
            }
        }
        XCTAssertEqual(probe.tempFiles, [])
        XCTAssertEqual(try s.snapshot(), before)
    }

    func testUnsafeDestinationsAreRefused() throws {
        let s = try Scratch()
        defer { s.remove() }
        let (input, encrypted) = try makeEncrypted(s, contents: [1, 2, 3])
        let folder = try s.makeFolder("folder")
        let hardLink = s.url("hardlink.pdf")
        try FileManager.default.linkItem(at: input, to: hardLink)
        let symlink = s.url("symlink.enc")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: s.url("elsewhere"))
        let before = try s.snapshot()

        let destinations: [(String, Destination)] = [
            ("the input", .file(input)),
            ("the input, replacing", .file(input, replacingExisting: true)),
            ("a hard link to the input", .file(hardLink, replacingExisting: true)),
            ("a folder", .file(folder, replacingExisting: true)),
            ("a symbolic link", .file(symlink, replacingExisting: true)),
            ("a file as the folder", .folder(input)),
            ("a missing folder", .folder(s.url("missing"))),
        ]
        for (label, destination) in destinations {
            assertThrows(EncryptionError.file(.invalidDestination), label) {
                _ = try FileProcessor.encrypt(input, to: destination, using: fast)
            }
        }
        assertThrows(DecryptionError.file(.invalidDestination)) {
            _ = try FileProcessor.decrypt(encrypted, to: .file(encrypted, replacingExisting: true), using: key)
        }
        XCTAssertEqual(try s.snapshot(), before)
    }

    func testMissingOrFolderInputsAreRefused() throws {
        let s = try Scratch()
        defer { s.remove() }
        let folder = try s.makeFolder("Package.pages")
        let missing = s.url("missing.pdf")

        assertThrows(EncryptionError.file(.readFailed)) {
            _ = try FileProcessor.encrypt(missing, to: .folder(s.folder), using: fast)
        }
        assertThrows(DecryptionError.file(.readFailed)) {
            _ = try FileProcessor.decrypt(missing, to: .folder(s.folder), using: key)
        }
        assertThrows(EncryptionError.file(.inputNotAFile)) {
            _ = try FileProcessor.encrypt(folder, to: .folder(s.folder), using: fast)
        }
        assertThrows(DecryptionError.file(.inputNotAFile)) {
            _ = try FileProcessor.decrypt(folder, to: .folder(s.folder), using: key)
        }
        XCTAssertEqual(Set(try s.snapshot().keys), ["Package.pages"])
    }

    // MARK: Errors

    func testErrorMapping() {
        XCTAssertEqual(FileProcessor.decryptionError(for: CoreFailure(.keyDerivationFailed)), .notEnoughMemory)
        XCTAssertEqual(FileProcessor.decryptionError(for: CoreFailure(.readFailed)), .file(.readFailed))
        XCTAssertEqual(FileProcessor.decryptionError(for: CoreFailure(.writeFailed)), .file(.writeFailed))
        XCTAssertEqual(FileProcessor.decryptionError(for: FileProblem.outputExists), .file(.outputExists))
        // Everything about the contents or the key stays generic.
        let generic: [CoreFailure.Reason] = [
            .commitmentMismatch, .chunkAuthenticationFailed, .truncatedBody, .truncatedHeader,
            .badMagic, .wrongMode, .malformedMetadata, .argon2ParametersOutOfRange, .unexpected,
        ]
        for reason in generic {
            XCTAssertEqual(FileProcessor.decryptionError(for: CoreFailure(reason)), .failed, reason.rawValue)
        }
        XCTAssertEqual(FileProcessor.decryptionError(for: OutputProbe.SimulatedFailure()), .failed)

        XCTAssertEqual(FileProcessor.encryptionError(for: CoreFailure(.weakPassword)), .weakPassword)
        XCTAssertEqual(FileProcessor.encryptionError(for: CoreFailure(.invalidFilename)), .invalidFilename)
        XCTAssertEqual(FileProcessor.encryptionError(for: CoreFailure(.keyDerivationFailed)), .notEnoughMemory)
        XCTAssertEqual(FileProcessor.encryptionError(for: CoreFailure(.readFailed)), .file(.readFailed))
        XCTAssertEqual(FileProcessor.encryptionError(for: FileProblem.accessDenied), .file(.accessDenied))
        XCTAssertEqual(FileProcessor.encryptionError(for: CoreFailure(.tooManyChunks)), .unexpected)

        XCTAssertEqual(FileProblem.posix(EACCES, otherwise: .writeFailed), .accessDenied)
        XCTAssertEqual(FileProblem.posix(ENOSPC, otherwise: .writeFailed), .writeFailed)
        XCTAssertEqual(FileProblem.classify(CocoaError(.fileWriteNoPermission), otherwise: .writeFailed), .accessDenied)
        XCTAssertEqual(FileProblem.classify(CocoaError(.fileReadNoSuchFile), otherwise: .readFailed), .readFailed)
    }

    func testErrorMessagesAreFixedAndDistinct() {
        let problems: [FileProblem] = [
            .inputNotAFile, .outputExists, .invalidDestination, .accessDenied, .readFailed, .writeFailed,
        ]
        let encryption: [EncryptionError] = [.weakPassword, .invalidFilename, .notEnoughMemory, .unexpected]
        let decryption: [DecryptionError] = [.failed, .notEnoughMemory]
        let messages = problems.map(\.errorDescription) + encryption.map(\.errorDescription)
            + decryption.map(\.errorDescription)
        XCTAssertFalse(messages.contains(nil))
        XCTAssertEqual(Set(messages).count, messages.count)
        XCTAssertEqual(DecryptionError.failed.errorDescription, DecryptionFailed.message)
        XCTAssertEqual(EncryptionError.file(.outputExists).errorDescription, FileProblem.outputExists.errorDescription)
    }

    func testModesNeverShowThePassword() {
        let secret = "correct horse battery staple"
        let texts = [
            String(describing: EncryptionMode.password(secret)),
            String(reflecting: EncryptionMode.password(secret)),
            String(describing: DecryptionMode.password(secret)),
            String(reflecting: DecryptionMode.password(secret)),
        ]
        for text in texts {
            XCTAssertFalse(text.contains("horse"), text)
        }
        var dumped = ""
        dump(EncryptionMode.password(secret), to: &dumped)
        dump(DecryptionMode.password(secret), to: &dumped)
        XCTAssertFalse(dumped.contains("horse"))
    }
}
