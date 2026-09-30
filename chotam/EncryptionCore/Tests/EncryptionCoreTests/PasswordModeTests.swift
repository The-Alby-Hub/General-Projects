import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Password mode end to end: Argon2id → HKDF → streaming AES-256-GCM.
///
/// Most tests use the cheapest accepted cost (ops 3, 256 MiB) to stay fast. The
/// SENSITIVE preset is exercised by `testDefaultCostIsSensitiveAndRoundTrips`.
final class PasswordModeTests: XCTestCase {
    private let c = Fixtures.chunk

    private func assertRoundTrip(
        size: Int, password: String = PasswordFixtures.password, filename: String? = "file.bin",
        file: StaticString = #filePath, line: UInt = #line
    ) throws {
        let plaintext = Fixtures.pattern(size, seed: UInt64(size) &+ 99)
        let sealed = try passwordSeal(plaintext, password: password, filename: filename)
        XCTAssertEqual(Array(sealed.prefix(9)), FormatV1.magic + [0, 1, 1], file: file, line: line)
        let opened = try passwordOpen(sealed, password: password)
        XCTAssertEqual(opened.plaintext, plaintext, "size \(size)", file: file, line: line)
        XCTAssertEqual(opened.filename, filename, file: file, line: line)
    }

    private func decodedParameters(_ file: [UInt8]) throws -> FileHeader.PasswordParameters {
        let header = try HeaderCodec.decode(Array(file.prefix(FormatV1.passwordHeaderLength)))
        guard case .password(let parameters) = header.parameters else {
            XCTFail("not a password-mode header")
            throw CoreFailure(.wrongMode)
        }
        return parameters
    }

    // MARK: Round trips

    func testEmptyFile() throws { try assertRoundTrip(size: 0) }
    func testOneByteFile() throws { try assertRoundTrip(size: 1, filename: nil) }

    /// "file.bin" makes a 10-byte metadata record, so these fill exactly one and
    /// exactly two chunks.
    func testExactChunkBoundaries() throws {
        try assertRoundTrip(size: c - 10)
        try assertRoundTrip(size: 2 * c - 10)
    }

    /// Regression test for non-ASCII passwords (SECURITY.md D11), plus NFC handling.
    func testNonASCIIPasswords() throws {
        // Hebrew: "חותם סודי מאוד מאוד"
        try assertRoundTrip(
            size: 100,
            password: "\u{05D7}\u{05D5}\u{05EA}\u{05DD} \u{05E1}\u{05D5}\u{05D3}\u{05D9} \u{05DE}\u{05D0}\u{05D5}\u{05D3} \u{05DE}\u{05D0}\u{05D5}\u{05D3}")
        try assertRoundTrip(size: 100, password: "\u{1F510} my vault key \u{1F5DD} keep out")
    }

    func testPasswordTypedDecomposedOpensFileMadeWithPrecomposed() throws {
        let precomposed = "fa\u{E7}ade d\u{E9}j\u{E0} vu na\u{EF}ve caf\u{E9}"
        let decomposed = precomposed.decomposedStringWithCanonicalMapping
        XCTAssertNotEqual(Array(precomposed.utf8), Array(decomposed.utf8))
        let sealed = try passwordSeal([1, 2, 3], password: precomposed)
        XCTAssertEqual(try passwordOpen(sealed, password: decomposed).plaintext, [1, 2, 3])
    }

    /// > 100 MB through real files. Memory stays flat: the source is generated,
    /// the output is hashed, and no read asks for more than one sealed chunk + 1.
    func testLargeFileRoundTripThroughFiles() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("chotam-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let encrypted = directory.appendingPathComponent("large.bin.enc")
        let size = 100 * (1 << 20) + 1

        XCTAssertTrue(FileManager.default.createFile(atPath: encrypted.path, contents: nil))
        let writeEnc = try FileHandle(forWritingTo: encrypted)
        let plainSource = CountingSource(PatternSource(count: size))
        try PasswordMode.encrypt(
            password: PasswordFixtures.password, filename: "large.bin",
            from: plainSource, to: FileHandleSink(writeEnc), cost: PasswordFixtures.fast)
        try writeEnc.close()
        XCTAssertEqual(plainSource.bytesRead, size)
        XCTAssertLessThanOrEqual(plainSource.largestRequest, FormatV1.chunkSize)

        let readEnc = try FileHandle(forReadingFrom: encrypted)
        let encSource = CountingSource(FileHandleSource(readEnc))
        let output = DigestSink()
        let filename = try PasswordMode.open(
            password: PasswordFixtures.password, from: encSource, to: output)
        try readEnc.close()
        XCTAssertEqual(filename, "large.bin")
        XCTAssertLessThanOrEqual(encSource.largestRequest, FormatV1.sealedChunkSize + 1)
        XCTAssertEqual(output.count, size)
        XCTAssertEqual(output.finalize(), try PatternSource.digest(count: size))
    }

    /// The production default: ops 4, 1 GiB. Takes a few seconds.
    func testDefaultCostIsSensitiveAndRoundTrips() throws {
        let sink = MemorySink()
        try PasswordMode.encrypt(
            password: PasswordFixtures.password, filename: "a.txt",
            from: MemorySource([7, 8, 9]), to: sink)
        let parameters = try decodedParameters(sink.bytes)
        XCTAssertEqual(parameters.opsLimit, 4)
        XCTAssertEqual(parameters.memLimit, 1 << 30)
        let opened = try passwordOpen(sink.bytes)
        XCTAssertEqual(opened.plaintext, [7, 8, 9])
        XCTAssertEqual(opened.filename, "a.txt")
    }

    // MARK: Header

    func testHeaderRecordsCostAndFreshSaltsEveryTime() throws {
        let a = try passwordSeal([1, 2, 3])
        let b = try passwordSeal([1, 2, 3])
        let pa = try decodedParameters(a)
        let pb = try decodedParameters(b)
        XCTAssertEqual(pa.opsLimit, 3)
        XCTAssertEqual(pa.memLimit, 256 << 20)
        XCTAssertNotEqual(pa.argon2Salt, pb.argon2Salt, "Argon2id salt must be fresh")
        // HKDF salt, base nonce and commitment (bytes 17..<93) are fresh too.
        XCTAssertNotEqual(Array(a[17 ..< 93]), Array(b[17 ..< 93]))
    }

    // MARK: Refused at encrypt time

    func testWeakPasswordIsRefusedAndNothingIsWritten() {
        for weak in ["", "short", "Password12345678", "aaaaaaaaaaaaaaaaaaaa", "qwertyuiopasdfgh"] {
            let sink = MemorySink()
            assertCoreFailure(.weakPassword, weak) {
                try PasswordMode.encrypt(
                    password: weak, filename: nil, from: MemorySource([1]), to: sink,
                    cost: PasswordFixtures.fast)
            }
            XCTAssertEqual(sink.bytes, [], weak)
        }
    }

    func testInvalidFilenameIsRefusedAndNothingIsWritten() {
        let sink = MemorySink()
        assertCoreFailure(.invalidFilename) {
            try PasswordMode.encrypt(
                password: PasswordFixtures.password, filename: "../x", from: MemorySource([1]),
                to: sink, cost: PasswordFixtures.fast)
        }
        XCTAssertEqual(sink.bytes, [])
    }

    // MARK: Wrong password

    func testWrongPasswordsFailAtTheCommitmentAndReleaseNothing() throws {
        let sealed = try passwordSeal(Fixtures.pattern(3 * c))
        let wrong = [
            "correct horse battery stapler",
            "Correct horse battery staple",  // case matters
            "correct horse battery staple ",  // nothing is trimmed
            "",
        ]
        for password in wrong {
            let sink = MemorySink()
            assertCoreFailure(.commitmentMismatch, password.debugDescription) {
                _ = try PasswordMode.open(password: password, from: MemorySource(sealed), to: sink)
            }
            XCTAssertEqual(sink.bytes, [], "no plaintext may be released")
        }
    }

    func testPublicDecryptThrowsOnlyTheGenericError() throws {
        let sealed = try passwordSeal([1, 2, 3])
        let inputs: [(String, [UInt8])] = [
            ("wrong password", sealed),
            ("garbage", Fixtures.pattern(500)),
            ("empty", []),
            ("header only", Array(sealed.prefix(FormatV1.passwordHeaderLength))),
        ]
        for (label, bytes) in inputs {
            let password = label == "wrong password" ? "not the right password" : PasswordFixtures.password
            XCTAssertThrowsError(
                try PasswordMode.decrypt(password: password, from: MemorySource(bytes), to: MemorySink()),
                label
            ) { error in
                XCTAssertEqual(error as? DecryptionFailed, DecryptionFailed(), label)
                XCTAssertEqual(error.localizedDescription, DecryptionFailed.message, label)
            }
        }
        XCTAssertEqual(
            try PasswordMode.decrypt(password: PasswordFixtures.password, from: MemorySource(sealed), to: MemorySink()),
            "file.bin")
    }

    // MARK: Hostile headers

    func testRecipientModeFileIsRejectedWithoutRunningArgon2id() throws {
        let file = try sealBytes(
            [1, 2, 3], ikm: Fixtures.randomKey(),
            parameters: Fixtures.recipientParameters(count: 1),
            trailer: [UInt8](repeating: 0, count: FormatV1.mldsa65SignatureSize))
        var derivations = 0
        assertCoreFailure(.wrongMode) {
            _ = try passwordOpen(file, onDeriveKey: { derivations += 1 })
        }
        XCTAssertEqual(derivations, 0)
    }

    /// A crafted file can't make us run Argon2id with more than 1 GiB or ops 8, or
    /// with a trivially cheap cost: the parser rejects it first.
    func testOutOfRangeCostIsRejectedBeforeArgon2id() throws {
        let sealed = try passwordSeal([1, 2, 3])
        let edits: [(String, (inout [UInt8]) -> Void)] = [
            ("ops 2", { $0.put(UInt64(2), at: HeaderOffsets.opsLimit) }),
            ("ops 9", { $0.put(UInt64(9), at: HeaderOffsets.opsLimit) }),
            ("ops max", { $0.put(UInt64.max, at: HeaderOffsets.opsLimit) }),
            ("mem 255 MiB", { $0.put(UInt64(255 << 20), at: HeaderOffsets.memLimit) }),
            ("mem 1 GiB + 1", { $0.put(UInt64((1 << 30) + 1), at: HeaderOffsets.memLimit) }),
            ("mem 64 GiB", { $0.put(UInt64(64) << 30, at: HeaderOffsets.memLimit) }),
        ]
        for (label, edit) in edits {
            var file = sealed
            edit(&file)
            var derivations = 0
            assertCoreFailure(.argon2ParametersOutOfRange, label) {
                _ = try passwordOpen(file, onDeriveKey: { derivations += 1 })
            }
            XCTAssertEqual(derivations, 0, label)
        }
    }

    /// In-range edits to the Argon2id parameters derive a different IKM, which the
    /// commitment check catches before any chunk is opened.
    func testTamperedSaltOrCostFailsTheCommitment() throws {
        let sealed = try passwordSeal([1, 2, 3])
        let edits: [(String, (inout [UInt8]) -> Void)] = [
            ("salt", { $0[HeaderOffsets.modeParameters] ^= 0x01 }),
            ("ops 3 → 4", { $0.put(UInt64(4), at: HeaderOffsets.opsLimit) }),
            ("mem + 1 MiB", { $0.put(UInt64(257 << 20), at: HeaderOffsets.memLimit) }),
        ]
        for (label, edit) in edits {
            var file = sealed
            edit(&file)
            assertCoreFailure(.commitmentMismatch, label) { _ = try passwordOpen(file) }
        }
    }

    // MARK: Golden files (independent implementation)

    /// Built by `Vectors/make_password_vectors.py` with the reference Argon2 and
    /// pyca/cryptography, straight from FORMAT.md. Opening them checks the whole
    /// format, not just that our encoder and decoder agree with each other.
    func testOpensSmallGoldenFile() throws {
        let file = try vector("password-small.enc")
        XCTAssertEqual(file.count, 190)
        let parameters = try decodedParameters(file)
        XCTAssertEqual(parameters.argon2Salt, hex("000102030405060708090a0b0c0d0e0f"))
        XCTAssertEqual(parameters.opsLimit, 3)
        XCTAssertEqual(parameters.memLimit, 256 << 20)
        let opened = try passwordOpen(file)
        XCTAssertEqual(opened.plaintext, Array("Chotam golden vector: password mode.\n".utf8))
        XCTAssertEqual(opened.filename, "vector.txt")
    }

    /// One full chunk, then a 100-byte final chunk: covers the nonce counter and
    /// the final-chunk flag across a boundary.
    func testOpensTwoChunkGoldenFile() throws {
        let file = try vector("password-two-chunks.enc")
        XCTAssertEqual(file.count, FormatV1.passwordHeaderLength + Fixtures.sealedChunk + 100 + 16)
        let opened = try passwordOpen(file)
        XCTAssertEqual(opened.plaintext, (0 ..< 65_634).map { UInt8($0 % 251) })
        XCTAssertNil(opened.filename)
    }

    func testGoldenFileRejectsWrongPassword() throws {
        let file = try vector("password-small.enc")
        assertCoreFailure(.commitmentMismatch) {
            _ = try passwordOpen(file, password: "correct horse battery staples")
        }
    }
}
