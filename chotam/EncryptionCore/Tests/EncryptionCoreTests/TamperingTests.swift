import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Every modification of a sealed file must fail with a `CoreFailure`, which the
/// public API maps to the one generic message.
final class TamperingTests: XCTestCase {
    private let s = Fixtures.sealedChunk
    private let h = FormatV1.passwordHeaderLength

    /// A file whose stream is 3 chunks: full, full, and a 110-byte final chunk.
    private func threeChunkFile() throws -> (file: [UInt8], ikm: SymmetricKey) {
        let ikm = Fixtures.randomKey()
        let file = try sealBytes(Fixtures.pattern(2 * Fixtures.chunk + 100), ikm: ikm)
        XCTAssertEqual(file.count, h + 2 * s + 110 + 16)
        return (file, ikm)
    }

    private func chunk(_ file: [UInt8], _ i: Int) -> [UInt8] {
        let start = h + i * s
        return Array(file[start ..< min(start + s, file.count)])
    }

    func testUntamperedFileOpens() throws {
        let (file, ikm) = try threeChunkFile()
        XCTAssertNoThrow(try openBytes(file, ikm: ikm))
    }

    // MARK: Header

    func testBitFlipInEveryHeaderByteIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        for offset in 0 ..< h {
            var tampered = file
            tampered[offset] ^= 1 << UInt8(offset % 8)
            assertCoreFailure(nil, "header byte \(offset)") { _ = try openBytes(tampered, ikm: ikm) }
        }
    }

    func testBitFlipInEveryRecipientHeaderFieldIsDetected() throws {
        let ikm = Fixtures.randomKey()
        let parameters = Fixtures.recipientParameters(count: 2)
        let trailer = [UInt8](repeating: 0x5A, count: FormatV1.mldsa65SignatureSize)
        let file = try sealBytes(Fixtures.pattern(5000), ikm: ikm, parameters: parameters, trailer: trailer)
        let headerLength = FormatV1.recipientHeaderLength(count: 2)
        // One flip in each field region, incl. both stanzas and their length fields.
        let offsets = [0, 6, 8, 9, 13, 17, 49, 61, 93, 125, 126, 158, 160, 1280, 1282, 1329, 1330, 1362, 2533]
        for offset in offsets where offset < headerLength {
            var tampered = file
            tampered[offset] ^= 0x01
            assertCoreFailure(nil, "recipient header byte \(offset)") {
                _ = try openBytes(tampered, ikm: ikm, trailerLength: trailer.count)
            }
        }
    }

    // MARK: Body

    func testBitFlipInCiphertextIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        for offset in [h, h + 1000, h + s + 5, h + 2 * s + 3] {
            var tampered = file
            tampered[offset] ^= 0x80
            assertCoreFailure(.chunkAuthenticationFailed, "offset \(offset)") { _ = try openBytes(tampered, ikm: ikm) }
        }
    }

    func testBitFlipInTagIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        for offset in [h + s - 1, h + 2 * s - 16, file.count - 1] {
            var tampered = file
            tampered[offset] ^= 0x01
            assertCoreFailure(.chunkAuthenticationFailed, "offset \(offset)") { _ = try openBytes(tampered, ikm: ikm) }
        }
    }

    func testReorderedChunksAreDetected() throws {
        let (file, ikm) = try threeChunkFile()
        let header = Array(file.prefix(h))
        let swapped = header + chunk(file, 1) + chunk(file, 0) + chunk(file, 2)
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(swapped, ikm: ikm) }
    }

    func testDuplicatedChunkIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        let header = Array(file.prefix(h))
        let duplicated = header + chunk(file, 0) + chunk(file, 0) + chunk(file, 1) + chunk(file, 2)
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(duplicated, ikm: ikm) }
    }

    func testChunkSplicedFromAnotherFileIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        let other = try sealBytes(Fixtures.pattern(2 * Fixtures.chunk + 100), ikm: ikm)
        let spliced = Array(file.prefix(h)) + chunk(file, 0) + chunk(other, 1) + chunk(file, 2)
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(spliced, ikm: ikm) }
    }

    // MARK: Truncation

    func testTruncationInsideFinalChunkIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(Array(file.dropLast(1)), ikm: ikm) }
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(Array(file.dropLast(10)), ikm: ikm) }
        // Leaves only 6 bytes of the final chunk: shorter than a tag.
        assertCoreFailure(.truncatedBody) { _ = try openBytes(Array(file.dropLast(120)), ikm: ikm) }
    }

    /// Dropping the whole final chunk leaves a full chunk that was sealed as
    /// non-final at the end of the file. The final flag in the AAD catches it.
    func testDroppingFinalChunkIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        let truncated = Array(file.prefix(h + 2 * s))
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(truncated, ikm: ikm) }
        let oneChunk = Array(file.prefix(h + s))
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(oneChunk, ikm: ikm) }
    }

    func testTruncationInsideNonFinalChunkIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(Array(file.prefix(h + s + 500)), ikm: ikm) }
    }

    func testHeaderOnlyFileIsRejected() throws {
        let (file, ikm) = try threeChunkFile()
        assertCoreFailure(.truncatedBody) { _ = try openBytes(Array(file.prefix(h)), ikm: ikm) }
        assertCoreFailure(.truncatedBody) { _ = try openBytes(Array(file.prefix(h + 15)), ikm: ikm) }
    }

    // MARK: Appended data

    func testAppendedBytesAreDetected() throws {
        let (file, ikm) = try threeChunkFile()
        for junk in [[0x00], Fixtures.pattern(100), Fixtures.pattern(100_000)] as [[UInt8]] {
            assertCoreFailure(.chunkAuthenticationFailed, "junk \(junk.count)") {
                _ = try openBytes(file + junk, ikm: ikm)
            }
        }
    }

    func testAppendedCopyOfFinalChunkIsDetected() throws {
        let (file, ikm) = try threeChunkFile()
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(file + chunk(file, 2), ikm: ikm) }
    }

    /// When the stream ends exactly on a boundary, the final chunk is full-size.
    /// Appending another genuine full chunk must still fail.
    func testAppendedFullChunkAfterBoundaryFileIsDetected() throws {
        let ikm = Fixtures.randomKey()
        let file = try sealBytes(Fixtures.pattern(2 * Fixtures.chunk - 10), ikm: ikm)
        XCTAssertEqual(file.count, h + 2 * s)
        XCTAssertNoThrow(try openBytes(file, ikm: ikm))
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(file + chunk(file, 0), ikm: ikm) }
        assertCoreFailure(.chunkAuthenticationFailed) { _ = try openBytes(file + chunk(file, 1), ikm: ikm) }
    }

    // MARK: Trailer framing (recipient mode; signature checks arrive in Phase 5)

    func testTrailerLengthChangesAreDetected() throws {
        let ikm = Fixtures.randomKey()
        let trailer = [UInt8](repeating: 0x5A, count: FormatV1.mldsa65SignatureSize)
        let file = try sealBytes(
            Fixtures.pattern(3000), ikm: ikm,
            parameters: Fixtures.recipientParameters(count: 1), trailer: trailer)
        let t = trailer.count
        XCTAssertNoThrow(try openBytes(file, ikm: ikm, trailerLength: t))
        // Stripped signature: the reader holds back T bytes of real ciphertext.
        assertCoreFailure { _ = try openBytes(Array(file.dropLast(t)), ikm: ikm, trailerLength: t) }
        // One byte missing from or added to the trailer shifts the final chunk.
        assertCoreFailure { _ = try openBytes(Array(file.dropLast(1)), ikm: ikm, trailerLength: t) }
        assertCoreFailure { _ = try openBytes(file + [0], ikm: ikm, trailerLength: t) }
    }
}
