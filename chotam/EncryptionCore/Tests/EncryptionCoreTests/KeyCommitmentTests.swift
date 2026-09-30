import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// The key-commitment tag must be checked in constant time before any chunk
/// is opened (FORMAT.md §4.2). `onChunkOpen` counts AES-GCM open attempts, so
/// these tests prove that "before" literally holds.
final class KeyCommitmentTests: XCTestCase {
    /// A file whose plaintext stream is exactly 3 chunks ("file.bin" record = 10 bytes).
    private func sealed() throws -> (file: [UInt8], ikm: SymmetricKey) {
        let ikm = Fixtures.randomKey()
        return (try sealBytes(Fixtures.pattern(3 * Fixtures.chunk - 10), ikm: ikm), ikm)
    }

    /// Replaces the header of `file` with a re-encoded, modified one. The raw
    /// header changes, so its hash is recomputed exactly as a real attacker's would be.
    private func replacingHeader(of file: [UInt8], _ modify: (inout FileHeader) throws -> Void) throws -> [UInt8] {
        let h = FormatV1.passwordHeaderLength
        var header = try HeaderCodec.decode(Array(file.prefix(h)))
        try modify(&header)
        return try HeaderCodec.encode(header) + file[h...]
    }

    func testWrongKeyFailsBeforeAnyChunkIsOpened() throws {
        let (file, _) = try sealed()
        var opens = 0
        assertCoreFailure(.commitmentMismatch) {
            _ = try openBytes(file, ikm: Fixtures.randomKey(), onChunkOpen: { opens += 1 })
        }
        XCTAssertEqual(opens, 0)
    }

    func testCraftedHeaderWithMismatchedCommitmentIsRejectedBeforeDecryption() throws {
        let (file, ikm) = try sealed()
        for byte in 0 ..< FormatV1.commitmentSize {
            let crafted = try replacingHeader(of: file) { $0.commitment[byte] ^= 0x01 }
            var opens = 0
            assertCoreFailure(.commitmentMismatch, "commitment byte \(byte)") {
                _ = try openBytes(crafted, ikm: ikm, onChunkOpen: { opens += 1 })
            }
            XCTAssertEqual(opens, 0, "a chunk was opened despite a bad commitment")
        }
    }

    func testChangedHKDFSaltBreaksCommitment() throws {
        let (file, ikm) = try sealed()
        let crafted = try replacingHeader(of: file) { $0.hkdfSalt[0] ^= 0x01 }
        var opens = 0
        assertCoreFailure(.commitmentMismatch) {
            _ = try openBytes(crafted, ikm: ikm, onChunkOpen: { opens += 1 })
        }
        XCTAssertEqual(opens, 0)
    }

    /// An attacker who controls the header can make the commitment match a key
    /// of their choosing, but the body then doesn't authenticate under it. One
    /// ciphertext can't be made to open under two different keys.
    func testCommitmentForAnotherKeyStillCannotOpenBody() throws {
        let (file, _) = try sealed()
        let attackerKey = Fixtures.randomKey()
        let crafted = try replacingHeader(of: file) { header in
            header.commitment = try KeySchedule.derive(ikm: attackerKey, hkdfSalt: header.hkdfSalt).commitment
        }
        var opens = 0
        assertCoreFailure(.chunkAuthenticationFailed) {
            _ = try openBytes(crafted, ikm: attackerKey, onChunkOpen: { opens += 1 })
        }
        XCTAssertEqual(opens, 1)
    }

    /// Positive control: the hook does count opens when the commitment is fine.
    func testHookCountsOpensWhenCommitmentMatches() throws {
        let (file, ikm) = try sealed()
        var opens = 0
        _ = try openBytes(file, ikm: ikm, onChunkOpen: { opens += 1 })
        XCTAssertEqual(opens, 3)

        var tampered = file
        tampered[tampered.count - 1] ^= 0x01
        opens = 0
        assertCoreFailure(.chunkAuthenticationFailed) {
            _ = try openBytes(tampered, ikm: ikm, onChunkOpen: { opens += 1 })
        }
        XCTAssertEqual(opens, 3)
    }

    func testStoredCommitmentMatchesKeySchedule() throws {
        let (file, ikm) = try sealed()
        let header = try HeaderCodec.decode(Array(file.prefix(FormatV1.passwordHeaderLength)))
        let keys = try KeySchedule.derive(ikm: ikm, hkdfSalt: header.hkdfSalt)
        XCTAssertEqual(header.commitment, keys.commitment)
    }
}
