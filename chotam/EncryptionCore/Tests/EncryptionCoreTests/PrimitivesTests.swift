import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

func hex(_ string: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var iterator = string.makeIterator()
    while let high = iterator.next(), let low = iterator.next() {
        bytes.append(UInt8(String([high, low]), radix: 16)!)
    }
    return bytes
}

func bytes(of key: SymmetricKey) -> [UInt8] {
    key.withUnsafeBytes { Array($0) }
}

final class PrimitivesTests: XCTestCase {
    // MARK: Nonce and AAD

    func testNonceIsBaseXorBigEndianCounterInLastEightBytes() throws {
        let base = hex("000102030405060708090a0b")
        let nonce = try ChunkCrypto.nonce(base: base, index: 0x0102_0304_0506_0708)
        let bytes = nonce.withUnsafeBytes { Array($0) }
        XCTAssertEqual(bytes, hex("0001020305070503" + "0d0f0d03"))
    }

    func testNonceForIndexZeroIsBaseNonce() throws {
        let base = Fixtures.pattern(12)
        let nonce = try ChunkCrypto.nonce(base: base, index: 0)
        XCTAssertEqual(nonce.withUnsafeBytes { Array($0) }, base)
    }

    func testNoncesAreDistinctAcrossIndices() throws {
        let base = Fixtures.pattern(12)
        var seen = Set<[UInt8]>()
        for index: UInt64 in [0, 1, 2, 255, 256, 65_535, 1 << 32 - 1, UInt64.max] {
            let bytes = try ChunkCrypto.nonce(base: base, index: index).withUnsafeBytes { Array($0) }
            XCTAssertTrue(seen.insert(bytes).inserted)
        }
    }

    func testNonceRejectsWrongBaseLength() {
        assertCoreFailure(.fieldSizeMismatch) { _ = try ChunkCrypto.nonce(base: [0, 1, 2], index: 0) }
    }

    func testAssociatedDataLayout() {
        let hash = [UInt8](repeating: 0xAB, count: 32)
        let aad = ChunkCrypto.associatedData(headerHash: hash, index: 0x0102, isFinal: true)
        XCTAssertEqual(aad, hash + hex("0000000000000102") + [0x01])
        let notFinal = ChunkCrypto.associatedData(headerHash: hash, index: 0, isFinal: false)
        XCTAssertEqual(notFinal, hash + [UInt8](repeating: 0, count: 8) + [0x00])
    }

    // MARK: Constant-time comparison

    func testConstantTimeEquals() {
        let a = Fixtures.pattern(32)
        XCTAssertTrue(ConstantTime.equals(a, a))
        XCTAssertTrue(ConstantTime.equals([], []))
        for i in 0 ..< a.count {
            var b = a
            b[i] ^= 0x01
            XCTAssertFalse(ConstantTime.equals(a, b), "difference at byte \(i) not detected")
        }
        XCTAssertFalse(ConstantTime.equals(a, Array(a.dropLast())))
    }

    // MARK: HKDF and key schedule

    /// RFC 5869 test case 1: confirms the HKDF API is used with salt and info in
    /// the right places on this platform's crypto library.
    func testHKDFMatchesRFC5869TestCase1() {
        let okm = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")),
            salt: hex("000102030405060708090a0b0c"),
            info: hex("f0f1f2f3f4f5f6f7f8f9"),
            outputByteCount: 42)
        XCTAssertEqual(
            okm.withUnsafeBytes { Array($0) },
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
    }

    func testKeyScheduleIsDeterministicAndSeparatesLabels() throws {
        let ikm = Fixtures.randomKey()
        let salt = Fixtures.pattern(32)
        let a = try KeySchedule.derive(ikm: ikm, hkdfSalt: salt)
        let b = try KeySchedule.derive(ikm: ikm, hkdfSalt: salt)
        XCTAssertEqual(a.commitment, b.commitment)
        XCTAssertEqual(bytes(of: a.fileKey), bytes(of: b.fileKey))
        XCTAssertEqual(a.commitment.count, 32)
        // The public commitment must not equal the secret file key.
        XCTAssertNotEqual(bytes(of: a.fileKey), a.commitment)
    }

    func testFreshSaltGivesFreshKeysForSameIKM() throws {
        let ikm = Fixtures.randomKey()
        let a = try KeySchedule.derive(ikm: ikm, hkdfSalt: Fixtures.pattern(32, seed: 1))
        let b = try KeySchedule.derive(ikm: ikm, hkdfSalt: Fixtures.pattern(32, seed: 2))
        XCTAssertNotEqual(bytes(of: a.fileKey), bytes(of: b.fileKey))
        XCTAssertNotEqual(a.commitment, b.commitment)
    }

    func testKeyScheduleRejectsShortIKMAndBadSalt() {
        assertCoreFailure(.invalidKeyLength) {
            _ = try KeySchedule.derive(ikm: SymmetricKey(size: .bits128), hkdfSalt: Fixtures.pattern(32))
        }
        assertCoreFailure(.fieldSizeMismatch) {
            _ = try KeySchedule.derive(ikm: Fixtures.randomKey(), hkdfSalt: Fixtures.pattern(16))
        }
    }

    // MARK: Randomness, wiping, readers

    func testSecureRandomProducesDistinctValues() {
        let a = SecureRandom.bytes(32)
        let b = SecureRandom.bytes(32)
        XCTAssertEqual(a.count, 32)
        XCTAssertEqual(SecureRandom.bytes(12).count, 12)
        XCTAssertNotEqual(a, b)
    }

    func testWipeZeroesBuffers() {
        var bytes = Fixtures.pattern(100)
        Wipe.bytes(&bytes)
        XCTAssertEqual(bytes, [UInt8](repeating: 0, count: 100))
        var data = Data(Fixtures.pattern(100))
        Wipe.data(&data)
        XCTAssertEqual(data, Data(count: 100))
        var empty: [UInt8] = []
        Wipe.bytes(&empty)  // must not crash
    }

    func testByteReaderNeverReadsPastEnd() throws {
        var r = ByteReader([1, 2, 3])
        let first = try r.readUInt16()
        XCTAssertEqual(first, 0x0102)
        assertCoreFailure(.truncatedHeader) { _ = try r.readUInt16() }
        assertCoreFailure(.truncatedHeader) { _ = try r.readBytes(-1) }
        let last = try r.readUInt8()
        XCTAssertEqual(last, 3)
        XCTAssertTrue(r.isAtEnd)
        assertCoreFailure(.truncatedHeader) { _ = try r.readUInt8() }
    }

    func testPublicErrorIsGenericForEveryReason() {
        let reasons: [CoreFailure.Reason] = [
            .badMagic, .commitmentMismatch, .chunkAuthenticationFailed, .truncatedBody,
            .wrongMode, .keyDerivationFailed, .argon2ParametersOutOfRange,
        ]
        for reason in reasons {
            XCTAssertEqual(publicDecryptionError(CoreFailure(reason)), DecryptionFailed())
        }
        XCTAssertEqual(publicDecryptionError(CocoaError(.fileReadNoPermission)).errorDescription, DecryptionFailed.message)
        XCTAssertEqual(DecryptionFailed().errorDescription, "Decryption failed: file is damaged or not for you.")
    }
}
