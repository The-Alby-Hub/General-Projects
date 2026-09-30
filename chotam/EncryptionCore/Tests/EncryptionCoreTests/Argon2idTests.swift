import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Argon2id through libsodium (FORMAT.md §4.1).
///
/// The expected values were computed with two independent implementations that
/// agree: the reference Argon2 C code (argon2-cffi 23.1.0) and libsodium 1.0.18,
/// both at Argon2id v1.3, parallelism 1, 32-byte output.
final class Argon2idTests: XCTestCase {
    private static let mib: UInt64 = 1 << 20
    private let salt0 = hex("000102030405060708090a0b0c0d0e0f")

    // MARK: Parameters

    func testLibsodiumSensitivePresetMatchesWhatWeWrite() {
        XCTAssertEqual(Argon2id.librarySensitiveCost, .sensitive)
        XCTAssertEqual(Argon2id.Cost.sensitive.opsLimit, 4)
        XCTAssertEqual(Argon2id.Cost.sensitive.memLimit, 1 << 30)
        XCTAssertEqual(Argon2id.librarySaltSize, FormatV1.argon2SaltSize)
        XCTAssertTrue(Argon2id.Cost.sensitive.isAccepted)
        XCTAssertTrue(Argon2id.Cost.minimumAccepted.isAccepted)
        XCTAssertEqual(Argon2id.Cost.minimumAccepted, .init(opsLimit: 3, memLimit: 256 * Self.mib))
    }

    func testRejectsBadSaltAndOutOfRangeCostBeforeRunning() {
        assertCoreFailure(.fieldSizeMismatch) {
            _ = try Argon2id.deriveIKM(password: "x", salt: [UInt8](repeating: 0, count: 15), cost: .minimumAccepted)
        }
        let outOfRange: [Argon2id.Cost] = [
            .init(opsLimit: 2, memLimit: 256 * Self.mib),
            .init(opsLimit: 9, memLimit: 256 * Self.mib),
            .init(opsLimit: 3, memLimit: 256 * Self.mib - 1),
            .init(opsLimit: 3, memLimit: (1 << 30) + 1),
            .init(opsLimit: 0, memLimit: 0),
            .init(opsLimit: .max, memLimit: .max),
        ]
        for cost in outOfRange {
            XCTAssertFalse(cost.isAccepted)
            assertCoreFailure(.argon2ParametersOutOfRange, "\(cost)") {
                _ = try Argon2id.deriveIKM(password: "x", salt: salt0, cost: cost)
            }
        }
    }

    // MARK: Known answers

    private func assertDerives(
        _ password: String, salt: [UInt8], ops: UInt64, mem: UInt64, _ expected: String,
        file: StaticString = #filePath, line: UInt = #line
    ) throws {
        let key = try Argon2id.deriveIKM(
            password: password, salt: salt, cost: .init(opsLimit: ops, memLimit: mem))
        XCTAssertEqual(bytes(of: key), hex(expected), file: file, line: line)
    }

    func testKnownAnswersAtMinimumCost() throws {
        try assertDerives(
            "correct horse battery staple", salt: salt0, ops: 3, mem: 256 * Self.mib,
            "aad608b5866cef907f47d5cae529ed01a91301c92c5d5fef46e1a65e394e5742")
        // The same password and salt give unrelated keys at another cost.
        try assertDerives(
            "correct horse battery staple", salt: salt0, ops: 4, mem: 256 * Self.mib,
            "58adf8f2eb38053b06b6d9365fd8f5de698bcfc69f2c02c0ba8d8c4634816db0")
        try assertDerives(
            "correct horse battery staple", salt: salt0, ops: 3, mem: 257 * Self.mib,
            "172749713c0e910966a22785495364556532c335d3479944ada6a7b8f34f7426")
        // An empty password is derivable (decryption must fail cleanly, never crash).
        try assertDerives(
            "", salt: salt0, ops: 3, mem: 256 * Self.mib,
            "9edfc582fc2c7141163ddcbcc725e1e785953d86f7865abbb125cb8674045cc7")
    }

    /// Regression test: swift-sodium's `PWHash.hash` traps on any byte ≥ 0x80.
    /// Calling libsodium directly must handle every non-ASCII password.
    func testKnownAnswersForNonASCIIPasswords() throws {
        // Hebrew: "חותם סודי מאוד"
        try assertDerives(
            "\u{05D7}\u{05D5}\u{05EA}\u{05DD} \u{05E1}\u{05D5}\u{05D3}\u{05D9} \u{05DE}\u{05D0}\u{05D5}\u{05D3}",
            salt: hex("101112131415161718191a1b1c1d1e1f"), ops: 3, mem: 256 * Self.mib,
            "39914cb72c63fdb27e9a7d41717261cc4b60c5a8cc9d72d7b18ca268575e0168")
        // "résumé 📄 年度" with precomposed é (NFC)
        try assertDerives(
            "r\u{E9}sum\u{E9} \u{1F4C4} \u{5E74}\u{5EA6}",
            salt: [UInt8](repeating: 0xA5, count: 16), ops: 3, mem: 256 * Self.mib,
            "06a1149571d0a304ee66e0a7ba7f3673470a71e662f79f9af7ad55ad6140ea63")
    }

    /// The same text typed with a combining accent (NFD) derives the NFC key.
    func testDecomposedPasswordIsNormalisedToNFC() throws {
        let decomposed = "re\u{301}sume\u{301} \u{1F4C4} \u{5E74}\u{5EA6}"
        XCTAssertNotEqual(Array(decomposed.utf8), Array("r\u{E9}sum\u{E9} \u{1F4C4} \u{5E74}\u{5EA6}".utf8))
        try assertDerives(
            decomposed,
            salt: [UInt8](repeating: 0xA5, count: 16), ops: 3, mem: 256 * Self.mib,
            "06a1149571d0a304ee66e0a7ba7f3673470a71e662f79f9af7ad55ad6140ea63")
    }

    /// The real preset: 1 GiB, a few seconds.
    func testKnownAnswerAtSensitiveCost() throws {
        try assertDerives(
            "correct horse battery staple", salt: salt0, ops: 4, mem: 1 << 30,
            "744c15fa0c4849143860af4fd976da2b4ea6c1f7c8e786f2343651215925ef2c")
    }
}
