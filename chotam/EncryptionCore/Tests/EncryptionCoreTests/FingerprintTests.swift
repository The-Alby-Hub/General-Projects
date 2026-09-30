import Foundation
import XCTest
@testable import EncryptionCore

/// Fingerprints (SECURITY.md D5): exact bytes, Crockford encoding, format, stability.
final class FingerprintTests: XCTestCase {
    // MARK: Crockford base32

    /// Spot values computed by make_identity_vectors.py's own encoder.
    func testCrockfordVectors() {
        XCTAssertEqual(Crockford.encode([UInt8](repeating: 0x00, count: 20)), String(repeating: "0", count: 32))
        XCTAssertEqual(Crockford.encode([UInt8](repeating: 0xFF, count: 20)), String(repeating: "Z", count: 32))
        XCTAssertEqual(Crockford.encode((0 ..< 20).map { UInt8($0) }), "000G40R40M30E209185GR38E1W8124GK")
        // 5 bytes = 40 bits = 8 symbols, most significant bit first.
        XCTAssertEqual(Crockford.encode([0x08, 0x42, 0x10, 0x84, 0x21]), "11111111")
        XCTAssertEqual(Crockford.encode([0xF8, 0x00, 0x00, 0x00, 0x00]), "Z0000000")
    }

    func testCrockfordAlphabetLeavesOutLookalikes() {
        XCTAssertEqual(Crockford.alphabet.count, 32)
        XCTAssertEqual(Set(Crockford.alphabet).count, 32)
        for letter in "ILOU" {
            XCTAssertFalse(Crockford.alphabet.contains(letter))
        }
    }

    func testNormaliseFollowsCrockfordDecodingRules() {
        XCTAssertEqual(Crockford.normalise("p6bc-hmey 9sas"), "P6BCHMEY9SAS")
        XCTAssertEqual(Crockford.normalise("OoIiLl"), "001111")
        XCTAssertNil(Crockford.normalise("P6BU"))  // U is not a symbol
        XCTAssertNil(Crockford.normalise("P6B*"))
        XCTAssertNil(Crockford.normalise("P6BÇ"))
        XCTAssertNil(Crockford.normalise("P6B\u{0660}"))  // Arabic-Indic digit zero
    }

    // MARK: The fingerprint

    func testGoldenFingerprint() throws {
        let identity = try PQIDCodec.decode(try IdentityVectors.pqid())
        XCTAssertEqual(identity.fingerprint.description, IdentityVectors.fingerprint)
        XCTAssertEqual(
            identity.fingerprint.groups, ["P6BC", "HMEY", "9SAS", "BEA0", "DGKS", "1Y3H", "FDP9", "VXBM"])
    }

    /// Exactly the bytes FORMAT.md §9.3 defines: the first 20 bytes of
    /// SHA-256(label ‖ X-Wing key ‖ ML-DSA key), in Crockford base32.
    func testFingerprintBytes() throws {
        let identity = try PQIDCodec.decode(try IdentityVectors.pqid())
        let digest = hex(sha256Hex(
            Array("Chotam v1 identity fingerprint".utf8) + identity.encryptionKeyBytes + identity.signingKeyBytes))
        XCTAssertEqual(identity.fingerprint.symbols, Crockford.encode(Array(digest.prefix(20))))
        XCTAssertEqual(hexString(Array(digest.prefix(20))), "b196c8d1de4e5595b9406c2790f8717b6c9df574")
    }

    func testFormatIsEightGroupsOfFourCrockfordSymbols() throws {
        for _ in 0 ..< 20 {
            let text = try SomeoneElse().publicIdentity.fingerprint.description
            XCTAssertEqual(text.count, 39)  // 32 symbols + 7 spaces
            let groups = text.split(separator: " ")
            XCTAssertEqual(groups.count, 8)
            XCTAssertTrue(groups.allSatisfy { $0.count == 4 && $0.allSatisfy { symbol in Crockford.alphabet.contains(symbol) } })
        }
    }

    /// Neither the name nor the (randomised) signature is part of it.
    func testStableAcrossNameAndSignature() throws {
        let xwing = try IdentityVectors.xwingKey()
        let mldsa = try IdentityVectors.mldsaKey()
        var raw = RawPQID(
            encryptionKey: [UInt8](xwing.publicKey.rawRepresentation),
            signingKey: [UInt8](mldsa.publicKey.rawRepresentation))
        raw.nameBytes = Array("Someone else entirely".utf8)
        let renamed = try PQIDCodec.decode(try raw.signed(by: mldsa))
        raw.nameBytes = []
        let unnamed = try PQIDCodec.decode(try raw.signed(by: mldsa))
        XCTAssertEqual(renamed.fingerprint.description, IdentityVectors.fingerprint)
        XCTAssertEqual(unnamed.fingerprint.description, IdentityVectors.fingerprint)
    }

    func testChangesWhenEitherKeyChanges() throws {
        let golden = try PQIDCodec.decode(try IdentityVectors.pqid())
        let other = try SomeoneElse()
        // Golden encryption key, someone else's signing key (signed by them), and vice versa.
        let mixedA = RawPQID(encryptionKey: golden.encryptionKeyBytes, signingKey: other.publicIdentity.signingKeyBytes)
        let mixedB = RawPQID(encryptionKey: other.publicIdentity.encryptionKeyBytes, signingKey: golden.signingKeyBytes)
        let a = try PQIDCodec.decode(try mixedA.signed(by: other.mldsa))
        let b = try PQIDCodec.decode(try mixedB.signed(by: try IdentityVectors.mldsaKey()))
        let all = [golden.fingerprint, other.publicIdentity.fingerprint, a.fingerprint, b.fingerprint]
        XCTAssertEqual(Set(all).count, 4)
    }

    // MARK: Comparing

    func testMatchesTypedFingerprint() throws {
        let fingerprint = try PQIDCodec.decode(try IdentityVectors.pqid()).fingerprint
        XCTAssertTrue(fingerprint.matches(IdentityVectors.fingerprint))
        XCTAssertTrue(fingerprint.matches("p6bchmey9sasbea0dgks1y3hfdp9vxbm"))
        XCTAssertTrue(fingerprint.matches("P6BC-HMEY-9SAS-BEAO-DGKS-lY3H-FDP9-VXBM"))  // O for 0, l for 1
        XCTAssertFalse(fingerprint.matches("P6BC HMEY 9SAS BEA0 DGKS 1Y3H FDP9 VXBN"))  // last symbol differs
        XCTAssertFalse(fingerprint.matches("P6BC HMEY 9SAS BEA0 DGKS 1Y3H FDP9 VXB"))  // 31 symbols
        XCTAssertFalse(fingerprint.matches("P6BC HMEY 9SAS BEA0 DGKS 1Y3H FDP9 VXBM 0"))  // 33 symbols
        XCTAssertFalse(fingerprint.matches("P6BC HMEY"))  // a prefix is not a match
        XCTAssertFalse(fingerprint.matches(""))
    }
}
