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
            identity.fingerprint.groups, ["80XX", "XYHV", "TNDW", "KMXW", "QJ1J", "KY3M", "0SVB", "QTVM"])
    }

    /// Exactly the bytes FORMAT.md §9.3 defines: the first 20 bytes of
    /// SHA-256(label ‖ X-Wing key ‖ ML-DSA-65 key ‖ Ed25519 key), in Crockford base32.
    func testFingerprintBytes() throws {
        let identity = try PQIDCodec.decode(try IdentityVectors.pqid())
        let digest = hex(sha256Hex(
            Array("Chotam v1 identity fingerprint".utf8) + identity.encryptionKeyBytes
                + identity.mldsaKeyBytes + identity.ed25519KeyBytes))
        XCTAssertEqual(identity.fingerprint.symbols, Crockford.encode(Array(digest.prefix(20))))
        XCTAssertEqual(hexString(Array(digest.prefix(20))), IdentityVectors.fingerprintDigest)
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

    /// Neither the name, the KDF parameters nor the (randomised) signature is part of it.
    func testStableAcrossNameKDFAndSignature() throws {
        var raw = try RawPQID.golden()
        raw.nameBytes = Array("Someone else entirely".utf8)
        let renamed = try PQIDCodec.decode(try raw.signedByGolden())
        raw.nameBytes = []
        raw.salt = Array(repeating: 0x55, count: 16)
        raw.opsLimit = 9
        let unnamed = try PQIDCodec.decode(try raw.signedByGolden())
        XCTAssertEqual(renamed.fingerprint.description, IdentityVectors.fingerprint)
        XCTAssertEqual(unnamed.fingerprint.description, IdentityVectors.fingerprint)
    }

    /// Each of the three keys changes it, so none can be swapped unnoticed.
    func testChangesWhenAnyKeyChanges() throws {
        let golden = try PQIDCodec.decode(try IdentityVectors.pqid())
        let other = try SomeoneElse()
        var fingerprints = [golden.fingerprint, other.publicIdentity.fingerprint]
        // Golden keys with one of someone else's swapped in, signed by whoever holds
        // the signing keys of the result.
        var a = try RawPQID.golden()
        a.encryptionKey = other.publicIdentity.encryptionKeyBytes
        fingerprints.append(try PQIDCodec.decode(try a.signedByGolden()).fingerprint)
        var b = try RawPQID.golden()
        b.mldsaKey = other.publicIdentity.mldsaKeyBytes
        fingerprints.append(try PQIDCodec.decode(try b.signed(by: try IdentityVectors.ed25519Key(), other.mldsa)).fingerprint)
        var c = try RawPQID.golden()
        c.ed25519Key = other.publicIdentity.ed25519KeyBytes
        fingerprints.append(try PQIDCodec.decode(try c.signed(by: other.ed25519, try IdentityVectors.mldsaKey())).fingerprint)
        XCTAssertEqual(Set(fingerprints).count, 5)
    }

    // MARK: Comparing

    func testMatchesTypedFingerprint() throws {
        let fingerprint = try PQIDCodec.decode(try IdentityVectors.pqid()).fingerprint
        XCTAssertTrue(fingerprint.matches(IdentityVectors.fingerprint))
        XCTAssertTrue(fingerprint.matches("80xxxyhvtndwkmxwqj1jky3m0svbqtvm"))
        XCTAssertTrue(fingerprint.matches("8OXX-XYHV-TNDW-KMXW-QJlJ-KY3M-0SVB-QTVM"))  // O for 0, l for 1
        XCTAssertFalse(fingerprint.matches("80XX XYHV TNDW KMXW QJ1J KY3M 0SVB QTVN"))  // last symbol differs
        XCTAssertFalse(fingerprint.matches("80XX XYHV TNDW KMXW QJ1J KY3M 0SVB QTV"))  // 31 symbols
        XCTAssertFalse(fingerprint.matches("80XX XYHV TNDW KMXW QJ1J KY3M 0SVB QTVM 0"))  // 33 symbols
        XCTAssertFalse(fingerprint.matches("80XX XYHV"))  // a prefix is not a match
        XCTAssertFalse(fingerprint.matches(""))
    }
}
