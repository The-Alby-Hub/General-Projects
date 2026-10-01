import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// The public identity file and string (FORMAT.md §9): round trips, the golden file,
/// and strict rejection of everything malformed.
final class PQIDTests: XCTestCase {
    // MARK: Golden file

    func testGoldenFileParses() throws {
        let bytes = try IdentityVectors.pqid()
        XCTAssertEqual(bytes.count, IdentityVectors.pqidSize)
        XCTAssertEqual(sha256Hex(bytes), IdentityVectors.pqidSHA256)

        let identity = try PQIDCodec.decode(bytes)
        XCTAssertEqual(identity.suggestedName, IdentityVectors.name)
        XCTAssertEqual(identity.fingerprint.description, IdentityVectors.fingerprint)
        XCTAssertEqual(identity.encryptionKeyID.hex, IdentityVectors.encryptionKeyID)
        XCTAssertEqual(identity.signingKeyID.hex, IdentityVectors.signingKeyID)
        XCTAssertEqual(identity.encryptionKeyBytes, [UInt8](try IdentityVectors.xwingKey().publicKey.rawRepresentation))
        XCTAssertEqual(identity.mldsaKeyBytes, [UInt8](try IdentityVectors.mldsaKey().publicKey.rawRepresentation))
        XCTAssertEqual(identity.ed25519KeyBytes, [UInt8](try IdentityVectors.ed25519Key().publicKey.rawRepresentation))
        XCTAssertEqual(identity.kdf, IdentityKDF(cost: IdentityVectors.kdfCost, salt: IdentityVectors.kdfSalt, requiresKeyFile: false))
        XCTAssertEqual(identity.encoded, bytes)
    }

    func testGoldenKeyFileIdentityParses() throws {
        let bytes = try vector(IdentityVectors.keyFilePQIDFile)
        XCTAssertEqual(sha256Hex(bytes), IdentityVectors.keyFilePQIDSHA256)
        let identity = try PQIDCodec.decode(bytes)
        XCTAssertTrue(identity.kdf.requiresKeyFile)
        XCTAssertEqual(bytes[3217], 0x01)  // the key-file flag
        XCTAssertEqual(identity.fingerprint.description, IdentityVectors.keyFileFingerprint)
    }

    /// The layout, byte by byte, as FORMAT.md §9.1 gives it.
    func testGoldenFileLayout() throws {
        let bytes = try IdentityVectors.pqid()
        XCTAssertEqual(Array(bytes[0 ..< 8]), Array("CHOTAMID".utf8))
        XCTAssertEqual(Array(bytes[8 ..< 10]), [0x00, 0x01])  // version 1
        XCTAssertEqual(Array(bytes[10 ..< 12]), [0x04, 0xC0])  // 1216
        XCTAssertEqual(Array(bytes[1228 ..< 1230]), [0x07, 0xA0])  // 1952
        XCTAssertEqual(Array(bytes[3182 ..< 3184]), [0x00, 0x20])  // 32
        XCTAssertEqual(bytes[3216], 1)  // Argon2id v1.3
        XCTAssertEqual(bytes[3217], 0)  // no key file
        XCTAssertEqual(Array(bytes[3218 ..< 3226]), [0, 0, 0, 0, 0, 0, 0, 3])  // opsLimit
        XCTAssertEqual(Array(bytes[3226 ..< 3234]), [0, 0, 0, 0, 0x10, 0, 0, 0])  // 256 MiB
        XCTAssertEqual(bytes[3234], 1)  // parallelism
        XCTAssertEqual(Array(bytes[3235 ..< 3251]), IdentityVectors.kdfSalt)
        XCTAssertEqual(bytes[3251], 5)  // "Alice"
        XCTAssertEqual(Array(bytes[3252 ..< 3257]), Array("Alice".utf8))
        XCTAssertEqual(Array(bytes[3257 ..< 3259]), [0x00, 0x00])  // no extensions
        XCTAssertEqual(Array(bytes[3259 ..< 3261]), [0x0D, 0x2D])  // 3373
        XCTAssertEqual(bytes.count, 3261 + 3373)
        XCTAssertEqual(IdentityFormat.pqidFixedSize, 6629)
    }

    // MARK: Round trips

    func testFileRoundTrip() throws {
        let original = try SomeoneElse().publicIdentity
        let imported = try PublicIdentity(importing: original.exportedData)
        XCTAssertEqual(imported, original)
        XCTAssertEqual(imported.suggestedName, "Bob")
        XCTAssertEqual(imported.fingerprint, original.fingerprint)
        XCTAssertEqual(imported.exportedData, original.exportedData)
    }

    func testStringRoundTrip() throws {
        let original = try SomeoneElse(name: nil).publicIdentity
        let string = original.exportedString
        XCTAssertFalse(string.contains("\n"))
        XCTAssertEqual(string.count, (original.encoded.count + 2) / 3 * 4)
        let imported = try PublicIdentity(importingString: string)
        XCTAssertEqual(imported, original)
        XCTAssertNil(imported.suggestedName)
    }

    /// An email client may wrap the string, or someone may paste it with spaces.
    func testStringToleratesLineBreaksAndSpaces() throws {
        let string = try PQIDCodec.decode(try IdentityVectors.pqid()).exportedString
        var wrapped = ""
        for (i, character) in string.enumerated() {
            if i > 0, i % 76 == 0 { wrapped += "\r\n" }
            wrapped.append(character)
        }
        let identity = try PublicIdentity(importingString: "  \n" + wrapped + "\n\t ")
        XCTAssertEqual(identity.fingerprint.description, IdentityVectors.fingerprint)
    }

    // MARK: No private material

    func testExportHoldsOnlyPublicData() throws {
        let vault = try TestVault()
        let identity = try vault.create()
        let exported = [UInt8](identity.publicIdentity.exportedData)
        XCTAssertEqual(exported.count, IdentityFormat.pqidFixedSize + 2)  // "Me"

        // The private seeds behind it, and the contacts key.
        let secrets: [[UInt8]] = try identity.withKeys { keys in
            [[UInt8](keys.xwing.seedRepresentation), [UInt8](keys.mldsa.seedRepresentation),
             [UInt8](keys.ed25519.rawRepresentation), keys.contactsKey.withUnsafeBytes { Array($0) }]
        }
        for secret in secrets {
            XCTAssertEqual(secret.count, 32)
            XCTAssertFalse(exported.containsSubsequence(secret))
            XCTAssertFalse(identity.publicIdentity.exportedString.contains(Data(secret).base64EncodedString()))
        }
        // Nor the passphrase.
        XCTAssertFalse(exported.containsSubsequence(Array("agreement".utf8)))
    }

    // MARK: Rejections: structure

    func testRejectsBadMagic() throws {
        var bytes = try IdentityVectors.pqid()
        bytes[0] = UInt8(ascii: "X")
        assertCoreFailure(.identityBadMagic) { _ = try PQIDCodec.decode(bytes) }
        assertCoreFailure(.identityBadMagic) { _ = try PQIDCodec.decode(Array("CHOTAM".utf8) + [0, 1]) }
        // A .enc file is not an identity.
        assertCoreFailure(.identityBadMagic) { _ = try PQIDCodec.decode(try vector("password-small.enc")) }
    }

    func testRejectsOtherVersions() throws {
        for version: UInt16 in [0, 2, 0xFFFF] {
            var bytes = try IdentityVectors.pqid()
            bytes.put(version, at: 8)
            assertCoreFailure(.identityUnsupportedVersion) { _ = try PQIDCodec.decode(bytes) }
            assertIdentityError(.unsupportedVersion) { _ = try PublicIdentity(importing: Data(bytes)) }
        }
    }

    func testRejectsWrongLengthFields() throws {
        let golden = try IdentityVectors.pqid()
        let fields: [(Int, UInt16)] = [
            (10, 1215), (10, 1217), (1228, 1951), (1228, 0), (3182, 31), (3182, 33), (3259, 3309), (3259, 3372), (3259, 3374),
        ]
        for (offset, value) in fields {
            var bytes = golden
            bytes.put(value, at: offset)
            assertCoreFailure(.identityMalformed, "offset \(offset) = \(value)") { _ = try PQIDCodec.decode(bytes) }
        }
    }

    func testRejectsEveryTruncation() throws {
        let golden = try IdentityVectors.pqid()
        for length in 0 ..< golden.count {
            assertCoreFailure(nil, "prefix \(length)") { _ = try PQIDCodec.decode(Array(golden.prefix(length))) }
        }
    }

    func testRejectsTrailingBytes() throws {
        let golden = try IdentityVectors.pqid()
        assertCoreFailure(.identityTrailingBytes) { _ = try PQIDCodec.decode(golden + [0]) }
        assertCoreFailure(.identityTrailingBytes) { _ = try PQIDCodec.decode(golden + golden.prefix(100)) }
    }

    func testRejectsOversizedInputBeforeParsing() throws {
        let golden = try IdentityVectors.pqid()
        let padded = golden + [UInt8](repeating: 0, count: IdentityFormat.pqidMaxFileSize + 1 - golden.count)
        assertCoreFailure(.identityTooLarge) { _ = try PQIDCodec.decode(padded) }
        assertIdentityError(.invalidIdentity) { _ = try PublicIdentity(importing: Data(count: 50_000_000)) }

        let longString = String(repeating: "A", count: IdentityFormat.pqidMaxStringLength + 1)
        assertCoreFailure(.identityTooLarge) { _ = try PQIDCodec.decode(string: longString) }
    }

    // MARK: Rejections: names

    func testNameRules() throws {
        let rejected: [[UInt8]] = [
            Array(repeating: UInt8(ascii: "a"), count: 65),  // too long
            Array("Al\u{202E}ecila".utf8),  // right-to-left override
            Array("Alice\nBob".utf8),  // newline
            Array("Alice\u{0}".utf8),  // NUL
            Array("   ".utf8),  // only whitespace
            [0x41, 0xC3, 0x28],  // invalid UTF-8
            [0xC0, 0xAF],  // overlong "/"
        ]
        for nameBytes in rejected {
            var raw = try RawPQID.golden()
            raw.nameBytes = nameBytes
            assertCoreFailure(.identityInvalidName, "\(nameBytes)") { _ = try PQIDCodec.decode(try raw.signedByGolden()) }
        }

        let accepted = ["A", "Élodie", "יוסף", "李雷", "Anne-Marie O'Neil", String(repeating: "x", count: 64)]
        for name in accepted {
            var raw = try RawPQID.golden()
            raw.nameBytes = Array(name.utf8)
            XCTAssertEqual(try PQIDCodec.decode(try raw.signedByGolden()).suggestedName, name)
        }
    }

    // MARK: Rejections: keys and signature

    func testRejectsNonCanonicalMLKEMKey() throws {
        var raw = try RawPQID.golden()
        raw.encryptionKey[0] = 0xFF  // first coefficient 0xFFF = 4095 ≥ q
        raw.encryptionKey[1] |= 0x0F
        // Correctly signed, so only the key check can fail.
        assertCoreFailure(.identityInvalidKey) { _ = try PQIDCodec.decode(try raw.signedByGolden()) }
    }

    func testMLKEMModulusCheck() {
        XCTAssertTrue(MLKEMEncoding.isCanonical([0x00, 0x0D, 0x00]))  // 3328, 0
        XCTAssertFalse(MLKEMEncoding.isCanonical([0x01, 0x0D, 0x00]))  // 3329, 0
        XCTAssertTrue(MLKEMEncoding.isCanonical([0x00, 0x00, 0xD0]))  // 0, 3328
        XCTAssertFalse(MLKEMEncoding.isCanonical([0x00, 0x10, 0xD0]))  // 0, 3329
        XCTAssertFalse(MLKEMEncoding.isCanonical([0x00, 0x00]))
        XCTAssertTrue(MLKEMEncoding.isCanonical([UInt8](try! IdentityVectors.xwingKey().publicKey.rawRepresentation.prefix(1152))))
    }

    func testRejectsAnyChangeUnderTheSignature() throws {
        let golden = try IdentityVectors.pqid()
        // In the X25519 part of the X-Wing key, the ML-DSA key, the Ed25519 key, the KDF
        // block, the name, and both halves of the signature.
        for offset in [1227, 1230, 2000, 3184, 3215, 3225, 3240, 3252, 3256, 3261, 3324, 3325, 5000, golden.count - 1] {
            var bytes = golden
            bytes[offset] ^= 0x02
            assertCoreFailure(nil, "offset \(offset)") { _ = try PQIDCodec.decode(bytes) }
        }
        var renamed = golden
        renamed[3252] = UInt8(ascii: "E")  // "Elice": a valid name, but not the signed one
        assertCoreFailure(.identityBadSignature) { _ = try PQIDCodec.decode(renamed) }
        var resalted = golden
        resalted[3240] ^= 0x01  // a different, valid salt: not the signed one
        assertCoreFailure(.identityBadSignature) { _ = try PQIDCodec.decode(resalted) }
    }

    /// Both halves of the self-signature must verify (SECURITY.md §5.9).
    func testRejectsAHalfSignedIdentity() throws {
        let raw = try RawPQID.golden()
        let other = try SomeoneElse()
        // Right ML-DSA key, wrong Ed25519 key; and the other way round.
        assertCoreFailure(.identityBadSignature) {
            _ = try PQIDCodec.decode(try raw.signed(by: other.ed25519, try IdentityVectors.mldsaKey()))
        }
        assertCoreFailure(.identityBadSignature) {
            _ = try PQIDCodec.decode(try raw.signed(by: try IdentityVectors.ed25519Key(), other.mldsa))
        }
    }

    /// Mallory can't publish an identity pairing Alice's signing keys with his own
    /// encryption key: he can't sign it with Alice's keys (SECURITY.md D14).
    func testRejectsSomeoneElsesSigningKey() throws {
        let mallory = try SomeoneElse(name: "Mallory")
        let alice = try PQIDCodec.decode(try IdentityVectors.pqid())
        var forged = RawPQID(
            encryptionKey: mallory.publicIdentity.encryptionKeyBytes,
            mldsaKey: alice.mldsaKeyBytes, ed25519Key: alice.ed25519KeyBytes)
        forged.nameBytes = Array("Alice".utf8)
        assertCoreFailure(.identityBadSignature) { _ = try PQIDCodec.decode(try forged.signed(by: mallory.ed25519, mallory.mldsa)) }
    }

    /// A signature made for another purpose (no label) doesn't count.
    func testSelfSignatureIsDomainSeparated() throws {
        let raw = try RawPQID.golden()
        let unlabelled = [UInt8](try IdentityVectors.ed25519Key().signature(for: raw.body))
            + [UInt8](try IdentityVectors.mldsaKey().signature(for: raw.body))
        let bytes = raw.body + [0x0D, 0x2D] + unlabelled
        assertCoreFailure(.identityBadSignature) { _ = try PQIDCodec.decode(bytes) }
    }

    // MARK: Rejections: KDF block

    func testKDFBlockRules() throws {
        func decode(_ change: (inout RawPQID) -> Void) throws -> [UInt8] {
            var raw = try RawPQID.golden()
            change(&raw)
            return try raw.signedByGolden()
        }
        // Another algorithm or an unknown flag: made by a newer version.
        assertCoreFailure(.identityUnsupportedVersion) { _ = try PQIDCodec.decode(try decode { $0.kdfAlgorithm = 2 }) }
        assertCoreFailure(.identityUnsupportedVersion) { _ = try PQIDCodec.decode(try decode { $0.kdfAlgorithm = 0 }) }
        assertCoreFailure(.identityUnsupportedVersion) { _ = try PQIDCodec.decode(try decode { $0.kdfFlags = 0x02 }) }
        assertCoreFailure(.identityUnsupportedVersion) { _ = try PQIDCodec.decode(try decode { $0.kdfFlags = 0x81 }) }
        // Costs outside the window: a substituted .pqid can't make unlock trivial or huge.
        for ops: UInt64 in [0, 2, 17, .max] {
            assertCoreFailure(.identityMalformed, "ops \(ops)") { _ = try PQIDCodec.decode(try decode { $0.opsLimit = ops }) }
        }
        for mem: UInt64 in [0, (256 << 20) - 1, (2 << 30) + 1, .max] {
            assertCoreFailure(.identityMalformed, "mem \(mem)") { _ = try PQIDCodec.decode(try decode { $0.memLimit = mem }) }
        }
        for lanes: UInt8 in [0, 2, 255] {
            assertCoreFailure(.identityMalformed) { _ = try PQIDCodec.decode(try decode { $0.parallelism = lanes }) }
        }
        // The edges of the window are accepted.
        XCTAssertNoThrow(try PQIDCodec.decode(try decode { $0.opsLimit = 16; $0.memLimit = 2 << 30 }))
        XCTAssertNoThrow(try PQIDCodec.decode(try decode { $0.kdfFlags = 1 }))
    }

    // MARK: Extensions (reserved for later versions)

    func testExtensionRules() throws {
        func entry(_ type: UInt16, _ value: [UInt8]) -> [UInt8] {
            [UInt8(type >> 8), UInt8(type & 0xFF), UInt8(value.count >> 8), UInt8(value.count & 0xFF)] + value
        }
        func decode(_ extensions: [UInt8]) throws -> PublicIdentity {
            var raw = try RawPQID.golden()
            raw.extensions = extensions
            return try PQIDCodec.decode(try raw.signedByGolden())
        }
        // Unknown, non-critical: kept (it's signed) and ignored.
        let ignored = try decode(entry(0x0001, [1, 2, 3]) + entry(0x0100, []))
        XCTAssertEqual(ignored.fingerprint.description, IdentityVectors.fingerprint)
        XCTAssertEqual(try PublicIdentity(importing: ignored.exportedData), ignored)
        // Unknown and critical: made by a newer version.
        assertCoreFailure(.identityUnsupportedVersion) { _ = try decode(entry(0x8001, [9])) }
        assertCoreFailure(.identityUnsupportedVersion) { _ = try decode(entry(0x0001, []) + entry(0x8000, [])) }
        // Malformed: type 0, out of order, duplicates, overrunning lengths, too long.
        assertCoreFailure(.identityMalformed) { _ = try decode(entry(0x0000, [])) }
        assertCoreFailure(.identityMalformed) { _ = try decode(entry(0x0002, []) + entry(0x0001, [])) }
        assertCoreFailure(.identityMalformed) { _ = try decode(entry(0x0003, []) + entry(0x0003, [])) }
        assertCoreFailure(.identityMalformed) { _ = try decode([0x00, 0x01, 0x00, 0x05, 1, 2]) }
        assertCoreFailure(.identityMalformed) { _ = try decode([0x00, 0x01, 0x00]) }
        assertCoreFailure(.identityMalformed) { _ = try decode(entry(0x0001, Array(repeating: 0, count: 1021))) }
        XCTAssertNoThrow(try decode(entry(0x0001, Array(repeating: 0, count: 1020))))  // exactly 1024 bytes

        // The encoder refuses what the parser refuses.
        XCTAssertThrowsError(try PQIDCodec.encode([.init(type: 2, value: []), .init(type: 1, value: [])]))
        XCTAssertThrowsError(try PQIDCodec.encode([.init(type: 0, value: [])]))
    }

    // MARK: Rejections: the string form

    func testStringMustBeStrictBase64() throws {
        let string = try PQIDCodec.decode(try IdentityVectors.pqid()).exportedString
        XCTAssertTrue(string.hasSuffix("=="))  // 6634 = 3 × 2211 + 1

        let broken = [
            String(string.dropLast()),  // bad padding
            String(string.dropLast(2)),  // no padding
            string + "=",
            string.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_"),  // URL-safe
            "*" + String(string.dropFirst()),
            "",
            "   ",
        ]
        for text in broken where text != string {
            assertCoreFailure(.identityBadEncoding, String(text.prefix(12))) { _ = try PQIDCodec.decode(string: text) }
        }

        // Non-canonical: the 4 spare bits of the last symbol before "==" set.
        var symbols = Array(string)
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        let index = symbols.count - 3
        symbols[index] = alphabet[alphabet.firstIndex(of: symbols[index])! | 0x01]
        assertCoreFailure(.identityBadEncoding) { _ = try PQIDCodec.decode(string: String(symbols)) }
    }

    func testPublicErrorsForImports() throws {
        assertIdentityError(.invalidIdentity) { _ = try PublicIdentity(importing: Data("hello".utf8)) }
        assertIdentityError(.invalidIdentity) { _ = try PublicIdentity(importingString: "not base64!") }
        assertIdentityError(.invalidIdentity) { _ = try PublicIdentity(importing: Data()) }
    }
}
