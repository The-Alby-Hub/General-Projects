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
        XCTAssertEqual(identity.signingKeyBytes, [UInt8](try IdentityVectors.mldsaKey().publicKey.rawRepresentation))
        XCTAssertEqual(identity.encoded, bytes)
    }

    /// The layout, byte by byte, as FORMAT.md §9.1 gives it.
    func testGoldenFileLayout() throws {
        let bytes = try IdentityVectors.pqid()
        XCTAssertEqual(Array(bytes[0 ..< 8]), Array("CHOTAMID".utf8))
        XCTAssertEqual(Array(bytes[8 ..< 10]), [0x00, 0x01])  // version 1
        XCTAssertEqual(Array(bytes[10 ..< 12]), [0x04, 0xC0])  // 1216
        XCTAssertEqual(Array(bytes[1228 ..< 1230]), [0x07, 0xA0])  // 1952
        XCTAssertEqual(bytes[3182], 5)  // "Alice"
        XCTAssertEqual(Array(bytes[3183 ..< 3188]), Array("Alice".utf8))
        XCTAssertEqual(Array(bytes[3188 ..< 3190]), [0x0C, 0xED])  // 3309
        XCTAssertEqual(bytes.count, 3190 + 3309)
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

    func testExportHoldsOnlyPublicKeysNameAndSignature() throws {
        for behaviour in [FakeSecureEnclave.Behaviour.available, .unavailable] {
            let keyring = TestKeyring(secureEnclave: behaviour)
            let identity = try keyring.store.createIdentity(name: "Me")
            let exported = [UInt8](identity.publicIdentity.exportedData)
            XCTAssertEqual(exported.count, IdentityFormat.pqidFixedSize + 2)

            // The private seeds, as held in the (fake) Keychain items.
            let items = keyring.items.snapshot
            let xwingSeed = Array([UInt8](items[.encryptionKey]!.data).prefix(32))
            let signingItem = [UInt8](items[.signingKey]!.data)
            let mldsaSeed = behaviour == .available
                ? Array(signingItem.dropFirst(FakeSecureEnclave.handlePrefix.count).prefix(32))
                : Array(signingItem.prefix(32))
            XCTAssertFalse(exported.containsSubsequence(xwingSeed))
            XCTAssertFalse(exported.containsSubsequence(mldsaSeed))
            XCTAssertFalse(identity.publicIdentity.exportedString.contains(Data(xwingSeed).base64EncodedString()))
        }
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
        for (offset, value) in [(10, UInt16(1215)), (10, 1217), (1228, 1951), (1228, 0), (3188, 3308), (3188, 3310)] {
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
        let key = try IdentityVectors.mldsaKey()
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
            assertCoreFailure(.identityInvalidName, "\(nameBytes)") { _ = try PQIDCodec.decode(try raw.signed(by: key)) }
        }

        let accepted = ["A", "Élodie", "יוסף", "李雷", "Anne-Marie O'Neil", String(repeating: "x", count: 64)]
        for name in accepted {
            var raw = try RawPQID.golden()
            raw.nameBytes = Array(name.utf8)
            XCTAssertEqual(try PQIDCodec.decode(try raw.signed(by: key)).suggestedName, name)
        }
    }

    // MARK: Rejections: keys and signature

    func testRejectsNonCanonicalMLKEMKey() throws {
        var raw = try RawPQID.golden()
        raw.encryptionKey[0] = 0xFF  // first coefficient 0xFFF = 4095 ≥ q
        raw.encryptionKey[1] |= 0x0F
        // Correctly signed, so only the key check can fail.
        assertCoreFailure(.identityInvalidKey) { _ = try PQIDCodec.decode(try raw.signed(by: try IdentityVectors.mldsaKey())) }
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
        // In the X25519 part of the X-Wing key, the ML-DSA key, the name, and the signature.
        for offset in [1227, 1230, 2000, 3183, 3187, 3190, 5000, golden.count - 1] {
            var bytes = golden
            bytes[offset] ^= 0x02
            assertCoreFailure(nil, "offset \(offset)") { _ = try PQIDCodec.decode(bytes) }
        }
        var renamed = golden
        renamed[3183] = UInt8(ascii: "E")  // "Elice": a valid name, but not the signed one
        assertCoreFailure(.identityBadSignature) { _ = try PQIDCodec.decode(renamed) }
    }

    /// Mallory can't publish an identity pairing Alice's signing key with his own
    /// encryption key: he can't sign it with Alice's key (SECURITY.md D14).
    func testRejectsSomeoneElsesSigningKey() throws {
        let mallory = try SomeoneElse(name: "Mallory")
        let alice = try PQIDCodec.decode(try IdentityVectors.pqid())
        let forged = RawPQID(encryptionKey: mallory.publicIdentity.encryptionKeyBytes, signingKey: alice.signingKeyBytes)
        assertCoreFailure(.identityBadSignature) { _ = try PQIDCodec.decode(try forged.signed(by: mallory.mldsa)) }
    }

    /// A signature made for another purpose (no label, or a file's label) doesn't count.
    func testSelfSignatureIsDomainSeparated() throws {
        let key = try IdentityVectors.mldsaKey()
        let raw = try RawPQID.golden()
        let unlabelled = [UInt8](try key.signature(for: raw.body))
        let bytes = raw.body + [0x0C, 0xED] + unlabelled
        assertCoreFailure(.identityBadSignature) { _ = try PQIDCodec.decode(bytes) }
    }

    // MARK: Rejections: the string form

    func testStringMustBeStrictBase64() throws {
        let string = try PQIDCodec.decode(try IdentityVectors.pqid()).exportedString
        XCTAssertTrue(string.hasSuffix("=="))  // 6499 = 3 × 2166 + 1

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
