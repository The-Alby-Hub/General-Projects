import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Keypair generation, the sizes FORMAT.md relies on (checked against the real SDK),
/// and key IDs (FORMAT.md §6.1).
final class IdentityKeyTests: XCTestCase {
    // MARK: Sizes on this SDK (FORMAT.md "(verify)" values)

    func testXWingSizes() throws {
        let key = try XWingMLKEM768X25519.PrivateKey.generate()
        XCTAssertEqual(key.publicKey.rawRepresentation.count, IdentityFormat.xwingPublicKeySize)  // 1216
        XCTAssertEqual(key.seedRepresentation.count, IdentityFormat.seedSize)

        let encapsulation = try key.publicKey.encapsulate()
        XCTAssertEqual(encapsulation.encapsulated.count, FormatV1.xwingEncapsulatedKeySize)  // 1120
        XCTAssertEqual(try key.decapsulate(encapsulation.encapsulated), encapsulation.sharedSecret)
    }

    func testMLDSA65Sizes() throws {
        let key = try MLDSA65.PrivateKey()
        XCTAssertEqual(key.publicKey.rawRepresentation.count, IdentityFormat.mldsa65PublicKeySize)  // 1952
        XCTAssertEqual(key.seedRepresentation.count, IdentityFormat.seedSize)

        let message = Array("Chotam".utf8)
        let signature = try key.signature(for: message)
        XCTAssertEqual(signature.count, FormatV1.mldsa65SignatureSize)  // 3309
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
        XCTAssertFalse(key.publicKey.isValidSignature(signature, for: message + [0]))
    }

    func testEd25519Sizes() throws {
        let key = Curve25519.Signing.PrivateKey()
        XCTAssertEqual(key.publicKey.rawRepresentation.count, IdentityFormat.ed25519PublicKeySize)  // 32
        XCTAssertEqual(key.rawRepresentation.count, IdentityFormat.seedSize)  // the 32-byte seed
        let message = Array("Chotam".utf8)
        let signature = try key.signature(for: message)
        XCTAssertEqual(signature.count, IdentityFormat.ed25519SignatureSize)  // 64
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
    }

    /// The hybrid signature: both halves, both checked (SECURITY.md §5.9).
    func testHybridSignatureNeedsBothHalves() throws {
        let ed = Curve25519.Signing.PrivateKey()
        let ml = try MLDSA65.PrivateKey()
        let message = Array("Chotam v1 test".utf8)
        let signature = try HybridSignature.sign(message, ed25519: ed, mldsa: ml)
        XCTAssertEqual(signature.count, IdentityFormat.hybridSignatureSize)  // 3373
        XCTAssertTrue(HybridSignature.isValid(signature, for: message, ed25519: ed.publicKey, mldsa: ml.publicKey))
        XCTAssertFalse(HybridSignature.isValid(signature, for: message + [0], ed25519: ed.publicKey, mldsa: ml.publicKey))

        // A valid ML-DSA half with a broken Ed25519 half, and the other way round.
        for offset in [0, 63, 64, signature.count - 1] {
            var broken = signature
            broken[offset] ^= 0x01
            XCTAssertFalse(HybridSignature.isValid(broken, for: message, ed25519: ed.publicKey, mldsa: ml.publicKey))
        }
        // Either half alone, or the halves swapped, is not a signature.
        XCTAssertFalse(HybridSignature.isValid(Array(signature.suffix(3309)), for: message, ed25519: ed.publicKey, mldsa: ml.publicKey))
        XCTAssertFalse(HybridSignature.isValid(Array(signature.prefix(64)), for: message, ed25519: ed.publicKey, mldsa: ml.publicKey))
        let swapped = Array(signature.suffix(3309)) + Array(signature.prefix(64))
        XCTAssertFalse(HybridSignature.isValid(swapped, for: message, ed25519: ed.publicKey, mldsa: ml.publicKey))
        // The right halves from two different keys.
        let otherEd = Curve25519.Signing.PrivateKey()
        XCTAssertFalse(HybridSignature.isValid(signature, for: message, ed25519: otherEd.publicKey, mldsa: ml.publicKey))
    }

    /// The Phase 5 wrapping path exists on this SDK with the sizes FORMAT.md §2.3 fixes.
    func testHPKEXWingCiphersuiteSizes() throws {
        let recipientKey = try XWingMLKEM768X25519.PrivateKey.generate()
        let suite = HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256
        let info = Data("wrap context".utf8)
        let aad = Data("key id".utf8)
        let dataKey = Data(repeating: 0xAB, count: 32)

        var sender = try HPKE.Sender(recipientKey: recipientKey.publicKey, ciphersuite: suite, info: info)
        XCTAssertEqual(sender.encapsulatedKey.count, FormatV1.xwingEncapsulatedKeySize)
        let wrapped = try sender.seal(dataKey, authenticating: aad)
        XCTAssertEqual(wrapped.count, FormatV1.wrappedDataKeySize)  // 32 + 16

        var recipient = try HPKE.Recipient(
            privateKey: recipientKey, ciphersuite: suite, info: info, encapsulatedKey: sender.encapsulatedKey)
        XCTAssertEqual(try recipient.open(wrapped, authenticating: aad), dataKey)
    }

    // MARK: Deterministic keys from the golden seeds

    /// CryptoKit derives the same public keys from the same seeds as the independent
    /// implementations the vectors came from (X-Wing draft seed expansion, FIPS 204
    /// KeyGen, RFC 8032).
    func testGoldenSeedsGiveGoldenPublicKeys() throws {
        let xwing = try IdentityVectors.xwingKey()
        let mldsa = try IdentityVectors.mldsaKey()
        let ed = try IdentityVectors.ed25519Key()
        XCTAssertEqual(sha256Hex(xwing.publicKey.rawRepresentation), IdentityVectors.xwingPublicKeySHA256)
        XCTAssertEqual(sha256Hex(mldsa.publicKey.rawRepresentation), IdentityVectors.mldsaPublicKeySHA256)
        XCTAssertEqual(hexString([UInt8](ed.publicKey.rawRepresentation)), IdentityVectors.ed25519PublicKey)
    }

    func testGeneratedKeysAreFresh() throws {
        let a = try XWingMLKEM768X25519.PrivateKey.generate()
        let b = try XWingMLKEM768X25519.PrivateKey.generate()
        XCTAssertNotEqual(a.publicKey.rawRepresentation, b.publicKey.rawRepresentation)
        XCTAssertNotEqual(try MLDSA65.PrivateKey().publicKey.rawRepresentation,
                          try MLDSA65.PrivateKey().publicKey.rawRepresentation)
    }

    // MARK: Key IDs (FORMAT.md §6.1)

    func testGoldenKeyIDs() throws {
        let xwing = try IdentityVectors.xwingKey()
        XCTAssertEqual(KeyID.encryption(xwing.publicKey).hex, IdentityVectors.encryptionKeyID)
        XCTAssertEqual(
            KeyID.signing(try IdentityVectors.mldsaKey().publicKey, try IdentityVectors.ed25519Key().publicKey).hex,
            IdentityVectors.signingKeyID)
    }

    func testKeyIDsAreDomainSeparatedSHA256() throws {
        let raw = [UInt8](repeating: 0x42, count: 100)
        let ed = [UInt8](repeating: 0x07, count: 32)
        let encryption = KeyID.encryption(rawPublicKey: raw)
        let signing = KeyID.signing(mldsaKey: raw, ed25519Key: ed)
        XCTAssertEqual(encryption.bytes.count, FormatV1.keyIDSize)
        XCTAssertNotEqual(encryption, signing)
        XCTAssertEqual(hexString(encryption.bytes), sha256Hex(Array("Chotam v1 encryption key id".utf8) + raw))
        // A signing key ID covers both halves of the hybrid key.
        XCTAssertEqual(hexString(signing.bytes), sha256Hex(Array("Chotam v1 signing key id".utf8) + raw + ed))
        XCTAssertNotEqual(signing, KeyID.signing(mldsaKey: raw, ed25519Key: [UInt8](repeating: 0x08, count: 32)))
        // Not the plain hash of the key.
        XCTAssertNotEqual(hexString(encryption.bytes), sha256Hex(raw))
    }
}
