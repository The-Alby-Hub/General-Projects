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
        XCTAssertEqual(key.seedRepresentation.count, 32)
        // seed ‖ SHA3-256(public key): what the Keychain item holds.
        XCTAssertEqual(key.integrityCheckedRepresentation.count, 64)

        let encapsulation = try key.publicKey.encapsulate()
        XCTAssertEqual(encapsulation.encapsulated.count, FormatV1.xwingEncapsulatedKeySize)  // 1120
        XCTAssertEqual(try key.decapsulate(encapsulation.encapsulated), encapsulation.sharedSecret)
    }

    func testMLDSA65Sizes() throws {
        let key = try MLDSA65.PrivateKey()
        XCTAssertEqual(key.publicKey.rawRepresentation.count, IdentityFormat.mldsa65PublicKeySize)  // 1952
        XCTAssertEqual(key.seedRepresentation.count, 32)
        XCTAssertEqual(key.integrityCheckedRepresentation.count, 64)

        let message = Array("Chotam".utf8)
        let signature = try key.signature(for: message)
        XCTAssertEqual(signature.count, FormatV1.mldsa65SignatureSize)  // 3309
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
        XCTAssertFalse(key.publicKey.isValidSignature(signature, for: message + [0]))
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
    /// implementations the vectors came from (X-Wing draft seed expansion, FIPS 204 KeyGen).
    func testGoldenSeedsGiveGoldenPublicKeys() throws {
        let xwing = try IdentityVectors.xwingKey()
        let mldsa = try IdentityVectors.mldsaKey()
        XCTAssertEqual(sha256Hex(xwing.publicKey.rawRepresentation), IdentityVectors.xwingPublicKeySHA256)
        XCTAssertEqual(sha256Hex(mldsa.publicKey.rawRepresentation), IdentityVectors.mldsaPublicKeySHA256)
        XCTAssertEqual([UInt8](xwing.seedRepresentation), IdentityVectors.xwingSeed)
        XCTAssertEqual([UInt8](mldsa.seedRepresentation), IdentityVectors.mldsaSeed)
    }

    func testGeneratedKeysAreFresh() throws {
        let a = try XWingMLKEM768X25519.PrivateKey.generate()
        let b = try XWingMLKEM768X25519.PrivateKey.generate()
        XCTAssertNotEqual(a.publicKey.rawRepresentation, b.publicKey.rawRepresentation)
        XCTAssertNotEqual(try MLDSA65.PrivateKey().publicKey.rawRepresentation,
                          try MLDSA65.PrivateKey().publicKey.rawRepresentation)
    }

    /// The Keychain holds the integrity-checked form; a damaged one must not load.
    func testIntegrityCheckedRepresentationsRejectDamage() throws {
        let xwing = try XWingMLKEM768X25519.PrivateKey.generate()
        var stored = [UInt8](xwing.integrityCheckedRepresentation)
        let reloaded = try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: stored)
        XCTAssertEqual(reloaded.publicKey.rawRepresentation, xwing.publicKey.rawRepresentation)
        stored[40] ^= 0x01  // in the public-key hash
        XCTAssertThrowsError(try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: stored))

        let mldsa = try MLDSA65.PrivateKey()
        var signing = [UInt8](mldsa.integrityCheckedRepresentation)
        signing[3] ^= 0x01  // in the seed
        XCTAssertThrowsError(try MLDSA65.PrivateKey(integrityCheckedRepresentation: signing))
    }

    // MARK: Key IDs (FORMAT.md §6.1)

    func testGoldenKeyIDs() throws {
        let xwing = try IdentityVectors.xwingKey()
        let mldsa = try IdentityVectors.mldsaKey()
        XCTAssertEqual(KeyID.encryption(xwing.publicKey).hex, IdentityVectors.encryptionKeyID)
        XCTAssertEqual(KeyID.signing(mldsa.publicKey).hex, IdentityVectors.signingKeyID)
    }

    func testKeyIDsAreDomainSeparatedSHA256() throws {
        let raw = [UInt8](repeating: 0x42, count: 100)
        let encryption = KeyID.encryption(rawPublicKey: raw)
        let signing = KeyID.signing(rawPublicKey: raw)
        XCTAssertEqual(encryption.bytes.count, FormatV1.keyIDSize)
        XCTAssertNotEqual(encryption, signing)
        XCTAssertEqual(hexString(encryption.bytes), sha256Hex(Array("Chotam v1 encryption key id".utf8) + raw))
        XCTAssertEqual(hexString(signing.bytes), sha256Hex(Array("Chotam v1 signing key id".utf8) + raw))
        // Not the plain hash of the key.
        XCTAssertNotEqual(hexString(encryption.bytes), sha256Hex(raw))
    }
}
