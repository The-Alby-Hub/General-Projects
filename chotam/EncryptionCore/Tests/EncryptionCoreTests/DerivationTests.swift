import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Passphrase → keys (FORMAT.md §9.6), checked value by value against the independent
/// Python implementation, plus the passphrase rules and the locked secret buffers.
final class DerivationTests: XCTestCase {
    private var goldenKDF: IdentityKDF {
        IdentityKDF(cost: IdentityVectors.kdfCost, salt: IdentityVectors.kdfSalt, requiresKeyFile: false)
    }

    // MARK: Golden values

    func testGoldenMaster() throws {
        let secret = try XCTUnwrap(IdentityPassphrase.canonical(IdentityVectors.typedPassphrase))
        let master = try Argon2id.derive(secret: secret, salt: IdentityVectors.kdfSalt, cost: IdentityVectors.kdfCost)
        XCTAssertEqual(master.withUnsafeBytes { hexString(Array($0)) }, IdentityVectors.master)
    }

    func testGoldenSeedsAndContactsKey() throws {
        let secret = try XCTUnwrap(IdentityPassphrase.canonical(IdentityVectors.typedPassphrase))
        let keys = try IdentityDerivation.derive(passphrase: secret, kdf: goldenKDF, keyFileDigest: nil)
        XCTAssertEqual([UInt8](keys.xwing.seedRepresentation), IdentityVectors.xwingSeed)
        XCTAssertEqual([UInt8](keys.mldsa.seedRepresentation), IdentityVectors.mldsaSeed)
        XCTAssertEqual([UInt8](keys.ed25519.rawRepresentation), IdentityVectors.ed25519Seed)
        XCTAssertEqual(keys.contactsKey.withUnsafeBytes { hexString(Array($0)) }, IdentityVectors.contactsKey)
        XCTAssertTrue(keys.match(try PQIDCodec.decode(try IdentityVectors.pqid())))
    }

    func testGoldenKeyFileDigestAndSeed() throws {
        let scratch = try Scratch()
        defer { scratch.remove() }
        let url = try scratch.write(IdentityVectors.keyFile, to: "key")
        let digest = try IdentityDerivation.keyFileDigest(url)
        XCTAssertEqual(hexString(digest), sha256Hex(Array("Chotam v1 key file".utf8) + IdentityVectors.keyFile))

        let secret = try XCTUnwrap(IdentityPassphrase.canonical(IdentityVectors.canonicalPassphrase))
        let kdf = IdentityKDF(cost: IdentityVectors.kdfCost, salt: IdentityVectors.kdfSalt, requiresKeyFile: true)
        let keys = try IdentityDerivation.derive(passphrase: secret, kdf: kdf, keyFileDigest: digest)
        XCTAssertEqual([UInt8](keys.xwing.seedRepresentation), IdentityVectors.keyFileXWingSeed)
        XCTAssertTrue(keys.match(try PQIDCodec.decode(try vector(IdentityVectors.keyFilePQIDFile))))
    }

    /// The four outputs are independent: distinct labels, distinct values.
    func testOutputsAreDistinct() throws {
        let values = [IdentityVectors.xwingSeed, IdentityVectors.mldsaSeed, IdentityVectors.ed25519Seed,
                      IdentityVectors.bytes(IdentityVectors.contactsKey), IdentityVectors.bytes(IdentityVectors.master)]
        XCTAssertEqual(Set(values).count, 5)
        let labels = [IdentityFormat.xwingSeedInfo, IdentityFormat.mldsaSeedInfo, IdentityFormat.ed25519SeedInfo,
                      IdentityFormat.contactsKeyInfo, IdentityFormat.keyFileLabel]
        XCTAssertEqual(Set(labels).count, 5)
    }

    // MARK: Passphrase rules

    func testCanonicalForm() throws {
        let typed = [
            IdentityVectors.typedPassphrase,
            IdentityVectors.canonicalPassphrase,
            "AGREEMENT CURVE FLAKILY LIGAMENT PRETTY SHRIMP UNBUNDLE",
            "agreement\ncurve\nflakily\nligament\npretty\nshrimp\nunbundle\n",
        ]
        for text in typed {
            let buffer = try XCTUnwrap(IdentityPassphrase.canonical(text), text)
            XCTAssertEqual(buffer.withUnsafeBytes { Array($0) }, Array(IdentityVectors.canonicalPassphrase.utf8))
        }
    }

    func testWellFormedRules() throws {
        let generated = try IdentityPassphrase.generate()
        XCTAssertTrue(IdentityPassphrase.isWellFormed(generated))
        XCTAssertEqual(generated.split(separator: " ").count, 7)
        for count in 7 ... 10 {
            XCTAssertTrue(IdentityPassphrase.isWellFormed(try IdentityPassphrase.generate(wordCount: count)))
        }
        assertIdentityError(.invalidPassphrase) { _ = try IdentityPassphrase.generate(wordCount: 6) }
        assertIdentityError(.invalidPassphrase) { _ = try IdentityPassphrase.generate(wordCount: 11) }
        // Hyphenated EFF words are single words.
        XCTAssertTrue(IdentityPassphrase.isWellFormed("t-shirt yo-yo agreement curve flakily ligament pretty"))
        XCTAssertFalse(IdentityPassphrase.isWellFormed(String(generated.split(separator: " ").dropLast().joined(separator: " "))))
        XCTAssertFalse(IdentityPassphrase.isWellFormed("Tr0ub4dor&3 is not seven words at all"))
    }

    /// About 90 bits for the default: offline guessing against the public .pqid is
    /// out of reach (SECURITY.md D17).
    func testDefaultEntropy() {
        XCTAssertGreaterThan(PassphraseGenerator.entropyBits(wordCount: IdentityPassphrase.defaultWordCount), 90)
    }

    // MARK: Secret buffers

    func testSecretBufferHoldsAndCopies() {
        let bytes: [UInt8] = [1, 2, 3, 4]
        let buffer = bytes.withUnsafeBytes { SecretBuffer(copying: $0) }
        XCTAssertEqual(buffer.count, 4)
        XCTAssertEqual(buffer.withUnsafeBytes { Array($0) }, bytes)
        XCTAssertEqual(SecretBuffer(count: 0).withUnsafeBytes { $0.count }, 0)
        XCTAssertNotNil(SecretBuffer(count: 0).withUnsafeBytes { $0.baseAddress })
        // mlock is best effort: on macOS it succeeds for a small buffer.
        #if os(macOS)
        XCTAssertTrue(SecretBuffer(count: 64).isMemoryLocked)
        #endif
    }

    // MARK: Cost on this Mac

    /// Prints how long the default identity cost (1 GiB, ops 8) takes here, for
    /// calibrating `IdentityFormat.defaultKDFCost` ("a few seconds"). Never fails on time.
    func testDefaultCostTiming() throws {
        let secret = try XCTUnwrap(IdentityPassphrase.canonical(IdentityVectors.canonicalPassphrase))
        let start = Date()
        _ = try Argon2id.derive(secret: secret, salt: IdentityVectors.kdfSalt, cost: IdentityFormat.defaultKDFCost)
        let seconds = Date().timeIntervalSince(start)
        print("Chotam calibration: Argon2id 1 GiB, ops 8 took \(String(format: "%.2f", seconds)) s")
    }
}
