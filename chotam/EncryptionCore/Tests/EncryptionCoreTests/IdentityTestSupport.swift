import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Golden values from `Vectors/make_identity_vectors.py`, an independent implementation
/// (argon2-cffi, pyca/cryptography, kyber-py, dilithium-py). See FORMAT.md §9.7.
enum IdentityVectors {
    /// As typed: odd spacing and case. Canonical: "agreement curve flakily ligament pretty shrimp unbundle".
    static let typedPassphrase = "  Agreement curve\tflakily  LIGAMENT pretty shrimp unbundle "
    static let canonicalPassphrase = "agreement curve flakily ligament pretty shrimp unbundle"
    static let kdfSalt = Array(UInt8(0xA0) ... UInt8(0xAF))
    static let kdfCost = IdentityFormat.minimumKDFCost  // ops 3, 256 MiB
    static let master = "56699a39a9c4c3fb4d2ae00b01c7e5d35e93d56ab43894dcd504c4a382d17bb0"
    static let xwingSeed = bytes("50982133f3fc11b35a7d74bd199e71ae2d32f7eff28ee9e41dfab1319c339e01")
    static let mldsaSeed = bytes("d73865dc9d34f90dc0a3285705e191567e33c975fe2088578a9ba416239a2029")
    static let ed25519Seed = bytes("ca4929a785c811281ff92dfee6f0ffe722c6dd8d73fa5cd0424b039fbbb062e8")
    static let contactsKey = "f7a103cafe4651cab5a16abc925db3bac5b4bb00368303905c3258cbc4d5179a"
    static let xwingPublicKeySHA256 = "1e34d8c2c31e5034107adc9a9d9cd835f6f3bdbbda90c7f3f49dfb79308fe5aa"
    static let mldsaPublicKeySHA256 = "2d47a737b8b0cd79b1664bbcf3560c59d0c079c072b0570863b917a6cd38d2cf"
    static let ed25519PublicKey = "a6ea84d3af13fddb9ea74b418494d456844e44cd4686dced46066264550246be"
    static let encryptionKeyID = "8e8b1793835f7461f1e4e32dd9479886c952a5984b1eb36b1be2f22dd33a186f"
    static let signingKeyID = "21e85ceeb2d426639b1464dade0766deaefb2646b254a67a2f18fb9e96333263"
    static let fingerprint = "80XX XYHV TNDW KMXW QJ1J KY3M 0SVB QTVM"
    static let fingerprintDigest = "403bdefa3bd55bc9d3bcbc8329f8740676bbeb74"
    static let name = "Alice"
    static let pqidFile = "identity-v1.pqid"
    static let pqidSize = 6634
    static let pqidSHA256 = "e752f0cc3ceba81971690e964dd1578f6a69586d58bf1fec157af71185c345a3"

    /// The same passphrase plus a key file: 1 KiB, bytes 0…255 repeated 4 times.
    static let keyFile: [UInt8] = Array((0 ..< 4).map { _ in Array(UInt8(0) ... UInt8(255)) }.joined())
    static let keyFilePQIDFile = "identity-keyfile-v1.pqid"
    static let keyFilePQIDSHA256 = "9a814bf6f3fd1ba2c6759ee34dd3b6ce464635b5892a229c98a39c8d17eed6ad"
    static let keyFileFingerprint = "PXJ3 2BC0 R2CV ZNDE BMXP RPPQ 6WM9 HK6D"
    static let keyFileXWingSeed = bytes("efdd6b690a140abedc42877315f2583c5b39b36e1b609a9abbefd816fad7c962")

    static func xwingKey() throws -> XWingMLKEM768X25519.PrivateKey {
        try XWingMLKEM768X25519.PrivateKey(seedRepresentation: xwingSeed, publicKey: nil)
    }

    static func mldsaKey() throws -> MLDSA65.PrivateKey {
        try MLDSA65.PrivateKey(seedRepresentation: mldsaSeed, publicKey: nil)
    }

    static func ed25519Key() throws -> Curve25519.Signing.PrivateKey {
        try Curve25519.Signing.PrivateKey(rawRepresentation: ed25519Seed)
    }

    static func pqid() throws -> [UInt8] {
        try vector(pqidFile)
    }

    static func bytes(_ hex: String) -> [UInt8] {
        var result: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            result.append(UInt8(hex[index ..< next], radix: 16)!)
            index = next
        }
        return result
    }
}

func sha256Hex<D: DataProtocol>(_ data: D) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

extension Array where Element == UInt8 {
    func containsSubsequence(_ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, needle.count <= count else { return false }
        for start in 0 ... (count - needle.count) where self[start] == needle[0] {
            if Array(self[start ..< start + needle.count]) == needle { return true }
        }
        return false
    }
}

// MARK: An independent .pqid builder

/// Builds `.pqid` bytes field by field from FORMAT.md §9, without `PQIDCodec`, so tests
/// can make files the encoder would refuse (bad names, wrong lengths, other versions).
struct RawPQID {
    var magic = Array("CHOTAMID".utf8)
    var version: UInt16 = 1
    var encryptionKey: [UInt8]
    var encryptionKeyLength: UInt16? = nil
    var mldsaKey: [UInt8]
    var mldsaKeyLength: UInt16? = nil
    var ed25519Key: [UInt8]
    var ed25519KeyLength: UInt16? = nil
    var kdfAlgorithm: UInt8 = 1
    var kdfFlags: UInt8 = 0
    var opsLimit: UInt64 = 3
    var memLimit: UInt64 = 256 << 20
    var parallelism: UInt8 = 1
    var salt: [UInt8] = IdentityVectors.kdfSalt
    var nameBytes: [UInt8] = Array("Alice".utf8)
    var extensions: [UInt8] = []
    var extensionsLength: UInt16? = nil
    var signatureLength: UInt16? = nil
    var trailing: [UInt8] = []

    init(encryptionKey: [UInt8], mldsaKey: [UInt8], ed25519Key: [UInt8]) {
        self.encryptionKey = encryptionKey
        self.mldsaKey = mldsaKey
        self.ed25519Key = ed25519Key
    }

    /// The golden identity's keys and KDF parameters.
    static func golden() throws -> RawPQID {
        RawPQID(
            encryptionKey: [UInt8](try IdentityVectors.xwingKey().publicKey.rawRepresentation),
            mldsaKey: [UInt8](try IdentityVectors.mldsaKey().publicKey.rawRepresentation),
            ed25519Key: [UInt8](try IdentityVectors.ed25519Key().publicKey.rawRepresentation))
    }

    var body: [UInt8] {
        var bytes = magic
        bytes += be(version)
        bytes += be(encryptionKeyLength ?? UInt16(encryptionKey.count)) + encryptionKey
        bytes += be(mldsaKeyLength ?? UInt16(mldsaKey.count)) + mldsaKey
        bytes += be(ed25519KeyLength ?? UInt16(ed25519Key.count)) + ed25519Key
        bytes += [kdfAlgorithm, kdfFlags] + be64(opsLimit) + be64(memLimit) + [parallelism] + salt
        bytes += [UInt8(truncatingIfNeeded: nameBytes.count)] + nameBytes
        bytes += be(extensionsLength ?? UInt16(extensions.count)) + extensions
        return bytes
    }

    /// Signed by both keys over `"Chotam v1 identity signature" ‖ body`, as §9.2 says.
    func signed(by ed25519: Curve25519.Signing.PrivateKey, _ mldsa: MLDSA65.PrivateKey) throws -> [UInt8] {
        let message = Array("Chotam v1 identity signature".utf8) + body
        let signature = [UInt8](try ed25519.signature(for: message)) + [UInt8](try mldsa.signature(for: message))
        return body + be(signatureLength ?? UInt16(signature.count)) + signature + trailing
    }

    /// Signed with the golden keys.
    func signedByGolden() throws -> [UInt8] {
        try signed(by: try IdentityVectors.ed25519Key(), try IdentityVectors.mldsaKey())
    }

    private func be(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    private func be64(_ value: UInt64) -> [UInt8] {
        (0 ..< 8).reversed().map { UInt8(truncatingIfNeeded: value >> (8 * UInt64($0))) }
    }
}

/// A fresh, valid public identity (someone else's), with its private keys. Its KDF
/// block is well-formed but never used: nobody derives a contact's keys.
struct SomeoneElse {
    let xwing: XWingMLKEM768X25519.PrivateKey
    let mldsa: MLDSA65.PrivateKey
    let ed25519: Curve25519.Signing.PrivateKey
    let publicIdentity: PublicIdentity

    init(name: String? = "Bob") throws {
        xwing = try XWingMLKEM768X25519.PrivateKey.generate()
        mldsa = try MLDSA65.PrivateKey()
        ed25519 = Curve25519.Signing.PrivateKey()
        var raw = RawPQID(
            encryptionKey: [UInt8](xwing.publicKey.rawRepresentation),
            mldsaKey: [UInt8](mldsa.publicKey.rawRepresentation),
            ed25519Key: [UInt8](ed25519.publicKey.rawRepresentation))
        raw.nameBytes = Array((name ?? "").utf8)
        raw.salt = SecureRandom.bytes(16)
        publicIdentity = try PQIDCodec.decode(try raw.signed(by: ed25519, mldsa))
    }
}

// MARK: A vault in a temp folder

/// An `IdentityVault` in a fresh temp folder, using the cheapest KDF cost an identity
/// may declare (ops 3, 256 MiB), so each unlock takes a fraction of a second.
final class TestVault {
    let scratch: Scratch
    let vault: IdentityVault

    init() throws {
        scratch = try Scratch()
        vault = IdentityVault(folder: scratch.folder.appendingPathComponent("Chotam", isDirectory: true))
    }

    deinit {
        scratch.remove()
    }

    var identityFile: URL { vault.folder.appendingPathComponent(IdentityFormat.identityFileName) }
    var contactsFile: URL { vault.folder.appendingPathComponent(IdentityFormat.contactsFileName) }

    /// Creates an identity with the golden test passphrase (and a key file if given).
    func create(name: String = "Me", passphrase: String = IdentityVectors.canonicalPassphrase, keyFile: URL? = nil) throws -> Identity {
        try vault.createIdentity(name: name, passphrase: passphrase, keyFile: keyFile, cost: IdentityFormat.minimumKDFCost)
    }

    func unlock(_ passphrase: String = IdentityVectors.canonicalPassphrase, keyFile: URL? = nil) throws -> Identity {
        try vault.unlock(passphrase: passphrase, keyFile: keyFile)
    }
}

/// Asserts that `body` throws exactly `expected`.
func assertIdentityError(
    _ expected: IdentityError, _ message: String = "",
    file: StaticString = #filePath, line: UInt = #line,
    _ body: () throws -> Void
) {
    do {
        try body()
        XCTFail("expected \(expected) \(message)", file: file, line: line)
    } catch let error as IdentityError {
        XCTAssertEqual(error, expected, message, file: file, line: line)
    } catch {
        XCTFail("unexpected error type \(type(of: error)) \(message)", file: file, line: line)
    }
}
