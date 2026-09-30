import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Golden values from `Vectors/make_identity_vectors.py`, an independent implementation
/// (kyber-py, dilithium-py and OpenSSL via pyca/cryptography). See FORMAT.md §9.
enum IdentityVectors {
    static let xwingSeed = Array(UInt8(0x60) ... UInt8(0x7F))
    static let mldsaSeed = Array(UInt8(0x80) ... UInt8(0x9F))
    static let xwingPublicKeySHA256 = "d13209d86547a31ae86a67d9a26c90e5efc1310514195ab06e9b9e12bf328b6a"
    static let mldsaPublicKeySHA256 = "e00c3ad05e18901d30ebc2c9044f4b0756ae6922ff258d688292e8ead8d4a2d5"
    static let encryptionKeyID = "19e469ef9a47e5d47b905b1f363d49d62394fec96d55fa6574214f41d65fd2bd"
    static let signingKeyID = "68b63822246c6146ecf92cd83e96fd9d3a78d795ca9a59a9ca53a3b5cbd751ef"
    static let fingerprint = "P6BC HMEY 9SAS BEA0 DGKS 1Y3H FDP9 VXBM"
    static let name = "Alice"
    static let pqidFile = "identity-v1.pqid"
    static let pqidSize = 6499
    static let pqidSHA256 = "2f3016a2e1d19d27202dfc29ef49c71eb9eba5e2a9d271b661b3cb05c3f47fad"

    static func xwingKey() throws -> XWingMLKEM768X25519.PrivateKey {
        try XWingMLKEM768X25519.PrivateKey(seedRepresentation: xwingSeed, publicKey: nil)
    }

    static func mldsaKey() throws -> MLDSA65.PrivateKey {
        try MLDSA65.PrivateKey(seedRepresentation: mldsaSeed, publicKey: nil)
    }

    static func pqid() throws -> [UInt8] {
        try vector(pqidFile)
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
    var signingKey: [UInt8]
    var signingKeyLength: UInt16? = nil
    var nameBytes: [UInt8] = Array("Alice".utf8)
    var signatureLength: UInt16? = nil
    var trailing: [UInt8] = []

    init(encryptionKey: [UInt8], signingKey: [UInt8]) {
        self.encryptionKey = encryptionKey
        self.signingKey = signingKey
    }

    /// The golden identity's keys.
    static func golden() throws -> RawPQID {
        RawPQID(
            encryptionKey: [UInt8](try IdentityVectors.xwingKey().publicKey.rawRepresentation),
            signingKey: [UInt8](try IdentityVectors.mldsaKey().publicKey.rawRepresentation))
    }

    var body: [UInt8] {
        var bytes = magic
        bytes += be(version)
        bytes += be(encryptionKeyLength ?? UInt16(encryptionKey.count)) + encryptionKey
        bytes += be(signingKeyLength ?? UInt16(signingKey.count)) + signingKey
        bytes += [UInt8(truncatingIfNeeded: nameBytes.count)] + nameBytes
        return bytes
    }

    /// Signed with `key` over `"Chotam v1 identity signature" ‖ body`, as §9 says.
    func signed(by key: MLDSA65.PrivateKey) throws -> [UInt8] {
        let signature = [UInt8](try key.signature(for: Array("Chotam v1 identity signature".utf8) + body))
        return body + be(signatureLength ?? UInt16(signature.count)) + signature + trailing
    }

    private func be(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }
}

// MARK: Storage fakes (SECURITY.md D8)

/// An in-memory `SecureItemStore` that records each item's protection, so tests can
/// check that private material is only ever stored behind user presence.
final class InMemoryItemStore: SecureItemStore, @unchecked Sendable {
    struct Entry: Equatable {
        var data: Data
        let protection: ItemProtection
    }

    struct SimulatedFailure: Error {}

    private let lock = NSLock()
    private var entries: [StoredItem: Entry] = [:]
    private var adds = 0
    /// Make the n-th call to `add` (1-based) fail.
    var failAddNumber: Int?
    /// Make every `copy` fail, like a Keychain that can't be reached.
    var failCopies = false
    /// Make reading protected items fail as if the user dismissed the prompt.
    var cancelProtectedReads = false

    func add(_ data: Data, as item: StoredItem, protection: ItemProtection) throws {
        lock.lock()
        defer { lock.unlock() }
        adds += 1
        if adds == failAddNumber { throw SimulatedFailure() }
        guard entries[item] == nil else { throw SecureStoreError.duplicateItem }
        entries[item] = Entry(data: data, protection: protection)
    }

    func replace(_ data: Data, for item: StoredItem) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard entries[item] != nil else { return false }
        entries[item]?.data = data
        return true
    }

    func copy(_ item: StoredItem) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if failCopies { throw SecureStoreError.unavailable }
        guard let entry = entries[item] else { return nil }
        if cancelProtectedReads, entry.protection == .userPresence { throw SecureStoreError.cancelled }
        return entry.data
    }

    func delete(_ item: StoredItem) throws {
        lock.lock()
        defer { lock.unlock() }
        entries[item] = nil
    }

    func accounts(in collection: StoredItem.Collection) throws -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return entries.keys.filter { $0.collection == collection }.map(\.account)
    }

    // Test access

    var snapshot: [StoredItem: Entry] {
        lock.lock()
        defer { lock.unlock() }
        return entries
    }

    func set(_ data: Data, for item: StoredItem, protection: ItemProtection = .whenUnlocked) {
        lock.lock()
        defer { lock.unlock() }
        entries[item] = Entry(data: data, protection: protection)
    }
}

/// A stand-in for the Secure Enclave, backed by in-memory ML-DSA-65 keys.
struct FakeSecureEnclave: SecureEnclaveSigning {
    enum Behaviour: Sendable {
        case available
        /// This Mac's Secure Enclave can't make an ML-DSA-65 key.
        case unavailable
        /// Keys are made, but the user cancels the prompt when signing.
        case cancelsSigning
    }

    static let handlePrefix = Array("FAKE-SE-HANDLE:".utf8)

    let behaviour: Behaviour

    func createKey() throws -> (handle: Data, signer: any MessageSigner) {
        guard behaviour != .unavailable else { throw SecureEnclaveUnavailable() }
        let key = try MLDSA65.PrivateKey()
        return (Data(Self.handlePrefix) + key.integrityCheckedRepresentation, signer(for: key))
    }

    func loadKey(handle: Data) throws -> any MessageSigner {
        let bytes = [UInt8](handle)
        guard bytes.starts(with: Self.handlePrefix) else { throw SecureStoreError.unavailable }
        return signer(for: try MLDSA65.PrivateKey(
            integrityCheckedRepresentation: Data(bytes.dropFirst(Self.handlePrefix.count))))
    }

    private func signer(for key: MLDSA65.PrivateKey) -> any MessageSigner {
        behaviour == .cancelsSigning ? CancellingSigner(publicKey: key.publicKey) : SoftwareSigner(key: key)
    }
}

/// Throws what LocalAuthentication throws when the user dismisses the prompt.
struct CancellingSigner: MessageSigner {
    let publicKey: MLDSA65.PublicKey

    func signature(for message: [UInt8]) throws -> [UInt8] {
        throw NSError(domain: "com.apple.LocalAuthentication", code: -2)
    }
}

/// A store with fakes, plus handles on them.
struct TestKeyring {
    let items = InMemoryItemStore()
    let store: IdentityStore

    init(secureEnclave: FakeSecureEnclave.Behaviour = .available) {
        store = IdentityStore(items: items, secureEnclave: FakeSecureEnclave(behaviour: secureEnclave))
    }
}

/// A fresh, valid public identity (someone else's), with its private keys.
struct SomeoneElse {
    let xwing: XWingMLKEM768X25519.PrivateKey
    let mldsa: MLDSA65.PrivateKey
    let publicIdentity: PublicIdentity

    init(name: String? = "Bob") throws {
        xwing = try XWingMLKEM768X25519.PrivateKey.generate()
        mldsa = try MLDSA65.PrivateKey()
        var raw = RawPQID(
            encryptionKey: [UInt8](xwing.publicKey.rawRepresentation),
            signingKey: [UInt8](mldsa.publicKey.rawRepresentation))
        raw.nameBytes = Array((name ?? "").utf8)
        publicIdentity = try PQIDCodec.decode(try raw.signed(by: mldsa))
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
