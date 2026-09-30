import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Where a private key lives.
public enum KeyStorage: Sendable, Equatable {
    /// Inside the Secure Enclave. The key never exists in Chotam's memory; signing
    /// happens in the chip, after Touch ID or the login password.
    case secureEnclave
    /// In the Keychain, protected by Touch ID or the login password, on this Mac only.
    /// It is loaded into memory for each operation that uses it.
    case keychain
}

/// Something that signs with an identity's ML-DSA-65 key: a Secure Enclave key, or
/// a key loaded from the Keychain. Phase 5 signs files through this.
protocol MessageSigner {
    var publicKey: MLDSA65.PublicKey { get }
    /// FIPS 204 ML-DSA-65 with an empty context string. Domain separation is done
    /// by a label at the start of every message Chotam signs.
    func signature(for message: [UInt8]) throws -> [UInt8]
}

/// An ML-DSA-65 key held in memory (the Keychain fallback, and tests).
struct SoftwareSigner: MessageSigner {
    let key: MLDSA65.PrivateKey

    var publicKey: MLDSA65.PublicKey { key.publicKey }

    func signature(for message: [UInt8]) throws -> [UInt8] {
        [UInt8](try key.signature(for: message))
    }
}

/// Thrown by `SecureEnclaveSigning.createKey()` when this Mac's Secure Enclave can't
/// make an ML-DSA-65 key (no Secure Enclave, a virtual machine, older hardware).
/// It is the **only** error that makes Chotam fall back to the Keychain, and only
/// while creating an identity (SECURITY.md D7).
struct SecureEnclaveUnavailable: Error {}

/// The Secure Enclave, as far as identities need it. The real one is
/// `SystemSecureEnclave`; tests use a fake.
protocol SecureEnclaveSigning: Sendable {
    /// Creates a new ML-DSA-65 key inside the Secure Enclave, usable only after
    /// user presence. Returns its handle (an encrypted blob only this Mac's Secure
    /// Enclave can use) and a signer for it.
    func createKey() throws -> (handle: Data, signer: any MessageSigner)
    /// Reopens a key from its handle.
    func loadKey(handle: Data) throws -> any MessageSigner
}
