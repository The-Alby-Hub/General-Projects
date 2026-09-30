#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Foundation
import Security

/// The real Secure Enclave (SECURITY.md D7).
///
/// CryptoKit on macOS 26 can keep ML-DSA-65 (and ML-KEM) keys in the Secure Enclave,
/// but not X-Wing, whose X25519 half the Secure Enclave doesn't support. So only the
/// signing key can live here.
struct SystemSecureEnclave: SecureEnclaveSigning {
    func createKey() throws -> (handle: Data, signer: any MessageSigner) {
        guard SecureEnclave.isAvailable else { throw SecureEnclaveUnavailable() }
        // Usable only while the Mac is unlocked, on this device, and only after
        // Touch ID or the login password, for every signature.
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error)
        else {
            _ = error?.takeRetainedValue()
            throw SecureStoreError.unavailable
        }
        let key: SecureEnclave.MLDSA65.PrivateKey
        do {
            // Creating the key doesn't prompt; using it does. So a failure here means
            // this Secure Enclave can't make the key, never that the user cancelled.
            key = try SecureEnclave.MLDSA65.PrivateKey(accessControl: access)
        } catch {
            DebugLog.record(.unexpected)
            throw SecureEnclaveUnavailable()
        }
        return (key.dataRepresentation, SecureEnclaveSigner(key: key))
    }

    func loadKey(handle: Data) throws -> any MessageSigner {
        SecureEnclaveSigner(key: try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: handle))
    }
}

/// An ML-DSA-65 key inside the Secure Enclave. `signature(for:)` shows the Touch ID
/// or password prompt; the private key never leaves the chip.
struct SecureEnclaveSigner: MessageSigner {
    let key: SecureEnclave.MLDSA65.PrivateKey

    var publicKey: MLDSA65.PublicKey { key.publicKey }

    func signature(for message: [UInt8]) throws -> [UInt8] {
        [UInt8](try key.signature(for: message))
    }
}
#endif
