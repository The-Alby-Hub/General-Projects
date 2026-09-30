#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Your own identity: an X-Wing keypair (encryption) and an ML-DSA-65 keypair (signing).
///
/// This value holds only public information. The private keys stay in the Secure
/// Enclave or the Keychain and are reached only for the duration of an operation
/// (Phase 5: signing a file, opening a file sent to you). They are never exported,
/// logged or written anywhere else (SECURITY.md D7).
public struct Identity: Sendable {
    /// Your public identity: share `exportedData` or `exportedString` with contacts.
    public let publicIdentity: PublicIdentity
    /// Where the ML-DSA-65 signing key lives. Always `.secureEnclave` unless this
    /// Mac's Secure Enclave couldn't create the key when the identity was made.
    public let signingKeyStorage: KeyStorage
    /// Where the X-Wing decryption key lives: always the Keychain, because the
    /// Secure Enclave doesn't support X-Wing (its X25519 half).
    public var encryptionKeyStorage: KeyStorage { .keychain }

    let store: IdentityStore

    /// The name you gave it (it is in your `.pqid`, so contacts see it as a suggestion).
    public var name: String { publicIdentity.suggestedName ?? "" }

    /// Read your fingerprint to a contact so they can mark you as verified.
    public var fingerprint: Fingerprint { publicIdentity.fingerprint }

    // MARK: Phase 5

    /// The signing key, opened for one operation. With the Secure Enclave, each
    /// signature asks for Touch ID or the login password; with the Keychain
    /// fallback, loading the key does.
    func signer() throws(IdentityError) -> any MessageSigner {
        try store.signer(for: self)
    }

    /// The X-Wing private key, for `HPKE.Recipient`. Loading it asks for Touch ID or
    /// the login password. Callers keep it only for the one operation.
    func decryptionKey() throws(IdentityError) -> XWingMLKEM768X25519.PrivateKey {
        try store.decryptionKey(for: self)
    }
}

/// Someone you exchange files with.
///
/// A contact starts **unverified**. Mark it verified only after you and they have
/// compared the whole fingerprint over a channel you trust (in person, a call where
/// you recognise their voice). Encrypting to an unverified contact needs an explicit
/// confirmation (`RecipientList`).
public struct Contact: Hashable, Sendable, Identifiable {
    /// The name you gave this contact. Only you see it.
    public let name: String
    public let isVerified: Bool
    public let publicIdentity: PublicIdentity

    public var fingerprint: Fingerprint { publicIdentity.fingerprint }

    /// Stable while the contact exists (derived from its encryption key ID).
    public var id: String { publicIdentity.encryptionKeyID.hex }
}
