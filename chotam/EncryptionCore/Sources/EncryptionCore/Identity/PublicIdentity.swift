import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Someone's public identity: an X-Wing encryption key and a hybrid signing key
/// (ML-DSA-65 + Ed25519), as exchanged in a `.pqid` file or its Base64 string
/// (FORMAT.md §9).
///
/// It holds public data only: the keys, the public parameters for re-deriving the
/// identity from its owner's passphrase, a name and a self-signature. A value always comes from a strictly parsed, correctly
/// self-signed `.pqid`, so every `PublicIdentity` is well-formed. That says nothing
/// about *whose* it is: only comparing fingerprints does (SECURITY.md D5, D14).
public struct PublicIdentity: Hashable, Sendable {
    /// Compare this with the other person, e.g. over a call, before trusting the identity.
    public let fingerprint: Fingerprint
    /// The name its owner gave it. Untrusted text: a suggestion to prefill, and only
    /// ever shown; the user picks the contact's actual name.
    public let suggestedName: String?

    let encryptionKey: XWingMLKEM768X25519.PublicKey
    let mldsaKey: MLDSA65.PublicKey
    let ed25519Key: Curve25519.Signing.PublicKey
    let encryptionKeyID: KeyID
    /// Covers both signing keys (FORMAT.md §6.1).
    let signingKeyID: KeyID
    let encryptionKeyBytes: [UInt8]
    let mldsaKeyBytes: [UInt8]
    let ed25519KeyBytes: [UInt8]
    /// How the owner's passphrase becomes these keys (FORMAT.md §9.6). Public.
    let kdf: IdentityKDF
    /// The exact, signed `.pqid` bytes it was parsed from.
    let encoded: [UInt8]

    /// Whether unlocking this identity needs a key file as well as the passphrase
    /// (FORMAT.md §9.6). Public data from the `.pqid`, so the unlock screen can ask for
    /// the file before the identity is unlocked.
    public var requiresKeyFile: Bool { kdf.requiresKeyFile }

    /// Only `PQIDCodec.decode` calls this, after every check has passed.
    init(
        encryptionKey: XWingMLKEM768X25519.PublicKey, mldsaKey: MLDSA65.PublicKey,
        ed25519Key: Curve25519.Signing.PublicKey,
        encryptionKeyBytes: [UInt8], mldsaKeyBytes: [UInt8], ed25519KeyBytes: [UInt8],
        kdf: IdentityKDF, suggestedName: String?, encoded: [UInt8]
    ) {
        self.encryptionKey = encryptionKey
        self.mldsaKey = mldsaKey
        self.ed25519Key = ed25519Key
        self.encryptionKeyBytes = encryptionKeyBytes
        self.mldsaKeyBytes = mldsaKeyBytes
        self.ed25519KeyBytes = ed25519KeyBytes
        self.encryptionKeyID = KeyID.encryption(rawPublicKey: encryptionKeyBytes)
        self.signingKeyID = KeyID.signing(mldsaKey: mldsaKeyBytes, ed25519Key: ed25519KeyBytes)
        self.fingerprint = Fingerprint(
            encryptionKey: encryptionKeyBytes, mldsaKey: mldsaKeyBytes, ed25519Key: ed25519KeyBytes)
        self.kdf = kdf
        self.suggestedName = suggestedName
        self.encoded = encoded
    }

    // MARK: Import

    /// Parses the contents of a `.pqid` file. Files over 8 KiB are refused unread.
    public init(importing data: Data) throws(IdentityError) {
        do {
            self = try PQIDCodec.decode([UInt8](data.prefix(IdentityFormat.pqidMaxFileSize + 1)))
        } catch {
            throw identityError(for: error, parsing: true)
        }
    }

    /// Parses a copied Base64 string. Spaces and line breaks are ignored.
    public init(importingString string: String) throws(IdentityError) {
        do {
            self = try PQIDCodec.decode(string: string)
        } catch {
            throw identityError(for: error, parsing: true)
        }
    }

    // MARK: Export

    /// The `.pqid` file contents: public keys, KDF parameters, name and self-signature only.
    public var exportedData: Data {
        Data(encoded)
    }

    /// The same bytes as one line of standard Base64, for copy and paste.
    public var exportedString: String {
        Data(encoded).base64EncodedString()
    }

    /// The file extension for exported identities.
    public static let fileExtension = "pqid"

    // MARK: Identity

    /// Two values are the same identity when all keys match. The name and the
    /// signature bytes don't matter (signatures may be randomised).
    public static func == (lhs: PublicIdentity, rhs: PublicIdentity) -> Bool {
        lhs.encryptionKeyID == rhs.encryptionKeyID && lhs.signingKeyID == rhs.signingKeyID
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(encryptionKeyID)
        hasher.combine(signingKeyID)
    }

    /// Whether the two share any key, including either half of the signing key. Two
    /// different contacts must never do this: it would let one key stand in for the
    /// other's (SECURITY.md D14).
    func sharesKey(with other: PublicIdentity) -> Bool {
        encryptionKeyBytes == other.encryptionKeyBytes
            || mldsaKeyBytes == other.mldsaKeyBytes
            || ed25519KeyBytes == other.ed25519KeyBytes
    }
}
