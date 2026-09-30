import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Someone's public identity: an X-Wing encryption key and an ML-DSA-65 signing key,
/// as exchanged in a `.pqid` file or its Base64 string (FORMAT.md §9).
///
/// It holds public keys only. A value always comes from a strictly parsed, correctly
/// self-signed `.pqid`, so every `PublicIdentity` is well-formed. That says nothing
/// about *whose* it is: only comparing fingerprints does (SECURITY.md D5, D14).
public struct PublicIdentity: Hashable, Sendable {
    /// Compare this with the other person, e.g. over a call, before trusting the identity.
    public let fingerprint: Fingerprint
    /// The name its owner gave it. Untrusted text: a suggestion to prefill, and only
    /// ever shown; the user picks the contact's actual name.
    public let suggestedName: String?

    let encryptionKey: XWingMLKEM768X25519.PublicKey
    let signingKey: MLDSA65.PublicKey
    let encryptionKeyID: KeyID
    let signingKeyID: KeyID
    let encryptionKeyBytes: [UInt8]
    let signingKeyBytes: [UInt8]
    /// The exact, signed `.pqid` bytes it was parsed from.
    let encoded: [UInt8]

    /// Only `PQIDCodec.decode` calls this, after every check has passed.
    init(
        encryptionKey: XWingMLKEM768X25519.PublicKey, signingKey: MLDSA65.PublicKey,
        encryptionKeyBytes: [UInt8], signingKeyBytes: [UInt8],
        suggestedName: String?, encoded: [UInt8]
    ) {
        self.encryptionKey = encryptionKey
        self.signingKey = signingKey
        self.encryptionKeyBytes = encryptionKeyBytes
        self.signingKeyBytes = signingKeyBytes
        self.encryptionKeyID = KeyID.encryption(rawPublicKey: encryptionKeyBytes)
        self.signingKeyID = KeyID.signing(rawPublicKey: signingKeyBytes)
        self.fingerprint = Fingerprint(encryptionKey: encryptionKeyBytes, signingKey: signingKeyBytes)
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

    /// The `.pqid` file contents. Public keys, name and self-signature only.
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

    /// Two values are the same identity when both keys match. The name and the
    /// signature bytes don't matter (ML-DSA signatures are randomised).
    public static func == (lhs: PublicIdentity, rhs: PublicIdentity) -> Bool {
        lhs.encryptionKeyID == rhs.encryptionKeyID && lhs.signingKeyID == rhs.signingKeyID
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(encryptionKeyID)
        hasher.combine(signingKeyID)
    }

    /// Whether the two share either key. Two different contacts must never do this:
    /// it would let one key stand in for the other's (SECURITY.md D14).
    func sharesKey(with other: PublicIdentity) -> Bool {
        encryptionKeyID == other.encryptionKeyID || signingKeyID == other.signingKeyID
    }
}
