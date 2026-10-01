#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A 32-byte key ID as stored in recipient-mode headers (FORMAT.md §6.1).
///
/// `SHA-256(label ‖ raw public key(s))`. The label differs for encryption and signing
/// keys, so the two kinds of ID can never collide (SECURITY.md D3). A signing key ID
/// covers both halves of the hybrid signing key: ML-DSA-65 ‖ Ed25519. Key IDs are
/// public: they appear in every recipient-mode header.
struct KeyID: Hashable, Sendable {
    let bytes: [UInt8]

    static func encryption(_ key: XWingMLKEM768X25519.PublicKey) -> KeyID {
        encryption(rawPublicKey: [UInt8](key.rawRepresentation))
    }

    static func signing(_ mldsa: MLDSA65.PublicKey, _ ed25519: Curve25519.Signing.PublicKey) -> KeyID {
        signing(mldsaKey: [UInt8](mldsa.rawRepresentation), ed25519Key: [UInt8](ed25519.rawRepresentation))
    }

    static func encryption(rawPublicKey: [UInt8]) -> KeyID {
        KeyID(bytes: labelledHash(IdentityFormat.encryptionKeyIDLabel, rawPublicKey))
    }

    /// Both keys have fixed sizes, so the concatenation is unambiguous.
    static func signing(mldsaKey: [UInt8], ed25519Key: [UInt8]) -> KeyID {
        KeyID(bytes: labelledHash(IdentityFormat.signingKeyIDLabel, mldsaKey, ed25519Key))
    }

    /// Lowercase hex, for display and debugging.
    var hex: String {
        bytes.map { byte in
            let digits = Array("0123456789abcdef")
            return String([digits[Int(byte >> 4)], digits[Int(byte & 0x0F)]])
        }.joined()
    }
}

/// `SHA-256(label ‖ part1 ‖ part2 ‖ …)`. Every input this is used for has a fixed
/// length per label, so plain concatenation is unambiguous.
func labelledHash(_ label: [UInt8], _ parts: [UInt8]...) -> [UInt8] {
    var hash = SHA256()
    hash.update(data: label)
    for part in parts {
        hash.update(data: part)
    }
    return Array(hash.finalize())
}
