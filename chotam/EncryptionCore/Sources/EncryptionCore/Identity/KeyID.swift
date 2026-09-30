#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A 32-byte key ID as stored in recipient-mode headers (FORMAT.md §6.1).
///
/// `SHA-256(label ‖ raw public key)`. The label differs for encryption and signing
/// keys, so the two kinds of ID can never collide (SECURITY.md D3). Key IDs are
/// public: they appear in every recipient-mode header.
struct KeyID: Hashable, Sendable {
    let bytes: [UInt8]

    static func encryption(_ key: XWingMLKEM768X25519.PublicKey) -> KeyID {
        encryption(rawPublicKey: [UInt8](key.rawRepresentation))
    }

    static func signing(_ key: MLDSA65.PublicKey) -> KeyID {
        signing(rawPublicKey: [UInt8](key.rawRepresentation))
    }

    static func encryption(rawPublicKey: [UInt8]) -> KeyID {
        KeyID(bytes: labelledHash(IdentityFormat.encryptionKeyIDLabel, rawPublicKey))
    }

    static func signing(rawPublicKey: [UInt8]) -> KeyID {
        KeyID(bytes: labelledHash(IdentityFormat.signingKeyIDLabel, rawPublicKey))
    }

    /// Lowercase hex, used as the contact's Keychain account name.
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
