/// The short, human-comparable fingerprint of an identity (SECURITY.md D5).
///
/// ```
/// digest      = SHA-256("Chotam v1 identity fingerprint" ‖ X-Wing public key ‖ ML-DSA-65 public key)
/// fingerprint = Crockford base32 of digest[0 ..< 20]    (160 bits → 32 characters)
/// shown as      P6BC HMEY 9SAS BEA0 DGKS 1Y3H FDP9 VXBM
/// ```
///
/// - It covers **both** public keys: the user trusts both (files are encrypted to one,
///   signatures are checked with the other), so neither can be swapped unnoticed.
/// - It covers nothing else. The name and the self-signature are left out, so a
///   rename or a fresh signature never changes the fingerprint.
/// - 160 bits: a quantum second-preimage search (Grover) costs about 2^80.
///
/// To verify a contact, both people read all 8 groups aloud (for example on a call)
/// and compare every character. Comparing only part of it gives only part of the security.
public struct Fingerprint: Hashable, Sendable, CustomStringConvertible {
    /// 32 Crockford symbols, no separators.
    let symbols: String

    init(encryptionKey: [UInt8], signingKey: [UInt8]) {
        let digest = labelledHash(IdentityFormat.fingerprintLabel, encryptionKey, signingKey)
        symbols = Crockford.encode(Array(digest.prefix(IdentityFormat.fingerprintBytes)))
    }

    /// The 8 groups of 4 characters, in order. Number them in the UI ("group 3 of 8")
    /// so two people reading them aloud don't lose their place.
    public var groups: [String] {
        let characters = Array(symbols)
        return stride(from: 0, to: characters.count, by: IdentityFormat.fingerprintGroupLength).map {
            String(characters[$0 ..< $0 + IdentityFormat.fingerprintGroupLength])
        }
    }

    /// `P6BC HMEY 9SAS BEA0 DGKS 1Y3H FDP9 VXBM`
    public var description: String {
        groups.joined(separator: " ")
    }

    /// Whether `typed` is this fingerprint, e.g. as read out by the contact and typed in.
    ///
    /// Forgiving about form, strict about content: case, spaces, hyphens, and O/0,
    /// I/L/1 don't matter; all 32 characters must match.
    public func matches(_ typed: String) -> Bool {
        Crockford.normalise(typed) == symbols
    }
}
