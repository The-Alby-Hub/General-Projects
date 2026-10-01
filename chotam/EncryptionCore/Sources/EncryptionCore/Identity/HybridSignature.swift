#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The hybrid signature Chotam uses everywhere it signs: Ed25519 ‖ ML-DSA-65, both over
/// the same message (SECURITY.md §5.9, D17).
///
/// A forger has to break **both** schemes: Ed25519 (classical, mature) and ML-DSA-65
/// (post-quantum, FIPS 204). That also covers an implementation bug in either one.
/// Every message starts with a Chotam domain label, so a signature made for one
/// purpose (a `.pqid`, a file) can't be replayed as another.
///
/// - ML-DSA-65 is pure FIPS 204 with an empty context string.
/// - Signatures may be randomised (CryptoKit may hedge either scheme); any valid
///   signature verifies.
enum HybridSignature {
    /// `Ed25519.sign(message) (64) ‖ ML-DSA-65.sign(message) (3309)`.
    static func sign(
        _ message: [UInt8], ed25519: Curve25519.Signing.PrivateKey, mldsa: MLDSA65.PrivateKey
    ) throws -> [UInt8] {
        let classical = [UInt8](try ed25519.signature(for: message))
        let postQuantum = [UInt8](try mldsa.signature(for: message))
        guard classical.count == IdentityFormat.ed25519SignatureSize,
              postQuantum.count == IdentityFormat.mldsa65SignatureSize
        else { throw CoreFailure(.unexpected) }
        return classical + postQuantum
    }

    /// True only if the signature has the exact size and **both** halves verify.
    static func isValid(
        _ signature: [UInt8], for message: [UInt8],
        ed25519: Curve25519.Signing.PublicKey, mldsa: MLDSA65.PublicKey
    ) -> Bool {
        guard signature.count == IdentityFormat.hybridSignatureSize else { return false }
        let classical = signature.prefix(IdentityFormat.ed25519SignatureSize)
        let postQuantum = signature.suffix(IdentityFormat.mldsa65SignatureSize)
        // Both are always checked; `&&` short-circuiting only skips work, not a check
        // that could change the answer.
        return ed25519.isValidSignature(classical, for: message)
            && mldsa.isValidSignature(postQuantum, for: message)
    }
}
