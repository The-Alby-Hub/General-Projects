#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Derives the per-file AES key and the key-commitment tag from the input
/// keying material (FORMAT.md §4).
enum KeySchedule {
    // Distinct HKDF `info` labels give independent outputs from one IKM, so the
    // public commitment tag reveals nothing about the file key.
    static let fileKeyInfo = Array("PQENC v1 file key".utf8)
    static let commitmentInfo = Array("PQENC v1 key commitment".utf8)

    struct Keys {
        /// AES-256-GCM key for this file's chunks. Stays inside `SymmetricKey`.
        let fileKey: SymmetricKey
        /// Public value stored in the header.
        let commitment: [UInt8]
    }

    /// - Parameters:
    ///   - ikm: The Data Key (recipient mode) or Argon2id output (password mode). Must be 256 bits.
    ///   - hkdfSalt: The file's random 32-byte salt. A fresh salt per file means the
    ///     file key is never reused, even when the IKM is (e.g. the same password).
    static func derive(ikm: SymmetricKey, hkdfSalt: [UInt8]) throws -> Keys {
        guard ikm.bitCount == FormatV1.ikmSize * 8 else {
            throw CoreFailure(.invalidKeyLength)
        }
        guard hkdfSalt.count == FormatV1.hkdfSaltSize else {
            throw CoreFailure(.fieldSizeMismatch)
        }
        let fileKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm, salt: hkdfSalt, info: fileKeyInfo,
            outputByteCount: 32)
        // Key commitment: AES-GCM alone lets one ciphertext decrypt validly under
        // two keys. This tag is derived from the same IKM and salt, so a header
        // commits to exactly one file key (HKDF-SHA256 collision resistance).
        let commitmentKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm, salt: hkdfSalt, info: commitmentInfo,
            outputByteCount: FormatV1.commitmentSize)
        let commitment = commitmentKey.withUnsafeBytes { Array($0) }
        return Keys(fileKey: fileKey, commitment: commitment)
    }
}
