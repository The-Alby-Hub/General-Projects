/// Fixed parameters of format version 1 (see FORMAT.md). Anything a file
/// declares that doesn't match these is rejected before any key derivation.
enum FormatV1 {
    static let magic: [UInt8] = Array("PQENC".utf8)
    static let version: UInt16 = 1

    /// magic(5) + version(2) + mode(1) + headerLength(4)
    static let preludeSize = 12
    /// chunkSize(4) + hkdfSalt(32) + baseNonce(12) + commitment(32)
    static let commonFieldsSize = 80
    /// Hard ceiling, checked before the rest of the header is read, so a hostile
    /// length field can never cause a large allocation.
    static let maxHeaderLength = 128 * 1024

    // Body. 64 KiB chunks keep memory use flat for files of any size.
    static let chunkSize = 64 * 1024
    static let tagSize = 16
    static let sealedChunkSize = chunkSize + tagSize
    /// Far above any real file (256 TiB) but keeps the nonce counter well-defined.
    static let maxChunkCount: UInt64 = 1 << 32

    static let hkdfSaltSize = 32
    static let baseNonceSize = 12  // 96-bit GCM nonce
    static let commitmentSize = 32
    static let ikmSize = 32  // Data Key or Argon2id output: always 256 bits
    static let keyIDSize = 32  // SHA-256

    // Password mode. Encryption writes libsodium's SENSITIVE preset (ops 4, 1 GiB).
    // Decryption accepts only this window, so a crafted file can't demand
    // gigabytes of RAM or minutes of CPU before anything is authenticated.
    static let argon2SaltSize = 16
    static let argon2OpsLimitRange: ClosedRange<UInt64> = 3...8
    static let argon2MemLimitRange: ClosedRange<UInt64> = (256 << 20)...(1 << 30)
    static let passwordParametersSize = argon2SaltSize + 8 + 8

    // Recipient mode.
    static let maxRecipients = 64
    /// X-Wing ciphertext: ML-KEM-768 ciphertext (1088) + X25519 share (32).
    /// Rechecked against the macOS 26 SDK in Phase 5.
    static let xwingEncapsulatedKeySize = 1120
    /// 32-byte Data Key + 16-byte AES-GCM tag.
    static let wrappedDataKeySize = 48
    static let recipientStanzaSize = keyIDSize + 2 + xwingEncapsulatedKeySize + 2 + wrappedDataKeySize
    /// FIPS 204 ML-DSA-65 signature size. Rechecked against the SDK in Phase 5.
    static let mldsa65SignatureSize = 3309

    // Encrypted metadata record (FORMAT.md §3).
    static let maxFilenameBytes = 1024

    static let passwordHeaderLength = preludeSize + commonFieldsSize + passwordParametersSize

    static func recipientHeaderLength(count: Int) -> Int {
        preludeSize + commonFieldsSize + keyIDSize + 1 + count * recipientStanzaSize
    }
}
