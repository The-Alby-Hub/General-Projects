import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// What the sealer produced. Recipient mode signs these values (FORMAT.md §6.3).
struct SealSummary {
    let headerHash: [UInt8]
    let chunkCount: UInt64
    /// SHA-256 over every sealed chunk (ciphertext ‖ tag) in order (FORMAT.md §6.3).
    let ciphertextDigest: [UInt8]
}

/// Streaming AES-256-GCM encryption with key commitment (FORMAT.md §4 and §5).
///
/// Memory use is bounded by two chunks (64 KiB each), whatever the file size.
/// The salt, base nonce and file key are generated inside, so callers never
/// handle nonces, salts or derived keys.
enum StreamSealer {
    /// - Parameter prepareHeader: Recipient mode only. Called with the complete header
    ///   (salt, nonce and commitment filled in) before it is encoded, to replace the
    ///   placeholder stanzas with the wrapped Data Key: the wrap context covers the
    ///   commitment, so the stanzas can only be made once it exists (FORMAT.md §6.2).
    static func seal(
        ikm: SymmetricKey,
        parameters: FileHeader.ModeParameters,
        filename: String?,
        from source: any ByteSource,
        to sink: any ByteSink,
        prepareHeader: ((inout FileHeader) throws -> Void)? = nil
    ) throws -> SealSummary {
        // Fresh random salt per file → a unique file key per file (no key reuse).
        let hkdfSalt = SecureRandom.bytes(FormatV1.hkdfSaltSize)
        let baseNonce = SecureRandom.bytes(FormatV1.baseNonceSize)
        let keys = try KeySchedule.derive(ikm: ikm, hkdfSalt: hkdfSalt)

        var header = FileHeader(
            chunkSize: UInt32(FormatV1.chunkSize),
            hkdfSalt: hkdfSalt,
            baseNonce: baseNonce,
            commitment: keys.commitment,
            parameters: parameters
        )
        try prepareHeader?(&header)
        let rawHeader = try HeaderCodec.encode(header)
        let headerHash = Array(SHA256.hash(data: rawHeader))
        let plaintext = PrefixedSource(
            prefix: try MetadataRecord.encode(filename: filename),
            base: source
        )

        try sink.write(Data(rawHeader))

        var digest = SHA256()
        var index: UInt64 = 0
        var current = try plaintext.readFully(FormatV1.chunkSize)
        var next: [UInt8] = []
        // Wiped on every way out, including a failed write or a cancellation.
        defer {
            Wipe.bytes(&current)
            Wipe.bytes(&next)
        }

        while true {
            // One-chunk lookahead: a chunk is final exactly when nothing follows it.
            // A short chunk means the source ended, so no lookahead is needed.
            if current.count == FormatV1.chunkSize {
                next = try plaintext.readFully(FormatV1.chunkSize)
            }
            let isFinal = next.isEmpty

            let sealed = try AES.GCM.seal(
                current,
                using: keys.fileKey,
                nonce: ChunkCrypto.nonce(base: baseNonce, index: index),
                authenticating: ChunkCrypto.associatedData(
                    headerHash: headerHash, index: index, isFinal: isFinal)
            )
            Wipe.bytes(&current)

            digest.update(data: sealed.ciphertext)
            digest.update(data: sealed.tag)
            try sink.write(sealed.ciphertext)
            try sink.write(sealed.tag)

            if isFinal {
                return SealSummary(
                    headerHash: headerHash,
                    chunkCount: index + 1,
                    ciphertextDigest: Array(digest.finalize())
                )
            }

            index += 1
            guard index < FormatV1.maxChunkCount else {
                throw CoreFailure(.tooManyChunks)
            }
            // Swap rather than assign, so `current` never shares storage with
            // `next` and each wipe hits the only copy.
            swap(&current, &next)
            next.removeAll(keepingCapacity: false)
        }
    }
}
