#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Per-chunk nonce and associated data (FORMAT.md §5.2 and §5.3).
enum ChunkCrypto {
    /// nonce(i) = baseNonce XOR (0x00000000 ‖ UInt64BE(i)).
    ///
    /// Unique within a file because the index is; unique across files because the
    /// file key is (fresh HKDF salt). The random base nonce is defence in depth.
    static func nonce(base: [UInt8], index: UInt64) throws -> AES.GCM.Nonce {
        guard base.count == FormatV1.baseNonceSize else {
            throw CoreFailure(.fieldSizeMismatch)
        }
        var bytes = base
        for i in 0 ..< 8 {
            bytes[4 + i] ^= UInt8(truncatingIfNeeded: index >> UInt64(56 - 8 * i))
        }
        return try AES.GCM.Nonce(data: bytes)
    }

    /// aad(i) = headerHash ‖ UInt64BE(i) ‖ finalFlag.
    ///
    /// Binds each chunk to this file's exact header, to its position, and to
    /// whether it is last. That detects header edits, reordering, truncation at a
    /// chunk boundary and appended data.
    static func associatedData(headerHash: [UInt8], index: UInt64, isFinal: Bool) -> [UInt8] {
        var w = ByteWriter()
        w.appendBytes(headerHash)
        w.appendInteger(index)
        w.appendInteger(UInt8(isFinal ? 1 : 0))
        return w.bytes
    }
}
