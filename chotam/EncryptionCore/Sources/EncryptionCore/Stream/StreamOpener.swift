import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// What the opener verified. Recipient mode (Phase 5b) checks the signature in
/// `trailer` against `headerHash`, `ciphertextDigest` and `chunkCount`.
struct OpenSummary {
    let filename: String?
    let headerHash: [UInt8]
    let chunkCount: UInt64
    let ciphertextDigest: [UInt8]
    let trailer: [UInt8]
}

/// Streaming AES-256-GCM decryption (FORMAT.md §4.2, §5).
///
/// Plaintext is written to `sink` only after its own chunk authenticates. It
/// isn't yet proven that later chunks (or the signature) are intact, so the
/// file processor (`AtomicOutput`) points `sink` at a temp file that's only moved into
/// place after `open` returns successfully.
enum StreamOpener {
    /// - Parameters:
    ///   - header: The parsed header, from `HeaderCodec.read(from:)`.
    ///   - rawHeader: The header bytes exactly as read from the file.
    ///   - source: Positioned at the first byte after the header.
    ///   - trailerLength: 0 in password mode; the signature size in recipient mode.
    ///   - onChunkOpen: Test hook, called before each AES-GCM open attempt.
    static func open(
        ikm: SymmetricKey,
        header: FileHeader,
        rawHeader: [UInt8],
        body source: any ByteSource,
        trailerLength: Int,
        to sink: any ByteSink,
        onChunkOpen: (() -> Void)? = nil
    ) throws -> OpenSummary {
        let keys = try KeySchedule.derive(ikm: ikm, hkdfSalt: header.hkdfSalt)

        // Key commitment is checked before any chunk is touched. A mismatch means
        // this IKM isn't the one the file was made with, so stop. This also rules
        // out a file crafted to decrypt differently under different keys.
        guard ConstantTime.equals(keys.commitment, header.commitment) else {
            throw CoreFailure(.commitmentMismatch)
        }

        let headerHash = Array(SHA256.hash(data: rawHeader))
        var reader = ChunkReader(source: source, trailerLength: trailerLength)
        var digest = SHA256()
        var filename: String?
        var index: UInt64 = 0

        while true {
            guard index < FormatV1.maxChunkCount else {
                throw CoreFailure(.tooManyChunks)
            }
            let (sealedChunk, isFinal) = try reader.next()
            digest.update(data: sealedChunk)

            onChunkOpen?()
            var plaintext: Data
            do {
                let box = try AES.GCM.SealedBox(
                    nonce: ChunkCrypto.nonce(base: header.baseNonce, index: index),
                    ciphertext: sealedChunk.prefix(sealedChunk.count - FormatV1.tagSize),
                    tag: sealedChunk.suffix(FormatV1.tagSize)
                )
                plaintext = try AES.GCM.open(
                    box,
                    using: keys.fileKey,
                    authenticating: ChunkCrypto.associatedData(
                        headerHash: headerHash, index: index, isFinal: isFinal)
                )
            } catch {
                throw CoreFailure(.chunkAuthenticationFailed)
            }

            // Our encoder only emits an empty chunk when the whole stream is
            // empty. Reject any other encoding so each plaintext has one ciphertext form.
            if isFinal, plaintext.isEmpty, index > 0 {
                throw CoreFailure(.nonCanonicalFinalChunk)
            }

            if index == 0 {
                var first = [UInt8](plaintext)
                Wipe.data(&plaintext)
                defer { Wipe.bytes(&first) }
                let record = try MetadataRecord.decode(first)
                filename = record.filename
                if record.contentOffset < first.count {
                    try sink.write(Data(first[record.contentOffset...]))
                }
            } else {
                try sink.write(plaintext)
                Wipe.data(&plaintext)
            }

            if isFinal {
                return OpenSummary(
                    filename: filename,
                    headerHash: headerHash,
                    chunkCount: index + 1,
                    ciphertextDigest: Array(digest.finalize()),
                    trailer: reader.trailer
                )
            }
            index += 1
        }
    }
}

/// Splits the body into sealed chunks without trusting any length field
/// (FORMAT.md §5.4).
///
/// With S = sealed chunk size and T = trailer size: while more than S + T bytes
/// remain, the next S bytes are a non-final chunk. Otherwise input has ended,
/// and what remains is the final chunk followed by exactly T trailer bytes.
/// Never requests more than S + T + 1 bytes at once.
struct ChunkReader {
    private let source: any ByteSource
    private let trailerLength: Int
    private var buffer: [UInt8] = []
    private var reachedEnd = false
    private(set) var trailer: [UInt8] = []

    init(source: any ByteSource, trailerLength: Int) {
        self.source = source
        self.trailerLength = max(trailerLength, 0)
    }

    mutating func next() throws -> (sealed: [UInt8], isFinal: Bool) {
        let full = FormatV1.sealedChunkSize
        let lookahead = full + trailerLength + 1

        while buffer.count < lookahead, !reachedEnd {
            let piece = try source.read(maxCount: lookahead - buffer.count)
            if piece.isEmpty {
                reachedEnd = true
            } else {
                buffer.append(contentsOf: piece)
            }
        }

        if buffer.count >= lookahead {
            // More than a full chunk plus the trailer remains: not the last chunk.
            let chunk = Array(buffer[0 ..< full])
            buffer.removeFirst(full)
            return (chunk, false)
        }

        // End of input. buffer.count ≤ full + trailerLength here.
        let bodyBytes = buffer.count - trailerLength
        guard bodyBytes >= FormatV1.tagSize else {
            throw CoreFailure(.truncatedBody)
        }
        let chunk = Array(buffer[0 ..< bodyBytes])
        trailer = Array(buffer[bodyBytes...])
        buffer = []
        return (chunk, true)
    }
}
