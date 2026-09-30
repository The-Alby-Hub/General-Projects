import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Deterministic PRNG (SplitMix64) so fuzz and data tests are reproducible.
/// Never used for anything cryptographic.
struct SeededGenerator: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func bytes(_ count: Int) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(count + 8)
        while result.count < count {
            withUnsafeBytes(of: next()) { result.append(contentsOf: $0) }
        }
        return Array(result.prefix(count))
    }
}

/// Wraps a source and records the largest read request, to prove streaming.
final class CountingSource: ByteSource {
    private let base: any ByteSource
    private(set) var largestRequest = 0
    private(set) var bytesRead = 0

    init(_ base: any ByteSource) {
        self.base = base
    }

    func read(maxCount: Int) throws -> [UInt8] {
        largestRequest = max(largestRequest, maxCount)
        let piece = try base.read(maxCount: maxCount)
        bytesRead += piece.count
        return piece
    }
}

enum Fixtures {
    static let chunk = FormatV1.chunkSize
    static let sealedChunk = FormatV1.sealedChunkSize

    static func randomKey() -> SymmetricKey {
        SymmetricKey(size: .bits256)
    }

    static let passwordParameters = FileHeader.ModeParameters.password(
        .init(argon2Salt: [UInt8](repeating: 0x44, count: 16), opsLimit: 4, memLimit: 1 << 30))

    /// Structurally valid recipient parameters. The stanza contents are filler:
    /// HPKE wrapping arrives in Phase 5, so here they're just header bytes.
    static func recipientParameters(count: Int) -> FileHeader.ModeParameters {
        .recipients(.init(
            senderKeyID: [UInt8](repeating: 0x55, count: 32),
            stanzas: (0 ..< count).map { i in
                .init(
                    keyID: [UInt8](repeating: UInt8(i), count: 31) + [0xA0],
                    encapsulatedKey: [UInt8](repeating: 0x66, count: FormatV1.xwingEncapsulatedKeySize),
                    wrappedDataKey: [UInt8](repeating: 0x77, count: FormatV1.wrappedDataKeySize))
            }))
    }

    static func header(parameters: FileHeader.ModeParameters = passwordParameters) -> FileHeader {
        FileHeader(
            chunkSize: UInt32(FormatV1.chunkSize),
            hkdfSalt: [UInt8](repeating: 0x11, count: 32),
            baseNonce: [UInt8](repeating: 0x22, count: 12),
            commitment: [UInt8](repeating: 0x33, count: 32),
            parameters: parameters)
    }

    static func pattern(_ count: Int, seed: UInt64 = 1) -> [UInt8] {
        var rng = SeededGenerator(seed: seed)
        return rng.bytes(count)
    }
}

/// Seals `plaintext` in memory and returns the complete `.enc` bytes.
func sealBytes(
    _ plaintext: [UInt8],
    ikm: SymmetricKey,
    filename: String? = "file.bin",
    parameters: FileHeader.ModeParameters = Fixtures.passwordParameters,
    trailer: [UInt8] = []
) throws -> [UInt8] {
    let sink = MemorySink()
    _ = try StreamSealer.seal(
        ikm: ikm, parameters: parameters, filename: filename,
        from: MemorySource(plaintext), to: sink)
    return sink.bytes + trailer
}

struct Opened {
    let plaintext: [UInt8]
    let summary: OpenSummary
}

/// Parses and opens complete `.enc` bytes in memory.
func openBytes(
    _ file: [UInt8],
    ikm: SymmetricKey,
    trailerLength: Int = 0,
    onChunkOpen: (() -> Void)? = nil
) throws -> Opened {
    let source = MemorySource(file)
    let (header, raw) = try HeaderCodec.read(from: source)
    let sink = MemorySink()
    let summary = try StreamOpener.open(
        ikm: ikm, header: header, rawHeader: raw, body: source,
        trailerLength: trailerLength, to: sink, onChunkOpen: onChunkOpen)
    return Opened(plaintext: sink.bytes, summary: summary)
}

/// Asserts that `body` fails with a `CoreFailure` (optionally a specific reason),
/// and that the public error it maps to is the single generic message.
func assertCoreFailure(
    _ expected: CoreFailure.Reason? = nil,
    _ message: String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> Void
) {
    do {
        try body()
        XCTFail("expected failure \(expected.map { $0.rawValue } ?? "") \(message)", file: file, line: line)
    } catch let failure as CoreFailure {
        if let expected {
            XCTAssertEqual(failure.reason, expected, message, file: file, line: line)
        }
        XCTAssertEqual(
            publicDecryptionError(failure).errorDescription, DecryptionFailed.message,
            file: file, line: line)
    } catch {
        XCTFail("unexpected error type \(type(of: error)) \(message)", file: file, line: line)
    }
}

/// Byte ranges of the encoded header, for targeted tampering.
enum HeaderOffsets {
    static let version = 5
    static let mode = 7
    static let headerLength = 8
    static let chunkSize = 12
    static let hkdfSalt = 16
    static let baseNonce = 48
    static let commitment = 60
    static let modeParameters = 92
    // Password mode
    static let opsLimit = 108
    static let memLimit = 116
    // Recipient mode
    static let recipientCount = 124
    static let firstStanza = 125
    static let firstEncLength = 125 + 32
}

extension Array where Element == UInt8 {
    /// Overwrites `count` bytes at `offset` with a big-endian integer.
    mutating func put<T: FixedWidthInteger>(_ value: T, at offset: Int) {
        withUnsafeBytes(of: value.bigEndian) { raw in
            for (i, byte) in raw.enumerated() {
                self[offset + i] = byte
            }
        }
    }
}
