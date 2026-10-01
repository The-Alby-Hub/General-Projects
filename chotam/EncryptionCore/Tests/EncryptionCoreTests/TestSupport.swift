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
            Swift.withUnsafeBytes(of: next()) { result.append(contentsOf: $0) }
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

    /// Structurally valid recipient parameters, with filler stanza contents.
    /// They only exercise the header codec; real stanzas are in `RecipientModeTests`.
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
    static let version = 6
    static let mode = 8
    static let headerLength = 9
    static let chunkSize = 13
    static let hkdfSalt = 17
    static let baseNonce = 49
    static let commitment = 61
    static let modeParameters = 93
    // Password mode
    static let opsLimit = 109
    static let memLimit = 117
    // Recipient mode
    static let recipientCount = 125
    static let firstStanza = 126
    static let firstEncLength = 126 + 32
}

extension Array where Element == UInt8 {
    /// Overwrites `count` bytes at `offset` with a big-endian integer.
    mutating func put<T: FixedWidthInteger>(_ value: T, at offset: Int) {
        Swift.withUnsafeBytes(of: value.bigEndian) { raw in
            for (i, byte) in raw.enumerated() {
                self[offset + i] = byte
            }
        }
    }
}

// MARK: Password mode

enum PasswordFixtures {
    /// Accepted by the policy (28 characters, no patterns).
    static let password = "correct horse battery staple"
    /// The cheapest cost v1 accepts (ops 3, 256 MiB), so tests stay fast.
    static let fast = Argon2id.Cost.minimumAccepted
}

/// Encrypts `plaintext` in password mode and returns the complete `.enc` bytes.
func passwordSeal(
    _ plaintext: [UInt8],
    password: String = PasswordFixtures.password,
    filename: String? = "file.bin",
    cost: Argon2id.Cost = PasswordFixtures.fast
) throws -> [UInt8] {
    let sink = MemorySink()
    try PasswordMode.encrypt(
        password: password, filename: filename,
        from: MemorySource(plaintext), to: sink, cost: cost)
    return sink.bytes
}

/// Opens password-mode bytes, throwing the precise internal reason.
func passwordOpen(
    _ file: [UInt8],
    password: String = PasswordFixtures.password,
    onDeriveKey: (() -> Void)? = nil
) throws -> (plaintext: [UInt8], filename: String?) {
    let sink = MemorySink()
    let filename = try PasswordMode.open(
        password: password, from: MemorySource(file), to: sink, onDeriveKey: onDeriveKey)
    return (sink.bytes, filename)
}

/// Reads a golden file from `Tests/EncryptionCoreTests/Vectors/` by path.
func vector(_ name: String) throws -> [UInt8] {
    let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("Vectors")
        .appendingPathComponent(name)
    return [UInt8](try Data(contentsOf: url))
}

/// Streams `count` bytes of the pattern `i % 251` without holding them in memory.
final class PatternSource: ByteSource {
    /// One period-aligned block longer than any single request we make.
    private static let block: [UInt8] = (0 ..< 251 * 300).map { UInt8($0 % 251) }
    private let count: Int
    private var offset = 0

    init(count: Int) {
        self.count = count
    }

    func read(maxCount: Int) throws -> [UInt8] {
        let n = min(max(maxCount, 0), count - offset, Self.block.count - 251)
        let start = offset % 251
        defer { offset += n }
        return Array(Self.block[start ..< start + n])
    }

    /// SHA-256 of the whole pattern, computed the same streaming way.
    static func digest(count: Int) throws -> [UInt8] {
        let source = PatternSource(count: count)
        var hash = SHA256()
        while true {
            let piece = try source.read(maxCount: 1 << 16)
            if piece.isEmpty { break }
            hash.update(data: piece)
        }
        return Array(hash.finalize())
    }
}

/// Hashes everything written to it, so large outputs never sit in memory.
final class DigestSink: ByteSink {
    private var hash = SHA256()
    private(set) var count = 0

    func write(_ data: Data) throws {
        hash.update(data: data)
        count += data.count
    }

    func finalize() -> [UInt8] {
        Array(hash.finalize())
    }
}

// MARK: Files

/// A fresh folder per test, deleted afterwards, for tests through real files.
final class Scratch {
    let folder: URL

    init() throws {
        folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("chotam-files-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }

    func remove() {
        try? FileManager.default.removeItem(at: folder)
    }

    func url(_ path: String) -> URL {
        folder.appendingPathComponent(path, isDirectory: false)
    }

    @discardableResult
    func write(_ bytes: [UInt8], to path: String) throws -> URL {
        let url = self.url(path)
        try Data(bytes).write(to: url)
        return url
    }

    @discardableResult
    func makeFolder(_ path: String) throws -> URL {
        let url = folder.appendingPathComponent(path, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// Every file and folder inside (hidden ones included), with file contents. Two
    /// equal snapshots prove an operation left nothing behind and changed nothing.
    func snapshot() throws -> [String: [UInt8]] {
        var result: [String: [UInt8]] = [:]
        guard let walker = FileManager.default.enumerator(atPath: folder.path) else { return result }
        while let path = walker.nextObject() as? String {
            // Folders, and links to nothing, have no contents to compare.
            let data = try? Data(contentsOf: folder.appendingPathComponent(path))
            result[path] = data.map { [UInt8]($0) } ?? []
        }
        return result
    }
}

func readFile(_ url: URL) throws -> [UInt8] {
    [UInt8](try Data(contentsOf: url))
}

func fileExists(_ url: URL) -> Bool {
    FileManager.default.fileExists(atPath: url.path)
}

/// The permission bits of a file (e.g. 0o600).
func permissions(_ url: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return ((attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1) & 0o777
}

/// Records what `AtomicOutput` does, and can make it fail on purpose.
final class OutputProbe {
    struct SimulatedFailure: Error {}

    private(set) var tempFiles: [URL] = []
    /// Fail the write that would start at or after this many bytes.
    var failWriteAt: Int?
    var failAtCommit = false

    var hooks: AtomicOutput.Hooks {
        AtomicOutput.Hooks(
            onTempCreated: { [unowned self] url in tempFiles.append(url) },
            beforeWrite: { [unowned self] written in
                if let limit = failWriteAt, written >= limit { throw SimulatedFailure() }
            },
            beforeCommit: { [unowned self] in
                if failAtCommit { throw SimulatedFailure() }
            })
    }
}
