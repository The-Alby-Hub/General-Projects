import XCTest
@testable import EncryptionCore

/// The parser must reject hostile bytes by throwing. A trap (crash) fails the
/// whole test run, so "the test finishes" is the property under test. Every
/// input is deterministic (seeded) so any failure is reproducible.
final class HeaderFuzzTests: XCTestCase {
    /// Calls both entry points. Any thrown error must be a `CoreFailure`.
    private func exercise(_ bytes: [UInt8], file: StaticString = #filePath, line: UInt = #line) {
        for attempt in [
            { _ = try HeaderCodec.decode(bytes) },
            { _ = try HeaderCodec.read(from: MemorySource(bytes)) },
        ] as [() throws -> Void] {
            do {
                try attempt()
            } catch is CoreFailure {
                // expected for almost all inputs
            } catch {
                XCTFail("non-CoreFailure error \(type(of: error))", file: file, line: line)
            }
        }
    }

    func testRandomBytes() {
        var rng = SeededGenerator(seed: 0xF022)
        for _ in 0 ..< 100_000 {
            let length = Int(rng.next() % 300)
            exercise(rng.bytes(length))
        }
    }

    /// Random bodies behind a valid prelude, so the fuzzer gets past the magic
    /// and version checks and exercises the field and stanza parsing.
    func testRandomBytesBehindValidPrelude() throws {
        var rng = SeededGenerator(seed: 0xBEEF)
        let passwordPrelude = Array(try HeaderCodec.encode(Fixtures.header()).prefix(12))
        let recipientPrelude = Array(try HeaderCodec.encode(
            Fixtures.header(parameters: Fixtures.recipientParameters(count: 1))).prefix(12))
        for i in 0 ..< 100_000 {
            let usePassword = i % 2 == 0
            let prelude = usePassword ? passwordPrelude : recipientPrelude
            let targetLength = usePassword ? 124 : 1329
            // Mostly exact length, sometimes off by a little.
            let jitter = Int(rng.next() % 5) - 2
            var bytes = prelude + rng.bytes(max(0, targetLength - 12 + (i % 7 == 0 ? jitter : 0)))
            // Make the fixed-size checks pass sometimes so deeper code runs.
            if bytes.count > 16, rng.next() % 2 == 0 {
                bytes.put(UInt32(FormatV1.chunkSize), at: HeaderOffsets.chunkSize)
            }
            if !usePassword, bytes.count > 160, rng.next() % 2 == 0 {
                bytes[HeaderOffsets.recipientCount] = 1
                bytes.put(UInt16(1120), at: HeaderOffsets.firstEncLength)
            }
            exercise(bytes)
        }
    }

    func testEveryTruncation() throws {
        for parameters in [Fixtures.passwordParameters, Fixtures.recipientParameters(count: 2)] {
            let bytes = try HeaderCodec.encode(Fixtures.header(parameters: parameters))
            for length in 0 ..< bytes.count {
                let prefix = Array(bytes.prefix(length))
                assertCoreFailure(nil, "prefix \(length)") { _ = try HeaderCodec.decode(prefix) }
                assertCoreFailure(nil, "prefix \(length)") { _ = try HeaderCodec.read(from: MemorySource(prefix)) }
            }
        }
    }

    func testSampledTruncationsOfLargestHeader() throws {
        let bytes = try HeaderCodec.encode(Fixtures.header(parameters: Fixtures.recipientParameters(count: 64)))
        var rng = SeededGenerator(seed: 64)
        for _ in 0 ..< 300 {
            let length = Int(rng.next() % UInt64(bytes.count))
            let prefix = Array(bytes.prefix(length))
            assertCoreFailure { _ = try HeaderCodec.read(from: MemorySource(prefix)) }
        }
    }

    /// Every single-bit flip in a password header, plus random multi-bit flips
    /// in a recipient header. Some flips still parse (e.g. inside a salt); that's
    /// fine, since the header hash then breaks decryption. None may crash.
    func testBitFlips() throws {
        let password = try HeaderCodec.encode(Fixtures.header())
        for bit in 0 ..< password.count * 8 {
            var bytes = password
            bytes[bit / 8] ^= 1 << UInt8(bit % 8)
            exercise(bytes)
        }

        let recipients = try HeaderCodec.encode(Fixtures.header(parameters: Fixtures.recipientParameters(count: 3)))
        var rng = SeededGenerator(seed: 0xB17)
        for _ in 0 ..< 5_000 {
            var bytes = recipients
            for _ in 0 ..< Int(1 + rng.next() % 4) {
                let bit = Int(rng.next() % UInt64(bytes.count * 8))
                bytes[bit / 8] ^= 1 << UInt8(bit % 8)
            }
            exercise(bytes)
        }
    }
}
