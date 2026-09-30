import XCTest
@testable import EncryptionCore

final class HeaderCodecTests: XCTestCase {
    // MARK: Encoding

    func testPasswordHeaderGoldenBytes() throws {
        let encoded = try HeaderCodec.encode(Fixtures.header())
        let expected: [UInt8] =
            hex("43484F54414D")  // "CHOTAM"
            + hex("0001")  // version 1
            + hex("01")  // password mode
            + hex("0000007D")  // header length 125
            + hex("00010000")  // chunk size 65536
            + [UInt8](repeating: 0x11, count: 32)  // HKDF salt
            + [UInt8](repeating: 0x22, count: 12)  // base nonce
            + [UInt8](repeating: 0x33, count: 32)  // commitment
            + [UInt8](repeating: 0x44, count: 16)  // Argon2id salt
            + hex("0000000000000004")  // opslimit 4
            + hex("0000000040000000")  // memlimit 1 GiB
        XCTAssertEqual(encoded, expected)
        XCTAssertEqual(encoded.count, FormatV1.passwordHeaderLength)
    }

    func testRecipientHeaderLayout() throws {
        let encoded = try HeaderCodec.encode(Fixtures.header(parameters: Fixtures.recipientParameters(count: 2)))
        XCTAssertEqual(encoded.count, 126 + 2 * 1204)
        XCTAssertEqual(encoded[HeaderOffsets.mode], 2)
        XCTAssertEqual(Array(encoded[9 ..< 13]), hex("000009E6"))  // 2534
        XCTAssertEqual(Array(encoded[93 ..< 125]), [UInt8](repeating: 0x55, count: 32))
        XCTAssertEqual(encoded[HeaderOffsets.recipientCount], 2)
        XCTAssertEqual(Array(encoded[158 ..< 160]), hex("0460"))  // 1120
        XCTAssertEqual(Array(encoded[1280 ..< 1282]), hex("0030"))  // 48
    }

    func testRoundTripBothModes() throws {
        for parameters in [
            Fixtures.passwordParameters,
            Fixtures.recipientParameters(count: 1),
            Fixtures.recipientParameters(count: 64),
        ] {
            let header = Fixtures.header(parameters: parameters)
            let encoded = try HeaderCodec.encode(header)
            XCTAssertEqual(try HeaderCodec.decode(encoded), header)
            let (read, raw) = try HeaderCodec.read(from: MemorySource(encoded + [1, 2, 3]))
            XCTAssertEqual(read, header)
            XCTAssertEqual(raw, encoded)
        }
    }

    func testMaximumRecipientHeaderFitsLimit() throws {
        let encoded = try HeaderCodec.encode(Fixtures.header(parameters: Fixtures.recipientParameters(count: 64)))
        XCTAssertEqual(encoded.count, 77_182)
        XCTAssertLessThanOrEqual(encoded.count, FormatV1.maxHeaderLength)
    }

    func testEncoderRejectsInvalidFields() {
        var header = Fixtures.header()
        header.hkdfSalt = [1, 2, 3]
        assertCoreFailure(.invalidHeaderFields) { _ = try HeaderCodec.encode(header) }

        assertCoreFailure(.invalidHeaderFields) {
            _ = try HeaderCodec.encode(Fixtures.header(parameters: Fixtures.recipientParameters(count: 65)))
        }
        assertCoreFailure(.invalidHeaderFields) {
            _ = try HeaderCodec.encode(Fixtures.header(parameters: Fixtures.recipientParameters(count: 0)))
        }
        guard case .recipients(var r) = Fixtures.recipientParameters(count: 2) else { return XCTFail() }
        r.stanzas[1].keyID = r.stanzas[0].keyID
        assertCoreFailure(.invalidHeaderFields) {
            _ = try HeaderCodec.encode(Fixtures.header(parameters: .recipients(r)))
        }
    }

    // MARK: Rejections, each before any key derivation

    private func passwordHeaderBytes() throws -> [UInt8] {
        try HeaderCodec.encode(Fixtures.header())
    }

    private func recipientHeaderBytes(count: Int = 2) throws -> [UInt8] {
        try HeaderCodec.encode(Fixtures.header(parameters: Fixtures.recipientParameters(count: count)))
    }

    func testRejectsBadMagic() throws {
        var bytes = try passwordHeaderBytes()
        bytes[0] = UInt8(ascii: "X")
        assertCoreFailure(.badMagic) { _ = try HeaderCodec.decode(bytes) }
    }

    func testRejectsUnknownVersions() throws {
        for version: UInt16 in [0, 2, 0xFFFF] {
            var bytes = try passwordHeaderBytes()
            bytes.put(version, at: HeaderOffsets.version)
            assertCoreFailure(.unsupportedVersion) { _ = try HeaderCodec.decode(bytes) }
        }
    }

    func testRejectsUnknownMode() throws {
        for mode: UInt8 in [0, 3, 0xFF] {
            var bytes = try passwordHeaderBytes()
            bytes[HeaderOffsets.mode] = mode
            assertCoreFailure(.unknownMode) { _ = try HeaderCodec.decode(bytes) }
        }
    }

    func testRejectsWrongHeaderLengths() throws {
        var bytes = try passwordHeaderBytes()
        bytes.put(UInt32(FormatV1.passwordHeaderLength + 1), at: HeaderOffsets.headerLength)
        assertCoreFailure(.headerLengthMismatch) { _ = try HeaderCodec.decode(bytes) }

        var recipient = try recipientHeaderBytes()
        recipient.put(UInt32.max, at: HeaderOffsets.headerLength)
        assertCoreFailure(.headerLengthOutOfRange) { _ = try HeaderCodec.decode(recipient) }

        // Declares 3 recipients' worth of length but a count of 2.
        var mismatched = try recipientHeaderBytes()
        mismatched.put(UInt32(FormatV1.recipientHeaderLength(count: 3)), at: HeaderOffsets.headerLength)
        mismatched += [UInt8](repeating: 0, count: 1204)
        assertCoreFailure(.headerLengthMismatch) { _ = try HeaderCodec.decode(mismatched) }
    }

    /// A hostile length is rejected after reading only the 13-byte prelude.
    func testHostileLengthIsRejectedBeforeReadingMore() throws {
        var bytes = try recipientHeaderBytes()
        bytes.put(UInt32.max, at: HeaderOffsets.headerLength)
        let source = CountingSource(MemorySource(bytes))
        assertCoreFailure(.headerLengthOutOfRange) { _ = try HeaderCodec.read(from: source) }
        XCTAssertEqual(source.bytesRead, FormatV1.preludeSize)
    }

    func testRejectsTruncationAndTrailingBytes() throws {
        let bytes = try passwordHeaderBytes()
        assertCoreFailure(.truncatedHeader) { _ = try HeaderCodec.decode(Array(bytes.dropLast())) }
        assertCoreFailure(.trailingHeaderBytes) { _ = try HeaderCodec.decode(bytes + [0]) }
        assertCoreFailure(.truncatedHeader) { _ = try HeaderCodec.read(from: MemorySource(Array(bytes.prefix(50)))) }
        assertCoreFailure(.truncatedHeader) { _ = try HeaderCodec.read(from: MemorySource([])) }
    }

    func testRejectsOtherChunkSizes() throws {
        for size: UInt32 in [0, 1, 32_768, 65_535, 65_537, 1 << 20, .max] {
            var bytes = try passwordHeaderBytes()
            bytes.put(size, at: HeaderOffsets.chunkSize)
            assertCoreFailure(.unsupportedChunkSize) { _ = try HeaderCodec.decode(bytes) }
        }
    }

    func testRejectsArgon2ParametersOutsideLimits() throws {
        for ops: UInt64 in [0, 1, 2, 9, .max] {
            var bytes = try passwordHeaderBytes()
            bytes.put(ops, at: HeaderOffsets.opsLimit)
            assertCoreFailure(.argon2ParametersOutOfRange, "ops \(ops)") { _ = try HeaderCodec.decode(bytes) }
        }
        for mem: UInt64 in [0, 8192, (256 << 20) - 1, (1 << 30) + 1, 64 << 30, .max] {
            var bytes = try passwordHeaderBytes()
            bytes.put(mem, at: HeaderOffsets.memLimit)
            assertCoreFailure(.argon2ParametersOutOfRange, "mem \(mem)") { _ = try HeaderCodec.decode(bytes) }
        }
    }

    func testRejectsRecipientCountOutOfRange() throws {
        for count: UInt8 in [0, 65, 0xFF] {
            var bytes = try recipientHeaderBytes()
            bytes[HeaderOffsets.recipientCount] = count
            assertCoreFailure(.recipientCountOutOfRange, "count \(count)") { _ = try HeaderCodec.decode(bytes) }
        }
    }

    func testRejectsWrongStanzaFieldSizes() throws {
        var bytes = try recipientHeaderBytes()
        bytes.put(UInt16(1119), at: HeaderOffsets.firstEncLength)
        assertCoreFailure(.fieldSizeMismatch) { _ = try HeaderCodec.decode(bytes) }

        var wrapped = try recipientHeaderBytes()
        wrapped.put(UInt16(49), at: HeaderOffsets.firstEncLength + 2 + 1120)
        assertCoreFailure(.fieldSizeMismatch) { _ = try HeaderCodec.decode(wrapped) }
    }

    func testRejectsDuplicateRecipients() throws {
        var bytes = try recipientHeaderBytes()
        let secondStanza = HeaderOffsets.firstStanza + FormatV1.recipientStanzaSize
        for i in 0 ..< 32 {
            bytes[secondStanza + i] = bytes[HeaderOffsets.firstStanza + i]
        }
        assertCoreFailure(.duplicateRecipient) { _ = try HeaderCodec.decode(bytes) }
    }
}
